// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Streamable HTTP upstream client.
//!
//! Each JSON-RPC message is one `POST` to the upstream endpoint. The reply is
//! either a single JSON object or a Server-Sent Events stream that carries the
//! response among other messages. The `Mcp-Session-Id` the server issues is
//! echoed on every later request.
//!
//! `https://` is the normal scheme. Trust roots are the Mozilla bundle from
//! `webpki-roots`, so results do not depend on the host's certificate store.
//! Plain `http://` is accepted only for loopback addresses, where no traffic
//! leaves the machine. Any other plain-HTTP URL is refused with
//! [`UpstreamError::Unsupported`], so tokens are never sent in the clear.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, MutexGuard};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{ACCEPT, CONTENT_TYPE, HeaderName, HeaderValue};
use hyper::{Method, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use serde_json::Value;
use tpt_mcpbox_protocol::LATEST_PROTOCOL_VERSION;
use tpt_mcpbox_protocol::jsonrpc::{Id, Notification, Request, Response};
use tpt_mcpbox_protocol::utilities::cancelled_notification;

use crate::ops::RpcChannel;
use crate::upstream::{UpstreamError, UpstreamOptions};

const SESSION_HEADER: &str = "mcp-session-id";
const PROTOCOL_HEADER: &str = "mcp-protocol-version";

/// Largest reply body, and largest unparsed SSE data, read from an upstream.
/// A reply over this is refused, so a hostile server cannot exhaust memory
/// within the request timeout (SR-15).
pub const MAX_REPLY_BYTES: usize = 16 * 1024 * 1024;

type Http = HyperClient<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// MCP client for a Streamable HTTP endpoint.
#[derive(Debug)]
pub struct HttpClient {
    endpoint: Uri,
    headers: Vec<(HeaderName, HeaderValue)>,
    session: Mutex<Option<HeaderValue>>,
    http: Http,
    next_id: AtomicI64,
    options: UpstreamOptions,
}

impl HttpClient {
    /// Builds a client for `url`, sending `headers` on every request.
    ///
    /// # Errors
    ///
    /// Fails for a malformed URL, a non-`http` scheme, or an invalid header.
    pub fn new(
        url: &str,
        headers: &BTreeMap<String, String>,
        options: UpstreamOptions,
    ) -> Result<Self, UpstreamError> {
        let endpoint: Uri = url
            .parse()
            .map_err(|e| UpstreamError::Unsupported(format!("invalid URL `{url}`: {e}")))?;
        let loopback = endpoint.host().is_some_and(is_loopback_host);
        match endpoint.scheme_str() {
            Some("https") => {}
            Some("http") if loopback => {}
            Some("http") => {
                return Err(UpstreamError::Unsupported(format!(
                    "plain http is only allowed for loopback addresses; use https:// for `{url}`"
                )));
            }
            _ => {
                return Err(UpstreamError::Unsupported(format!(
                    "URL `{url}` must use https:// (or http:// for a loopback address)"
                )));
            }
        }

        let headers = headers
            .iter()
            .map(|(name, value)| {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| UpstreamError::Unsupported(format!("header `{name}`: {e}")))?;
                let mut value = HeaderValue::from_str(value)
                    .map_err(|e| UpstreamError::Unsupported(format!("header `{name}`: {e}")))?;
                // Configured headers often carry credentials. Keep them out of
                // hyper's debug output and transport logging (SR-26).
                value.set_sensitive(true);
                Ok((name, value))
            })
            .collect::<Result<Vec<_>, UpstreamError>>()?;

        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();

        Ok(Self {
            endpoint,
            headers,
            session: Mutex::new(None),
            http: HyperClient::builder(TokioExecutor::new()).build(connector),
            next_id: AtomicI64::new(1),
            options,
        })
    }

    /// Performs the `initialize` handshake. See [`crate::ops::initialize`].
    pub async fn initialize(
        &self,
    ) -> Result<tpt_mcpbox_protocol::model::InitializeResult, UpstreamError> {
        crate::ops::initialize(self).await
    }

    /// Fetches every page of `tools/list`. See [`crate::ops::list_tools`].
    pub async fn list_tools(&self) -> Result<Vec<tpt_mcpbox_protocol::tools::Tool>, UpstreamError> {
        crate::ops::list_tools(self).await
    }

    /// Calls one tool. See [`crate::ops::call_tool`].
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<serde_json::Map<String, Value>>,
    ) -> Result<tpt_mcpbox_protocol::tools::CallToolResult, UpstreamError> {
        crate::ops::call_tool(self, name, arguments).await
    }

    /// The session id the server issued, if any.
    #[must_use]
    pub fn session_id(&self) -> Option<String> {
        lock(&self.session)
            .as_ref()
            .and_then(|v| v.to_str().ok().map(str::to_owned))
    }

    async fn post(&self, body: String) -> Result<hyper::Response<Incoming>, UpstreamError> {
        let session = lock(&self.session).clone();
        let request = build_post(&self.endpoint, &self.headers, session, body)?;
        let response = self
            .http
            .request(request)
            .await
            .map_err(|e| UpstreamError::Transport(e.to_string()))?;

        if let Some(session) = response.headers().get(SESSION_HEADER) {
            *lock(&self.session) = Some(session.clone());
        }
        Ok(response)
    }

    async fn exchange(&self, id: &Id, body: String) -> Result<Response, UpstreamError> {
        let response = self.post(body).await?;
        let status = response.status();
        if !status.is_success() {
            return Err(UpstreamError::Transport(format!("HTTP {status}")));
        }

        let is_sse = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"));
        let body = response.into_body();

        if is_sse {
            read_sse_response(body, id).await
        } else {
            let bytes = read_capped(body).await?;
            let response: Response = serde_json::from_slice(&bytes)
                .map_err(|e| UpstreamError::Malformed(e.to_string()))?;
            Ok(response)
        }
    }
}

/// Reads a whole reply body, refusing it once it passes [`MAX_REPLY_BYTES`].
async fn read_capped(mut body: Incoming) -> Result<Vec<u8>, UpstreamError> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| UpstreamError::Transport(e.to_string()))?;
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        if bytes.len() + chunk.len() > MAX_REPLY_BYTES {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn too_large() -> UpstreamError {
    UpstreamError::Transport(format!("reply is larger than {MAX_REPLY_BYTES} bytes"))
}

/// Builds one `POST` to the endpoint with the configured headers and, when
/// there is one, the session id.
fn build_post(
    endpoint: &Uri,
    headers: &[(HeaderName, HeaderValue)],
    session: Option<HeaderValue>,
    body: String,
) -> Result<hyper::Request<Full<Bytes>>, UpstreamError> {
    let mut builder = hyper::Request::builder()
        .method(Method::POST)
        .uri(endpoint.clone())
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json, text/event-stream")
        .header(PROTOCOL_HEADER, LATEST_PROTOCOL_VERSION);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    if let Some(session) = session {
        builder = builder.header(SESSION_HEADER, session);
    }
    builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| UpstreamError::Transport(e.to_string()))
}

/// Tells the server to stop a request this side no longer waits for. Armed
/// until the exchange finishes. Dropping it sends `notifications/cancelled` as
/// a detached `POST`, because drop cannot await. The guard owns clones of what
/// the `POST` needs, so it does not borrow the client.
struct Abandon {
    endpoint: Uri,
    headers: Vec<(HeaderName, HeaderValue)>,
    session: Option<HeaderValue>,
    http: Http,
    id: Option<Id>,
}

impl Abandon {
    fn new(client: &HttpClient, id: Id) -> Self {
        Self {
            endpoint: client.endpoint.clone(),
            headers: client.headers.clone(),
            session: lock(&client.session).clone(),
            http: client.http.clone(),
            id: Some(id),
        }
    }

    /// The exchange finished, so there is nothing to abandon.
    fn disarm(&mut self) {
        self.id = None;
    }
}

impl Drop for Abandon {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        // Nothing to spawn onto outside a runtime, and a client that is not
        // running on one has no request in flight to cancel.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let notice = cancelled_notification(id, "caller stopped waiting");
        let Ok(body) = serde_json::to_string(&notice) else {
            return;
        };
        let Ok(request) = build_post(&self.endpoint, &self.headers, self.session.clone(), body)
        else {
            return;
        };
        let http = self.http.clone();
        runtime.spawn(async move {
            match http.request(request).await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    tracing::debug!(status = %response.status(), "cancellation refused by upstream");
                }
                Err(error) => tracing::debug!(%error, "cancellation not delivered"),
            }
        });
    }
}

impl RpcChannel for HttpClient {
    async fn call(&self, method: &str, params: Value) -> Result<Value, UpstreamError> {
        let id = Id::Number(self.next_id.fetch_add(1, Ordering::Relaxed));
        let body = serde_json::to_string(&Request::new(id.clone(), method).with_params(params))
            .map_err(|e| UpstreamError::Malformed(e.to_string()))?;

        let mut abandon = Abandon::new(self, id.clone());
        let response = match tokio::time::timeout(
            self.options.request_timeout,
            self.exchange(&id, body),
        )
        .await
        {
            Err(_) => {
                return Err(UpstreamError::Timeout {
                    method: method.to_owned(),
                });
            }
            Ok(result) => {
                abandon.disarm();
                result?
            }
        };

        if let Some(error) = response.error {
            return Err(UpstreamError::Rpc {
                code: error.code.0,
                message: error.message,
            });
        }
        response
            .result
            .ok_or_else(|| UpstreamError::Malformed("response has no result".to_owned()))
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), UpstreamError> {
        let mut notification = Notification::new(method);
        if let Some(params) = params {
            notification = notification.with_params(params);
        }
        let body = serde_json::to_string(&notification)
            .map_err(|e| UpstreamError::Malformed(e.to_string()))?;

        let response = tokio::time::timeout(self.options.request_timeout, self.post(body))
            .await
            .map_err(|_| UpstreamError::Timeout {
                method: method.to_owned(),
            })??;
        // Notifications are answered with 202 Accepted and no body.
        if !response.status().is_success() {
            return Err(UpstreamError::Transport(format!(
                "HTTP {} for notification",
                response.status()
            )));
        }
        Ok(())
    }
}

/// Reads an SSE reply until the response with `id` arrives.
///
/// Server requests and notifications that share the stream are skipped, since
/// client-feature passthrough is not implemented yet.
async fn read_sse_response(mut body: Incoming, id: &Id) -> Result<Response, UpstreamError> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut data = String::new();

    loop {
        let Some(frame) = body.frame().await else {
            return Err(UpstreamError::Closed);
        };
        let frame = frame.map_err(|e| UpstreamError::Transport(e.to_string()))?;
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        buffer.extend_from_slice(&chunk);
        // A line with no newline yet, or data not yet delivered, is bounded too.
        if buffer.len() > MAX_REPLY_BYTES || data.len() > MAX_REPLY_BYTES {
            return Err(too_large());
        }

        while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = buffer.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line_bytes);
            let line = line.trim_end_matches(['\r', '\n']);

            if line.is_empty() {
                if data.is_empty() {
                    continue;
                }
                let event = std::mem::take(&mut data);
                if let Some(response) = parse_event(event.trim_end())
                    && &response.id == id
                {
                    return Ok(response);
                }
            } else if let Some(rest) = line.strip_prefix("data:") {
                data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
                data.push('\n');
            }
        }
    }
}

/// Parses one SSE event's data as a response. Other messages yield `None`.
fn parse_event(data: &str) -> Option<Response> {
    let value: Value = serde_json::from_str(data).ok()?;
    if value.get("method").is_some() {
        return None;
    }
    serde_json::from_value(value).ok()
}

/// `true` for `localhost` and loopback IP literals (bracketed IPv6 allowed).
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::Response as AxumResponse;
    use axum::routing::post;
    use serde_json::json;

    use super::*;

    /// How the fake server answers `tools/call`.
    #[derive(Clone, Copy)]
    enum Mode {
        Json,
        Sse,
        Silent,
        /// `tools/call` answers with a body over the reply limit.
        Oversized,
        /// `tools/call` streams an SSE event over the reply limit, with no end.
        OversizedSse,
    }

    async fn serve(mode: Mode) -> String {
        async fn handler(
            axum::extract::State(mode): axum::extract::State<Mode>,
            headers: HeaderMap,
            body: String,
        ) -> AxumResponse {
            let msg: Value = serde_json::from_str(&body).unwrap();
            let method = msg["method"].as_str().unwrap_or_default().to_owned();

            // Notifications get 202 with no body.
            if msg.get("id").is_none() {
                return AxumResponse::builder()
                    .status(StatusCode::ACCEPTED)
                    .body(Body::empty())
                    .unwrap();
            }

            // The session id must be echoed back on every request after initialize.
            let session_ok = method == "initialize"
                || headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) == Some("sess-1");
            if !session_ok {
                return AxumResponse::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("missing session"))
                    .unwrap();
            }

            let result = match method.as_str() {
                "initialize" => json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "serverInfo": { "name": "http-fake", "version": "1" }
                }),
                "tools/call" => json!({ "content": [{ "type": "text", "text": "ok" }] }),
                _ => json!({}),
            };
            let reply = json!({ "jsonrpc": "2.0", "id": msg["id"], "result": result });

            if method == "tools/call" && matches!(mode, Mode::Silent) {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }

            let mut builder = AxumResponse::builder().header("mcp-session-id", "sess-1");
            if method == "tools/call" && matches!(mode, Mode::Oversized) {
                let pad = "a".repeat(MAX_REPLY_BYTES);
                return AxumResponse::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!("{{\"pad\":\"{pad}\"}}")))
                    .unwrap();
            }
            if method == "tools/call" && matches!(mode, Mode::OversizedSse) {
                let pad = "a".repeat(MAX_REPLY_BYTES);
                return AxumResponse::builder()
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from(format!("data: {pad}")))
                    .unwrap();
            }
            let body = if method == "tools/call" && matches!(mode, Mode::Sse) {
                builder = builder.header(header::CONTENT_TYPE, "text/event-stream");
                // A server message arrives first and must be skipped.
                format!(
                    "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}}\n\n\
                     data: {reply}\n\n"
                )
            } else {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                reply.to_string()
            };
            builder.body(Body::from(body)).unwrap()
        }

        let app = Router::new().route("/mcp", post(handler)).with_state(mode);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/mcp")
    }

    fn client(url: &str, options: UpstreamOptions) -> HttpClient {
        HttpClient::new(url, &BTreeMap::new(), options).unwrap()
    }

    #[tokio::test]
    async fn abandoned_call_posts_cancellation() {
        async fn handler(
            axum::extract::State(seen): axum::extract::State<
                tokio::sync::mpsc::UnboundedSender<Value>,
            >,
            body: String,
        ) -> AxumResponse {
            let msg: Value = serde_json::from_str(&body).unwrap();
            let _ = seen.send(msg.clone());
            if msg.get("id").is_none() {
                return AxumResponse::builder()
                    .status(StatusCode::ACCEPTED)
                    .body(Body::empty())
                    .unwrap();
            }
            // The call is never answered in time; the caller gives up first.
            tokio::time::sleep(Duration::from_secs(5)).await;
            AxumResponse::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "jsonrpc": "2.0", "id": msg["id"], "result": {} }).to_string(),
                ))
                .unwrap()
        }

        let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
        let app = Router::new()
            .route("/mcp", post(handler))
            .with_state(seen_tx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let options = UpstreamOptions {
            request_timeout: Duration::from_millis(100),
            ..UpstreamOptions::default()
        };
        let client = client(&format!("http://{addr}/mcp"), options);
        let outcome = client.call_tool("hang", None).await;
        assert!(matches!(outcome, Err(UpstreamError::Timeout { .. })));

        let call = seen.recv().await.unwrap();
        assert_eq!(call["method"], "tools/call");
        let cancel = tokio::time::timeout(Duration::from_secs(2), seen.recv())
            .await
            .expect("cancellation arrives")
            .unwrap();
        assert_eq!(cancel["method"], "notifications/cancelled");
        assert_eq!(cancel["params"]["requestId"], call["id"]);
    }

    #[tokio::test]
    async fn json_replies_and_session_are_handled() {
        let url = serve(Mode::Json).await;
        let client = client(&url, UpstreamOptions::default());
        let init = client.initialize().await.unwrap();
        assert_eq!(init.server_info.name, "http-fake");
        assert_eq!(client.session_id().as_deref(), Some("sess-1"));

        let result = client.call_tool("echo", None).await.unwrap();
        assert_eq!(result.content.len(), 1);
    }

    #[tokio::test]
    async fn sse_reply_skips_server_messages() {
        let url = serve(Mode::Sse).await;
        let client = client(&url, UpstreamOptions::default());
        client.initialize().await.unwrap();
        let result = client.call_tool("echo", None).await.unwrap();
        assert_eq!(result.content.len(), 1);
    }

    #[tokio::test]
    async fn silent_server_times_out() {
        let url = serve(Mode::Silent).await;
        let options = UpstreamOptions {
            request_timeout: Duration::from_millis(200),
            ..UpstreamOptions::default()
        };
        let client = client(&url, options);
        client.initialize().await.unwrap();
        assert!(matches!(
            client.call_tool("echo", None).await,
            Err(UpstreamError::Timeout { .. })
        ));
    }

    #[tokio::test]
    async fn oversized_json_reply_is_refused() {
        let url = serve(Mode::Oversized).await;
        let client = client(&url, UpstreamOptions::default());
        client.initialize().await.unwrap();
        assert!(matches!(
            client.call_tool("echo", None).await,
            Err(UpstreamError::Transport(message)) if message.contains("larger than")
        ));
    }

    #[tokio::test]
    async fn oversized_sse_event_is_refused() {
        let url = serve(Mode::OversizedSse).await;
        let client = client(&url, UpstreamOptions::default());
        client.initialize().await.unwrap();
        assert!(matches!(
            client.call_tool("echo", None).await,
            Err(UpstreamError::Transport(message)) if message.contains("larger than")
        ));
    }

    #[test]
    fn https_endpoint_is_accepted() {
        assert!(
            HttpClient::new(
                "https://example.com/mcp",
                &BTreeMap::new(),
                UpstreamOptions::default(),
            )
            .is_ok()
        );
    }

    #[test]
    fn remote_plain_http_is_refused() {
        let err = HttpClient::new(
            "http://example.com/mcp",
            &BTreeMap::new(),
            UpstreamOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, UpstreamError::Unsupported(msg) if msg.contains("loopback")));
    }

    #[test]
    fn loopback_plain_http_is_accepted() {
        for url in [
            "http://127.0.0.1:8080/mcp",
            "http://localhost:8080/mcp",
            "http://[::1]:8080/mcp",
        ] {
            assert!(
                HttpClient::new(url, &BTreeMap::new(), UpstreamOptions::default()).is_ok(),
                "{url} should be accepted"
            );
        }
    }

    #[test]
    fn non_http_scheme_is_refused() {
        let err = HttpClient::new(
            "ftp://example.com/mcp",
            &BTreeMap::new(),
            UpstreamOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, UpstreamError::Unsupported(_)));
    }

    #[test]
    fn invalid_header_name_is_refused() {
        let mut headers = BTreeMap::new();
        headers.insert("bad header".to_owned(), "x".to_owned());
        let err = HttpClient::new(
            "http://127.0.0.1:1/mcp",
            &headers,
            UpstreamOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, UpstreamError::Unsupported(_)));
    }

    /// Network test: needs outbound HTTPS. Run with `cargo test -- --ignored`.
    /// Any HTTP-level answer proves the TLS handshake and trust roots work; the
    /// host is not an MCP server, so the call itself is expected to fail.
    #[tokio::test]
    #[ignore = "requires outbound network access"]
    async fn tls_handshake_with_public_host() {
        let client = client("https://example.com/", UpstreamOptions::default());
        match client.initialize().await {
            Err(UpstreamError::Transport(message)) => {
                assert!(
                    message.starts_with("HTTP "),
                    "unexpected transport error: {message}"
                );
            }
            other => panic!("expected an HTTP-level answer, got {other:?}"),
        }
    }

    #[test]
    fn parse_event_ignores_requests_and_notifications() {
        assert!(parse_event(r#"{"jsonrpc":"2.0","method":"roots/list","id":1}"#).is_none());
        assert!(parse_event(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#).is_some());
        assert!(parse_event("not json").is_none());
    }
}
