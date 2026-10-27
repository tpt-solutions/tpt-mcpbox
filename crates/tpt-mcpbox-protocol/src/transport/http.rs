// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! MCP Streamable HTTP transport (`POST` / `GET` / `DELETE` on one endpoint).
//!
//! * `POST /mcp` carries client -> server messages and answers with JSON (or an
//!   empty `202` for notifications). A session id is issued with the
//!   `initialize` response and echoed in `Mcp-Session-Id`.
//! * `GET /mcp` opens the SSE stream carrying server -> client messages. Every
//!   event has an `id`, and `Last-Event-ID` replays what the client missed.
//! * `DELETE /mcp` terminates the session.
//!
//! Security-relevant behaviour implemented here:
//!
//! * **Origin validation** ([`OriginPolicy`]) to blunt DNS rebinding, which the
//!   MCP specification explicitly requires of HTTP transports.
//! * **Payload caps** ([`HttpOptions::max_payload_bytes`]) because tool
//!   arguments are attacker-influenced.
//! * **Session-id validation** -- ids are 128-bit random values, and an unknown
//!   id yields `404` rather than a fresh privileged session.
//!
//! Policy enforcement is not here; it lives in the router behind [`Handler`].

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::fmt;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::Value;
use tokio::sync::{Mutex, broadcast};

use crate::jsonrpc::{ErrorCode, JSONRPC_VERSION, ServerMessage};
use crate::server::{Dispatcher, Handler};
use crate::session::{Session, SessionConfig, SessionId};
use crate::transport::{DEFAULT_MAX_PAYLOAD_BYTES, SESSION_HEADER};

/// Default number of stream events retained for `Last-Event-ID` replay.
pub const DEFAULT_EVENT_BUFFER: usize = 256;

/// Default broadcast depth for live SSE subscribers.
pub const DEFAULT_BROADCAST_CAPACITY: usize = 128;

/// How `Origin` headers are validated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum OriginPolicy {
    /// Accept any origin. Only safe behind an authenticating reverse proxy.
    AllowAny,
    /// Accept loopback origins on any port (`http://localhost:1234`,
    /// `http://127.0.0.1:1234`, ...). This is the default.
    #[default]
    LoopbackOnly,
    /// Accept exactly the listed origins.
    AllowList(Vec<String>),
}

impl OriginPolicy {
    /// Decide whether a request may proceed.
    ///
    /// A request without an `Origin` header (a non-browser client) is allowed:
    /// the header exists to protect browsers, and this server is local-first.
    #[must_use]
    pub fn allows(&self, origin: Option<&str>) -> bool {
        let Some(origin) = origin else {
            return true;
        };
        match self {
            Self::AllowAny => true,
            Self::LoopbackOnly => is_loopback_origin(origin),
            Self::AllowList(allowed) => allowed.iter().any(|candidate| candidate == origin),
        }
    }
}

fn is_loopback_origin(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if scheme != "http" && scheme != "https" {
        return false;
    }
    let host = rest.split(':').next().unwrap_or(rest);
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

/// Transport tuning.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// Origin validation policy.
    pub origin_policy: OriginPolicy,
    /// Maximum accepted request body size.
    pub max_payload_bytes: usize,
    /// Events retained for `Last-Event-ID` replay.
    pub event_buffer_capacity: usize,
    /// Depth of the live event broadcast.
    pub broadcast_capacity: usize,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            origin_policy: OriginPolicy::default(),
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            event_buffer_capacity: DEFAULT_EVENT_BUFFER,
            broadcast_capacity: DEFAULT_BROADCAST_CAPACITY,
        }
    }
}

/// One event on the stream: a monotonic id plus the message.
#[derive(Debug, Clone)]
struct StoredEvent {
    id: u64,
    message: ServerMessage,
}

/// Bounded, ordered replay buffer backing `Last-Event-ID`.
#[derive(Debug)]
struct EventBuffer {
    next_id: u64,
    capacity: usize,
    events: VecDeque<StoredEvent>,
}

impl EventBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            next_id: 1,
            capacity: capacity.max(1),
            events: VecDeque::new(),
        }
    }

    fn push(&mut self, message: ServerMessage) -> StoredEvent {
        let event = StoredEvent {
            id: self.next_id,
            message,
        };
        self.next_id += 1;
        self.events.push_back(event.clone());
        while self.events.len() > self.capacity {
            self.events.pop_front();
        }
        event
    }

    fn since(&self, last_id: u64) -> Vec<StoredEvent> {
        self.events
            .iter()
            .filter(|event| event.id > last_id)
            .cloned()
            .collect()
    }
}

/// A live HTTP session.
#[derive(Debug)]
struct SessionSlot {
    id: SessionId,
    dispatcher: Arc<Dispatcher>,
    events: broadcast::Sender<StoredEvent>,
    buffer: Arc<Mutex<EventBuffer>>,
}

/// Shared state behind the router.
struct HttpState {
    handler: Arc<dyn Handler>,
    config: SessionConfig,
    options: HttpOptions,
    sessions: Mutex<HashMap<String, Arc<SessionSlot>>>,
}

impl fmt::Debug for HttpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpState")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

/// Streamable HTTP server: one endpoint, many sessions.
///
/// Cloning is cheap and shares state, so the same value can be handed to the
/// router and kept for lifecycle calls such as
/// [`StreamableHttpServer::close_all`].
#[derive(Clone)]
pub struct StreamableHttpServer {
    state: Arc<HttpState>,
}

impl fmt::Debug for StreamableHttpServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamableHttpServer")
            .field("options", &self.state.options)
            .finish_non_exhaustive()
    }
}

impl StreamableHttpServer {
    /// Build a server with default options.
    #[must_use]
    pub fn new(handler: Arc<dyn Handler>, config: SessionConfig) -> Self {
        Self::with_options(handler, config, HttpOptions::default())
    }

    /// Build a server with explicit options.
    #[must_use]
    pub fn with_options(
        handler: Arc<dyn Handler>,
        config: SessionConfig,
        options: HttpOptions,
    ) -> Self {
        Self {
            state: Arc::new(HttpState {
                handler,
                config,
                options,
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Build the axum router; mount it wherever the caller likes.
    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/mcp",
                get(self::get_stream)
                    .post(self::post_message)
                    .delete(self::delete_session),
            )
            .layer(axum::extract::DefaultBodyLimit::max(
                self.state.options.max_payload_bytes,
            ))
            .with_state(self.state.clone())
    }

    /// Number of live sessions.
    pub async fn session_count(&self) -> usize {
        self.state.sessions.lock().await.len()
    }

    /// Terminate every session; used on graceful shutdown.
    pub async fn close_all(&self) {
        let slots: Vec<Arc<SessionSlot>> = {
            let mut sessions = self.state.sessions.lock().await;
            let slots = sessions.values().cloned().collect();
            sessions.clear();
            slots
        };
        for slot in slots {
            slot.dispatcher.session().close().await;
        }
    }
}

impl HttpState {
    async fn create_session(&self) -> Arc<SessionSlot> {
        let session = Arc::new(Session::new(self.config.clone()));
        let (dispatcher, mut outbound) = Dispatcher::new(session, self.handler.clone());
        let (events, _) = broadcast::channel(self.options.broadcast_capacity);
        let buffer = Arc::new(Mutex::new(EventBuffer::new(
            self.options.event_buffer_capacity,
        )));

        // One forwarder owns the dispatcher's outbound stream, so events are
        // buffered for replay and broadcast to live SSE subscribers.
        let forwarder_events = events.clone();
        let forwarder_buffer = Arc::clone(&buffer);
        tokio::spawn(async move {
            while let Some(message) = outbound.recv().await {
                let event = forwarder_buffer.lock().await.push(message);
                let _ = forwarder_events.send(event);
            }
        });

        Arc::new(SessionSlot {
            id: dispatcher.session().id().clone(),
            dispatcher,
            events,
            buffer,
        })
    }
}

// --- handlers -----------------------------------------------------------

fn header_str<'a>(headers: &'a HeaderMap, name: &header::HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn origin_of(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, &header::ORIGIN)
}

fn session_header_of(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, &header::HeaderName::from_static(SESSION_HEADER))
}

fn error_body(code: ErrorCode, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": Value::Null,
        "error": {"code": code.as_i32(), "message": message},
    })
}

fn json_error(status: StatusCode, code: ErrorCode, message: &str) -> Response {
    (status, axum::Json(error_body(code, message))).into_response()
}

fn origin_rejected(state: &HttpState, headers: &HeaderMap) -> Option<Response> {
    if state.options.origin_policy.allows(origin_of(headers)) {
        None
    } else {
        Some(json_error(
            StatusCode::FORBIDDEN,
            ErrorCode::INVALID_REQUEST,
            "origin not allowed",
        ))
    }
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    header_str(headers, &header::CONTENT_TYPE)
        .is_some_and(|value| value.starts_with(crate::transport::JSON_MEDIA_TYPE))
}

/// `POST /mcp` -- client -> server messages.
async fn post_message(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    if let Some(rejected) = origin_rejected(&state, &headers) {
        return rejected;
    }
    if !is_json_content_type(&headers) {
        return json_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::INVALID_REQUEST,
            "content-type must be application/json",
        );
    }

    let Ok(body) = axum::body::to_bytes(body, state.options.max_payload_bytes).await else {
        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::CONTENT_TOO_LARGE,
            "request body exceeds the configured limit",
        );
    };
    if body.len() > state.options.max_payload_bytes {
        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::CONTENT_TOO_LARGE,
            "request body exceeds the configured limit",
        );
    }

    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::PARSE_ERROR,
            "invalid JSON payload",
        );
    };

    // Resolve (or create) the session this payload belongs to.
    let (slot, is_new) = match session_header_of(&headers) {
        Some(raw) => {
            let Ok(id) = SessionId::parse(raw) else {
                return json_error(
                    StatusCode::NOT_FOUND,
                    ErrorCode::INVALID_REQUEST,
                    "unknown session",
                );
            };
            match state.sessions.lock().await.get(id.as_str()).cloned() {
                Some(slot) => (slot, false),
                None => {
                    return json_error(
                        StatusCode::NOT_FOUND,
                        ErrorCode::INVALID_REQUEST,
                        "unknown session",
                    );
                }
            }
        }
        None => (state.create_session().await, true),
    };

    if is_new && !payload_is_initialize(&payload) {
        return json_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::INVALID_REQUEST,
            "missing Mcp-Session-Id header",
        );
    }

    let responses = match slot.dispatcher.dispatch_payload(payload).await {
        Ok(responses) => responses,
        Err(error) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ErrorCode::INVALID_REQUEST,
                &error.to_string(),
            );
        }
    };

    if is_new {
        state
            .sessions
            .lock()
            .await
            .insert(slot.id.as_str().to_owned(), Arc::clone(&slot));
    }

    let body = match responses.len() {
        0 => return StatusCode::ACCEPTED.into_response(),
        1 => responses[0].clone().into_value().unwrap_or_default(),
        _ => Value::Array(
            responses
                .iter()
                .map(|message| message.clone().into_value().unwrap_or_default())
                .collect(),
        ),
    };

    let mut response = (StatusCode::OK, axum::Json(body)).into_response();
    if is_new && let Ok(value) = HeaderValue::from_str(slot.id.as_str()) {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static(SESSION_HEADER), value);
    }
    response
}

fn payload_is_initialize(payload: &Value) -> bool {
    let candidate = match payload {
        Value::Array(items) => items.first(),
        other => Some(other),
    };
    candidate.and_then(Value::as_object).is_some_and(|object| {
        object.get("method").and_then(Value::as_str) == Some(crate::method::lifecycle::INITIALIZE)
    })
}

/// `GET /mcp` -- server -> client SSE stream, with `Last-Event-ID` replay.
async fn get_stream(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let headers = request.headers().clone();
    if let Some(rejected) = origin_rejected(&state, &headers) {
        return rejected;
    }

    let Some(raw_id) = session_header_of(&headers) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::INVALID_REQUEST,
            "missing Mcp-Session-Id header",
        );
    };
    let Ok(id) = SessionId::parse(raw_id) else {
        return json_error(
            StatusCode::NOT_FOUND,
            ErrorCode::INVALID_REQUEST,
            "unknown session",
        );
    };
    let Some(slot) = state.sessions.lock().await.get(id.as_str()).cloned() else {
        return json_error(
            StatusCode::NOT_FOUND,
            ErrorCode::INVALID_REQUEST,
            "unknown session",
        );
    };

    let last_event_id = header_str(&headers, &header::HeaderName::from_static("last-event-id"))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);

    let receiver = slot.events.subscribe();
    let replay = {
        let buffer = slot.buffer.lock().await;
        buffer.since(last_event_id)
    };

    let stream = futures::stream::unfold(
        SseState {
            replay: replay.into_iter().collect(),
            receiver,
        },
        |mut state| async move {
            loop {
                if let Some(event) = state.replay.pop_front() {
                    return Some((Ok::<Event, Infallible>(to_sse_event(&event)), state));
                }
                match state.receiver.recv().await {
                    Ok(event) => return Some((Ok(to_sse_event(&event)), state)),
                    // A slow reader fell behind; replay what was missed from
                    // the buffer rather than terminating the stream.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    );

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

struct SseState {
    replay: VecDeque<StoredEvent>,
    receiver: broadcast::Receiver<StoredEvent>,
}

fn to_sse_event(event: &StoredEvent) -> Event {
    let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "{}".to_owned());
    Event::default()
        .id(event.id.to_string())
        .event("message")
        .data(data)
}

/// `DELETE /mcp` -- terminate the session.
async fn delete_session(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let headers = request.headers().clone();
    if let Some(rejected) = origin_rejected(&state, &headers) {
        return rejected;
    }

    let Some(raw_id) = session_header_of(&headers) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::INVALID_REQUEST,
            "missing Mcp-Session-Id header",
        );
    };
    let Ok(id) = SessionId::parse(raw_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let removed = state.sessions.lock().await.remove(id.as_str());
    match removed {
        Some(slot) => {
            slot.dispatcher.session().begin_closing().await;
            slot.dispatcher.session().close().await;
            StatusCode::NO_CONTENT.into_response()
        }
        None => json_error(
            StatusCode::NOT_FOUND,
            ErrorCode::INVALID_REQUEST,
            "unknown session",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    use super::*;
    use crate::jsonrpc::Request;
    use crate::model::ServerCapabilities;
    use crate::server::HandlerFuture;
    use crate::shared::{Implementation, LATEST_PROTOCOL_VERSION};
    use crate::tools::CallToolResult;

    #[derive(Debug, Default)]
    struct EchoHandler;

    impl Handler for EchoHandler {
        fn handle<'a>(&'a self, _session: &'a Arc<Session>, request: Request) -> HandlerFuture<'a> {
            Box::pin(async move {
                Ok(Some(ServerMessage::Response(
                    crate::jsonrpc::Response::success_serde(
                        request.id,
                        CallToolResult::text("pong"),
                    )?,
                )))
            })
        }
    }

    fn config() -> SessionConfig {
        SessionConfig::new(
            Implementation::new("tpt-mcpbox", "0.1.0"),
            ServerCapabilities::full(),
        )
    }

    fn server() -> StreamableHttpServer {
        StreamableHttpServer::new(Arc::new(EchoHandler), config())
    }

    fn json_body(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).expect("serializes")
    }

    fn initialize_body() -> Vec<u8> {
        json_body(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "claude-code", "version": "1.0"}
            }
        }))
    }

    fn post(body: Vec<u8>, session: Option<&str>, origin: Option<&str>) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::CONTENT_TYPE, crate::transport::JSON_MEDIA_TYPE);
        if let Some(session) = session {
            builder = builder.header(SESSION_HEADER, session);
        }
        if let Some(origin) = origin {
            builder = builder.header(header::ORIGIN, origin);
        }
        builder.body(Body::from(body)).expect("request builds")
    }

    async fn body_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body reads");
        if bytes.is_empty() {
            return Value::Null;
        }
        serde_json::from_slice(&bytes).expect("valid JSON")
    }

    async fn initialize(server: &StreamableHttpServer) -> String {
        let response = server
            .router()
            .oneshot(post(initialize_body(), None, None))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        let session = response
            .headers()
            .get(SESSION_HEADER)
            .expect("session header")
            .to_str()
            .expect("header is text")
            .to_owned();
        let payload = body_json(response).await;
        assert_eq!(payload["result"]["serverInfo"]["name"], "tpt-mcpbox");
        session
    }

    async fn initialized(server: &StreamableHttpServer, session: &str) {
        let response = server
            .router()
            .oneshot(post(
                json_body(serde_json::json!({
                    "jsonrpc": "2.0", "method": "notifications/initialized"
                })),
                Some(session),
                None,
            ))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn initialize_issues_a_session_id() {
        let server = server();
        let session = initialize(&server).await;
        assert_eq!(session.len(), 32);
        assert_eq!(server.session_count().await, 1);
    }

    #[tokio::test]
    async fn requests_without_a_session_are_rejected() {
        let server = server();
        let response = server
            .router()
            .oneshot(post(
                json_body(serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})),
                None,
                None,
            ))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unknown_sessions_are_not_found() {
        let server = server();
        let response = server
            .router()
            .oneshot(post(initialize_body(), Some(&"0".repeat(32)), None))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn malformed_session_ids_are_not_found() {
        let server = server();
        let response = server
            .router()
            .oneshot(post(initialize_body(), Some("../../etc/passwd"), None))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cross_origin_requests_are_forbidden() {
        let server = server();
        let response = server
            .router()
            .oneshot(post(initialize_body(), None, Some("https://evil.example")))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn loopback_origins_are_allowed() {
        let server = server();
        let response = server
            .router()
            .oneshot(post(initialize_body(), None, Some("http://localhost:5173")))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_content_type_is_rejected() {
        let server = server();
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(initialize_body()))
            .expect("request builds");
        let response = server
            .router()
            .oneshot(request)
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn oversized_bodies_are_rejected() {
        let server = StreamableHttpServer::with_options(
            Arc::new(EchoHandler),
            config(),
            HttpOptions {
                max_payload_bytes: 64,
                ..HttpOptions::default()
            },
        );
        let response = server
            .router()
            .oneshot(post(initialize_body(), None, None))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn tool_calls_return_json_results() {
        let server = server();
        let session = initialize(&server).await;
        initialized(&server, &session).await;

        let response = server
            .router()
            .oneshot(post(
                json_body(serde_json::json!({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "ping"}
                })),
                Some(&session),
                None,
            ))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        let payload = body_json(response).await;
        assert_eq!(payload["id"], 2);
        assert_eq!(payload["result"]["content"][0]["text"], "pong");
    }

    #[tokio::test]
    async fn batches_return_arrays() {
        let server = server();
        let session = initialize(&server).await;
        initialized(&server, &session).await;

        let response = server
            .router()
            .oneshot(post(
                json_body(serde_json::json!([
                    {"jsonrpc": "2.0", "id": 3, "method": "ping"},
                    {"jsonrpc": "2.0", "id": 4, "method": "ping"}
                ])),
                Some(&session),
                None,
            ))
            .await
            .expect("router responds");
        let payload = body_json(response).await;
        assert!(payload.is_array());
        assert_eq!(payload.as_array().expect("array").len(), 2);
    }

    #[tokio::test]
    async fn delete_terminates_the_session() {
        let server = server();
        let session = initialize(&server).await;

        let response = server
            .router()
            .oneshot(
                HttpRequest::builder()
                    .method("DELETE")
                    .uri("/mcp")
                    .header(SESSION_HEADER, &session)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(server.session_count().await, 0);

        let response = server
            .router()
            .oneshot(post(initialize_body(), Some(&session), None))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_requires_a_session() {
        let server = server();
        let response = server
            .router()
            .oneshot(
                HttpRequest::builder()
                    .method("GET")
                    .uri("/mcp")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_opens_an_sse_stream() {
        let server = server();
        let session = initialize(&server).await;
        initialized(&server, &session).await;

        let response = server
            .router()
            .oneshot(
                HttpRequest::builder()
                    .method("GET")
                    .uri("/mcp")
                    .header(SESSION_HEADER, &session)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content type"),
            crate::transport::SSE_MEDIA_TYPE
        );
    }

    #[tokio::test]
    async fn close_all_terminates_every_session() {
        let server = server();
        initialize(&server).await;
        assert_eq!(server.session_count().await, 1);
        server.close_all().await;
        assert_eq!(server.session_count().await, 0);
    }

    #[test]
    fn origin_policy_defaults_to_loopback_only() {
        let policy = OriginPolicy::default();
        assert!(policy.allows(None));
        assert!(policy.allows(Some("http://localhost:3000")));
        assert!(policy.allows(Some("http://127.0.0.1")));
        assert!(!policy.allows(Some("https://evil.example")));
        assert!(!policy.allows(Some("file:///tmp")));
        assert!(OriginPolicy::AllowAny.allows(Some("https://evil.example")));
        assert!(
            OriginPolicy::AllowList(vec!["https://ok.example".to_owned()])
                .allows(Some("https://ok.example"))
        );
    }

    #[test]
    fn event_buffer_replays_in_order_and_drops_oldest() {
        let mut buffer = EventBuffer::new(2);
        let notification = crate::jsonrpc::Notification::new("notifications/message");
        buffer.push(ServerMessage::Notification(notification.clone()));
        buffer.push(ServerMessage::Notification(notification.clone()));
        buffer.push(ServerMessage::Notification(notification));

        assert_eq!(buffer.next_id, 4);
        let replay = buffer.since(1);
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[0].id, 2);
        assert!(buffer.since(3).is_empty());
    }
}
