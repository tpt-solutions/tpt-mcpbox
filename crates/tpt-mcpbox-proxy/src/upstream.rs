// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! MCP client for one upstream server over newline-delimited JSON-RPC.
//!
//! [`Client::connect`] works on any async byte stream, so the same code drives
//! a spawned child process and an in-memory peer in tests. [`Client::spawn`]
//! starts a configured stdio upstream as a child process, which is killed when
//! the client is dropped.
//!
//! Responses are matched to requests by id. Server-initiated requests
//! (`roots/list`, `sampling/createMessage`, ...) are answered with
//! method-not-found until client-feature passthrough is implemented. Server
//! notifications are logged and dropped.

use std::collections::HashMap;

use crate::ops::{self, RpcChannel};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures::StreamExt;
use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{FramedRead, LinesCodec};
use tpt_mcpbox_config::model::StdioUpstream;
use tpt_mcpbox_protocol::jsonrpc::{Error as RpcError, Id, Notification, Request, Response};

use tpt_mcpbox_protocol::model::InitializeResult;
use tpt_mcpbox_protocol::tools::{CallToolResult, Tool};

/// Default cap on a single line received from an upstream.
pub const DEFAULT_MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// Tunables for one upstream connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamOptions {
    /// How long to wait for a response before failing the call.
    pub request_timeout: Duration,
    /// Largest line accepted from the upstream.
    pub max_line_bytes: usize,
}

impl Default for UpstreamOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        }
    }
}

/// Failures talking to an upstream.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The child process could not be started.
    #[error("failed to start upstream `{command}`: {source}")]
    Spawn {
        /// Configured executable.
        command: String,
        /// Underlying OS error.
        source: std::io::Error,
    },
    /// The connection closed before or during the call.
    #[error("upstream connection closed")]
    Closed,
    /// No response arrived within the request timeout.
    #[error("upstream did not answer `{method}` within the timeout")]
    Timeout {
        /// Method that timed out.
        method: String,
    },
    /// The upstream answered with a JSON-RPC error.
    #[error("upstream returned error {code}: {message}")]
    Rpc {
        /// JSON-RPC error code.
        code: i32,
        /// Upstream-supplied message.
        message: String,
    },
    /// The upstream sent something that cannot be a valid reply.
    #[error("malformed upstream message: {0}")]
    Malformed(String),
    /// The upstream negotiated a protocol revision this build does not speak.
    #[error("upstream negotiated unsupported protocol version `{0}`")]
    UnsupportedVersion(String),
    /// The upstream address cannot be used by this build.
    #[error("unsupported upstream: {0}")]
    Unsupported(String),
    /// The HTTP exchange failed below the MCP layer.
    #[error("upstream transport failed: {0}")]
    Transport(String),
    /// Writing to the upstream failed.
    #[error("failed to write to upstream: {0}")]
    Write(#[source] std::io::Error),
}

type Pending = HashMap<Id, oneshot::Sender<Response>>;

/// Shared between the caller side and the reader task.
#[derive(Debug, Default)]
struct Shared {
    pending: Mutex<Pending>,
    closed: AtomicBool,
}

/// A connected MCP client. Dropping it closes the connection.
#[derive(Debug)]
pub struct Client {
    outbound: mpsc::Sender<String>,
    shared: Arc<Shared>,
    next_id: AtomicI64,
    options: UpstreamOptions,
    child: Option<Child>,
}

impl Client {
    /// Starts the client over an existing byte stream pair.
    ///
    /// Must be called inside a Tokio runtime; it spawns the reader and writer
    /// tasks.
    pub fn connect<R, W>(reader: R, writer: W, options: UpstreamOptions) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (outbound, rx) = mpsc::channel::<String>(64);
        let shared = Arc::new(Shared::default());

        tokio::spawn(write_loop(writer, rx));
        tokio::spawn(read_loop(
            reader,
            options.max_line_bytes,
            Arc::clone(&shared),
            outbound.clone(),
        ));

        Self {
            outbound,
            shared,
            next_id: AtomicI64::new(1),
            options,
            child: None,
        }
    }

    /// Spawns a stdio upstream as a child process.
    ///
    /// The child gets only the variables listed in the config; the inherited
    /// environment is cleared. Its stderr is forwarded to debug logs.
    pub fn spawn(
        upstream: &StdioUpstream,
        options: UpstreamOptions,
    ) -> Result<Self, UpstreamError> {
        let mut command = Command::new(&upstream.command);
        command
            .args(&upstream.args)
            .env_clear()
            .envs(&upstream.env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        if let Some(cwd) = &upstream.cwd {
            command.current_dir(cwd);
        }

        let mut child = command.spawn().map_err(|source| UpstreamError::Spawn {
            command: upstream.command.clone(),
            source,
        })?;

        let stdin = child.stdin.take().ok_or(UpstreamError::Closed)?;
        let stdout = child.stdout.take().ok_or(UpstreamError::Closed)?;
        if let Some(stderr) = child.stderr.take() {
            let command = upstream.command.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(upstream = %command, "{line}");
                }
            });
        }

        let mut client = Self::connect(stdout, stdin, options);
        client.child = Some(child);
        Ok(client)
    }

    /// Performs the `initialize` handshake. See [`ops::initialize`].
    pub async fn initialize(&self) -> Result<InitializeResult, UpstreamError> {
        ops::initialize(self).await
    }

    /// Fetches every page of `tools/list`. See [`ops::list_tools`].
    pub async fn list_tools(&self) -> Result<Vec<Tool>, UpstreamError> {
        ops::list_tools(self).await
    }

    /// Calls one tool on the upstream. See [`ops::call_tool`].
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<Map<String, Value>>,
    ) -> Result<CallToolResult, UpstreamError> {
        ops::call_tool(self, name, arguments).await
    }

    /// Sends a request and waits for its response.
    async fn call(&self, method: &str, params: Value) -> Result<Value, UpstreamError> {
        let id = Id::Number(self.next_id.fetch_add(1, Ordering::Relaxed));
        let (reply, response) = oneshot::channel();

        {
            // The closed flag is checked under the same lock the reader task
            // takes when it clears pending calls, so a call cannot be parked
            // after the reader has already given up.
            let mut pending = lock(&self.shared.pending);
            if self.shared.closed.load(Ordering::Acquire) {
                return Err(UpstreamError::Closed);
            }
            pending.insert(id.clone(), reply);
        }

        let request = Request::new(id.clone(), method).with_params(params);
        if let Err(err) = self.send(&request).await {
            lock(&self.shared.pending).remove(&id);
            return Err(err);
        }

        let response = match tokio::time::timeout(self.options.request_timeout, response).await {
            Err(_) => {
                lock(&self.shared.pending).remove(&id);
                return Err(UpstreamError::Timeout {
                    method: method.to_owned(),
                });
            }
            Ok(Err(_)) => return Err(UpstreamError::Closed),
            Ok(Ok(response)) => response,
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
        self.send(&notification).await
    }

    async fn send<T: serde::Serialize>(&self, message: &T) -> Result<(), UpstreamError> {
        let line = serde_json::to_string(message)
            .map_err(|e| UpstreamError::Malformed(format!("cannot encode message: {e}")))?;
        self.outbound
            .send(line)
            .await
            .map_err(|_| UpstreamError::Closed)
    }
}

impl RpcChannel for Client {
    async fn call(&self, method: &str, params: Value) -> Result<Value, UpstreamError> {
        Client::call(self, method, params).await
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), UpstreamError> {
        Client::notify(self, method, params).await
    }
}

async fn write_loop<W>(mut writer: W, mut rx: mpsc::Receiver<String>)
where
    W: AsyncWrite + Unpin,
{
    while let Some(line) = rx.recv().await {
        let written = async {
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await
        }
        .await;
        if let Err(err) = written {
            tracing::debug!("upstream write failed: {err}");
            break;
        }
    }
}

async fn read_loop<R>(
    reader: R,
    max_line_bytes: usize,
    shared: Arc<Shared>,
    reply: mpsc::Sender<String>,
) where
    R: AsyncRead + Unpin,
{
    let mut lines = FramedRead::new(reader, LinesCodec::new_with_max_length(max_line_bytes));
    while let Some(next) = lines.next().await {
        let line = match next {
            Ok(line) => line,
            Err(err) => {
                tracing::debug!("upstream read failed: {err}");
                break;
            }
        };
        let value: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(err) => {
                tracing::debug!("discarding non-JSON upstream line: {err}");
                continue;
            }
        };
        route(value, &shared, &reply).await;
    }

    let mut pending = lock(&shared.pending);
    shared.closed.store(true, Ordering::Release);
    pending.clear();
}

async fn route(value: Value, shared: &Shared, reply: &mpsc::Sender<String>) {
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        let method = method.to_owned();
        match value.get("id").cloned() {
            Some(raw_id) => {
                // Server → client request. Client features are not forwarded yet.
                let Ok(id) = serde_json::from_value::<Id>(raw_id) else {
                    tracing::debug!("upstream request with unusable id dropped");
                    return;
                };
                let response = Response::failure(RpcError::method_not_found(&method).with_id(id));
                if let Ok(line) = serde_json::to_string(&response) {
                    let _ = reply.send(line).await;
                }
            }
            None => tracing::debug!(%method, "upstream notification"),
        }
        return;
    }

    match serde_json::from_value::<Response>(value) {
        Ok(response) => {
            let waiter = lock(&shared.pending).remove(&response.id);
            if let Some(waiter) = waiter {
                let _ = waiter.send(response);
            } else {
                tracing::debug!("upstream response with no pending request");
            }
        }
        Err(err) => tracing::debug!("discarding malformed upstream response: {err}"),
    }
}

pub(crate) fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, UpstreamError> {
    serde_json::to_value(value).map_err(|e| UpstreamError::Malformed(e.to_string()))
}

pub(crate) fn from_value<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, UpstreamError> {
    serde_json::from_value(value).map_err(|e| UpstreamError::Malformed(e.to_string()))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use tokio::io::{BufReader, duplex};

    use super::*;

    /// Runs `handler` for every request line the client sends. A `None` reply
    /// means the server stays silent for that request.
    fn fake_server<F>(
        server_side: tokio::io::DuplexStream,
        mut handler: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: FnMut(&str, Value) -> Option<Response> + Send + 'static,
    {
        let (read, mut write) = tokio::io::split(server_side);
        tokio::spawn(async move {
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let message: Value = serde_json::from_str(&line).unwrap();
                let Some(method) = message.get("method").and_then(Value::as_str) else {
                    continue;
                };
                let Some(id) = message.get("id").cloned() else {
                    continue;
                };
                let params = message.get("params").cloned().unwrap_or(Value::Null);
                let id: Id = serde_json::from_value(id).unwrap();
                if let Some(mut response) = handler(method, params) {
                    response.id = id;
                    let out = serde_json::to_string(&response).unwrap() + "\n";
                    if write.write_all(out.as_bytes()).await.is_err() {
                        break;
                    }
                }
            }
        })
    }

    fn client_pair(options: UpstreamOptions) -> (Client, tokio::io::DuplexStream) {
        let (client_side, server_side) = duplex(64 * 1024);
        let (read, write) = tokio::io::split(client_side);
        (Client::connect(read, write, options), server_side)
    }

    fn ok(result: Value) -> Option<Response> {
        Some(Response::success(Id::Null, result))
    }

    #[tokio::test]
    async fn initialize_negotiates_and_sends_initialized() {
        let (client, server) = client_pair(UpstreamOptions::default());
        let (seen_tx, mut seen_rx) = mpsc::channel::<String>(4);
        let (read, mut write) = tokio::io::split(server);
        tokio::spawn(async move {
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let msg: Value = serde_json::from_str(&line).unwrap();
                let method = msg["method"].as_str().unwrap().to_owned();
                let _ = seen_tx.send(method.clone()).await;
                if let Some(id) = msg.get("id") {
                    let reply = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "serverInfo": { "name": "fake", "version": "1" }
                        }
                    });
                    write
                        .write_all(format!("{reply}\n").as_bytes())
                        .await
                        .unwrap();
                }
            }
        });

        let result = client.initialize().await.unwrap();
        assert_eq!(result.server_info.name, "fake");
        assert_eq!(seen_rx.recv().await.unwrap(), "initialize");
        assert_eq!(seen_rx.recv().await.unwrap(), "notifications/initialized");
    }

    #[tokio::test]
    async fn unsupported_protocol_version_is_rejected() {
        let (client, server) = client_pair(UpstreamOptions::default());
        let _peer = fake_server(server, |_, _| {
            ok(json!({
                "protocolVersion": "1999-01-01",
                "capabilities": {},
                "serverInfo": { "name": "old", "version": "0" }
            }))
        });
        assert!(matches!(
            client.initialize().await,
            Err(UpstreamError::UnsupportedVersion(v)) if v == "1999-01-01"
        ));
    }

    #[tokio::test]
    async fn list_tools_follows_pagination() {
        let (client, server) = client_pair(UpstreamOptions::default());
        let _peer = fake_server(server, |method, params| {
            assert_eq!(method, "tools/list");
            if params.get("cursor").is_none() {
                ok(json!({
                    "tools": [{ "name": "a", "inputSchema": { "type": "object" } }],
                    "nextCursor": "page2"
                }))
            } else {
                assert_eq!(params["cursor"], "page2");
                ok(json!({
                    "tools": [{ "name": "b", "inputSchema": { "type": "object" } }]
                }))
            }
        });
        let tools = client.list_tools().await.unwrap();
        let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
    }

    #[tokio::test]
    async fn repeated_cursor_is_malformed() {
        let (client, server) = client_pair(UpstreamOptions::default());
        let _peer = fake_server(server, |_, _| {
            ok(json!({
                "tools": [],
                "nextCursor": "same"
            }))
        });
        assert!(matches!(
            client.list_tools().await,
            Err(UpstreamError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn call_tool_passes_name_and_arguments() {
        let (client, server) = client_pair(UpstreamOptions::default());
        let _peer = fake_server(server, |method, params| {
            assert_eq!(method, "tools/call");
            assert_eq!(params["name"], "echo");
            assert_eq!(params["arguments"]["text"], "hi");
            ok(json!({ "content": [{ "type": "text", "text": "hi" }] }))
        });
        let mut args = Map::new();
        args.insert("text".to_owned(), json!("hi"));
        let result = client.call_tool("echo", Some(args)).await.unwrap();
        assert_eq!(result.content.len(), 1);
    }

    #[tokio::test]
    async fn rpc_error_is_surfaced() {
        let (client, server) = client_pair(UpstreamOptions::default());
        let _peer = fake_server(server, |_, _| {
            Some(Response::from_error(
                Id::Null,
                tpt_mcpbox_protocol::jsonrpc::ErrorCode(-32602),
                "bad args",
            ))
        });
        match client.call_tool("x", None).await {
            Err(UpstreamError::Rpc { code, message }) => {
                assert_eq!(code, -32602);
                assert_eq!(message, "bad args");
            }
            other => panic!("expected Rpc error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn silent_upstream_times_out() {
        let options = UpstreamOptions {
            request_timeout: Duration::from_millis(50),
            ..UpstreamOptions::default()
        };
        let (client, server) = client_pair(options);
        let _peer = fake_server(server, |_, _| None);
        assert!(matches!(
            client.list_tools().await,
            Err(UpstreamError::Timeout { .. })
        ));
        // The timed-out waiter must be removed, or it would leak.
        assert_eq!(client.shared.pending.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn closed_peer_fails_pending_and_later_calls() {
        let (client, server) = client_pair(UpstreamOptions::default());
        drop(server);
        // Wait for the reader to observe EOF.
        for _ in 0..100 {
            if client.shared.closed.load(Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(matches!(
            client.list_tools().await,
            Err(UpstreamError::Closed)
        ));
    }

    #[tokio::test]
    async fn server_initiated_request_gets_method_not_found() {
        let (_client, server) = client_pair(UpstreamOptions::default());
        let (read, mut write) = tokio::io::split(server);
        write
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"r1\",\"method\":\"roots/list\"}\n")
            .await
            .unwrap();
        let mut lines = BufReader::new(read).lines();
        // The reader task answers the server request on its own, without any
        // call from this side, so the reply is the first line on the wire.
        let line = lines.next_line().await.unwrap().unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["id"], "r1");
        assert_eq!(reply["error"]["code"], -32601);
    }

    #[test]
    fn spawn_error_names_the_command() {
        let upstream = StdioUpstream {
            command: "definitely-not-a-real-binary-tpt-mcpbox".to_owned(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        match Client::spawn(&upstream, UpstreamOptions::default()) {
            Err(UpstreamError::Spawn { command, .. }) => {
                assert_eq!(command, "definitely-not-a-real-binary-tpt-mcpbox");
            }
            other => panic!("expected Spawn error, got {other:?}"),
        }
    }
}
