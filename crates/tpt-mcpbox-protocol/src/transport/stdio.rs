// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! stdio transport: newline-delimited JSON on stdin/stdout, logs on stderr.
//!
//! One message per line, no embedded newlines (`serde_json` escapes control
//! characters, so this holds by construction). A single task owns the write
//! half — every outbound message, whether a response to an inbound request, an
//! unsolicited notification or a server → agent request — is funnelled through
//! one channel so frames can never interleave.
//!
//! Oversized lines are rejected by the codec instead of being buffered, which
//! keeps a hostile agent from exhausting memory with a single write.

use std::sync::Arc;

use futures::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LinesCodec};

use crate::error::{ProtocolError, Result};
use crate::jsonrpc::{ErrorCode, Id, Response, ServerMessage};
use crate::server::{Dispatcher, Handler};
use crate::session::SessionConfig;

/// Default cap for a single inbound line (8 MiB).
pub const DEFAULT_MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// Tuning for the stdio transport.
#[derive(Debug, Clone, Copy)]
pub struct StdioOptions {
    /// Maximum accepted line length in bytes.
    pub max_line_bytes: usize,
}

impl Default for StdioOptions {
    fn default() -> Self {
        Self {
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        }
    }
}

/// Serve one stdio session, wiring `handler` to a fresh [`Dispatcher`].
pub async fn serve(
    handler: Arc<dyn Handler>,
    config: SessionConfig,
    options: StdioOptions,
) -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    serve_with_io(handler, config, options, stdin, stdout).await
}

/// Serve a stdio session over arbitrary byte streams (used by tests and by
/// supervisors that hand us pipes).
pub async fn serve_with_io<R, W>(
    handler: Arc<dyn Handler>,
    config: SessionConfig,
    options: StdioOptions,
    reader: R,
    writer: W,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let session = Arc::new(crate::session::Session::new(config));
    let (dispatcher, outbound) = Dispatcher::new(session, handler);
    run(dispatcher, outbound, options, reader, writer).await
}

async fn run<R, W>(
    dispatcher: Arc<Dispatcher>,
    mut outbound: mpsc::UnboundedReceiver<ServerMessage>,
    options: StdioOptions,
    reader: R,
    writer: W,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Sole owner of the write half.
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(message) = outbound.recv().await {
            let mut frame = serde_json::to_vec(&message).map_err(std::io::Error::other)?;
            frame.push(b'\n');
            writer.write_all(&frame).await?;
            writer.flush().await?;
        }
        Ok::<(), std::io::Error>(())
    });

    let read_result = read_loop(&dispatcher, options, reader).await;

    // Stop the session, then close the channel so the writer can finish.
    dispatcher.session().begin_closing().await;
    drop(dispatcher);
    match writer_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(%error, "stdio writer stopped early"),
        Err(error) => tracing::warn!(%error, "stdio writer task panicked"),
    }

    read_result
}

async fn read_loop<R>(dispatcher: &Arc<Dispatcher>, options: StdioOptions, reader: R) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut framed = Framed::new(
        reader,
        LinesCodec::new_with_max_length(options.max_line_bytes),
    );

    while let Some(line) = framed.next().await {
        let line = line.map_err(|error| match error {
            tokio_util::codec::LinesCodecError::MaxLineLengthExceeded => {
                ProtocolError::Transport("inbound line exceeds the configured limit".to_owned())
            }
            other => ProtocolError::Transport(other.to_string()),
        })?;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let payload: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::debug!(%error, "rejecting malformed JSON line");
                let _ = dispatcher.emit(ServerMessage::Response(Response::from_error(
                    Id::Null,
                    ErrorCode::PARSE_ERROR,
                    "invalid JSON payload",
                )));
                continue;
            }
        };

        // Requests run on their own tasks, so this loop keeps reading while
        // they are in flight and can receive `notifications/cancelled`.
        match dispatcher.accept_payload(payload).await {
            Ok(()) => {}
            Err(error) => {
                tracing::debug!(%error, "rejecting malformed JSON-RPC payload");
                let _ = dispatcher.emit(ServerMessage::Response(Response::from_error(
                    Id::Null,
                    ErrorCode::INVALID_REQUEST,
                    "invalid JSON-RPC payload",
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::jsonrpc::Request;
    use crate::model::ServerCapabilities;
    use crate::server::HandlerFuture;
    use crate::shared::{Implementation, LATEST_PROTOCOL_VERSION};
    use crate::tools::CallToolResult;

    /// Handler that echoes a fixed tool result and ignores everything else.
    #[derive(Debug, Default)]
    struct EchoHandler;

    impl Handler for EchoHandler {
        fn handle<'a>(
            &'a self,
            _session: &'a Arc<crate::session::Session>,
            request: Request,
        ) -> HandlerFuture<'a> {
            Box::pin(async move {
                if request.method != crate::method::tools::CALL {
                    return Err(crate::error::ProtocolError::MethodNotFound(
                        request.method.clone(),
                    ));
                }
                Ok(Some(ServerMessage::Response(Response::success_serde(
                    request.id,
                    CallToolResult::text("pong"),
                )?)))
            })
        }
    }

    struct Harness {
        to_server: DuplexStream,
        from_server: DuplexStream,
    }

    fn start(options: StdioOptions) -> Harness {
        start_with(Arc::new(EchoHandler), options)
    }

    fn start_with(handler: Arc<dyn Handler>, options: StdioOptions) -> Harness {
        let (client_in, server_in) = tokio::io::duplex(64 * 1024);
        let (server_out, client_out) = tokio::io::duplex(64 * 1024);
        let config = SessionConfig::new(
            Implementation::new("tpt-mcpbox", "0.1.0"),
            ServerCapabilities::full(),
        );
        tokio::spawn(async move {
            let _ = serve_with_io(handler, config, options, server_in, server_out).await;
        });
        Harness {
            to_server: client_in,
            from_server: client_out,
        }
    }

    async fn write_line(stream: &mut DuplexStream, value: Value) {
        let mut line = serde_json::to_vec(&value).expect("serializes");
        line.push(b'\n');
        stream.write_all(&line).await.expect("write succeeds");
    }

    async fn read_message(stream: &mut DuplexStream) -> Value {
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            let read = stream.read(&mut byte).await.expect("read succeeds");
            assert_ne!(read, 0, "server closed the stream early");
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        serde_json::from_slice(&line).expect("server wrote valid JSON")
    }

    async fn handshake(harness: &mut Harness) {
        write_line(
            &mut harness.to_server,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": LATEST_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "claude-code", "version": "1.0"}
                }
            }),
        )
        .await;
        let response = read_message(&mut harness.from_server).await;
        assert_eq!(response["result"]["serverInfo"]["name"], "tpt-mcpbox");

        write_line(
            &mut harness.to_server,
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await;
    }

    #[tokio::test]
    async fn full_session_round_trip() {
        let mut harness = start(StdioOptions::default());
        handshake(&mut harness).await;

        write_line(
            &mut harness.to_server,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "ping"}
            }),
        )
        .await;

        let response = read_message(&mut harness.from_server).await;
        assert_eq!(response["id"], 2);
        assert_eq!(response["result"]["content"][0]["text"], "pong");
    }

    /// Handler whose `tools/call` never completes on its own.
    #[derive(Debug, Default)]
    struct HangingCalls;

    impl Handler for HangingCalls {
        fn handle<'a>(
            &'a self,
            _session: &'a Arc<crate::session::Session>,
            request: Request,
        ) -> HandlerFuture<'a> {
            Box::pin(async move {
                std::future::pending::<()>().await;
                Ok(Some(ServerMessage::Response(Response::success(
                    request.id,
                    Value::Null,
                ))))
            })
        }
    }

    #[tokio::test]
    async fn cancellation_is_read_while_a_call_is_in_flight() {
        let mut harness = start_with(Arc::new(HangingCalls), StdioOptions::default());
        handshake(&mut harness).await;

        write_line(
            &mut harness.to_server,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "slow"}
            }),
        )
        .await;
        write_line(
            &mut harness.to_server,
            serde_json::json!({
                "jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": {"requestId": 2, "reason": "user aborted"}
            }),
        )
        .await;
        write_line(
            &mut harness.to_server,
            serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
        )
        .await;

        // The loop never blocked behind the hung call, and the cancelled call
        // stays silent: the first line back is the ping's reply.
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_message(&mut harness.from_server),
        )
        .await
        .expect("ping is answered while the call is in flight");
        assert_eq!(response["id"], 3);
    }

    #[tokio::test]
    async fn blank_lines_are_ignored() {
        let mut harness = start(StdioOptions::default());
        harness
            .to_server
            .write_all(b"\n   \n")
            .await
            .expect("write succeeds");
        handshake(&mut harness).await;
    }

    #[tokio::test]
    async fn malformed_json_is_answered_with_a_parse_error() {
        let mut harness = start(StdioOptions::default());
        harness
            .to_server
            .write_all(b"{not json}\n")
            .await
            .expect("write succeeds");

        let response = read_message(&mut harness.from_server).await;
        assert!(response["id"].is_null());
        assert_eq!(response["error"]["code"], ErrorCode::PARSE_ERROR.as_i32());
    }

    #[tokio::test]
    async fn unknown_methods_produce_method_not_found() {
        let mut harness = start(StdioOptions::default());
        handshake(&mut harness).await;
        write_line(
            &mut harness.to_server,
            serde_json::json!({"jsonrpc": "2.0", "id": 7, "method": "nope/nope"}),
        )
        .await;

        let response = read_message(&mut harness.from_server).await;
        assert_eq!(
            response["error"]["code"],
            ErrorCode::METHOD_NOT_FOUND.as_i32()
        );
    }

    #[tokio::test]
    async fn oversized_lines_are_rejected() {
        let mut harness = start(StdioOptions {
            max_line_bytes: 128,
        });
        let payload = "x".repeat(512);
        let _ = harness
            .to_server
            .write_all(format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{{\"p\":\"{payload}\"}}}}}}\n").as_bytes())
            .await;

        // The read loop stops on the codec error; the session closes cleanly.
        let mut sink = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            harness.from_server.read_to_end(&mut sink),
        )
        .await;
    }
}
