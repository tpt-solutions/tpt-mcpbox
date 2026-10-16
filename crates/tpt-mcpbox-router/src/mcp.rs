// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Connects the [`Router`] to the MCP protocol layer.
//!
//! [`ToolHandler`] answers `tools/list` from the merged catalog and `tools/call`
//! through [`Router::call`]. The session id is the caller identity for limits,
//! policy and audit.
//!
//! Errors are split by who can act on them. An unknown tool name is a protocol
//! error (`-32602`), because the agent asked for something that does not exist.
//! Everything else (policy denial, rate limit, upstream or tool failure) is a
//! normal result with `isError: true`, so the agent sees the reason and can
//! adjust.
//!
//! Every reply is scrubbed with the configured [`Redactor`] before it leaves the
//! process. A tool or upstream can echo a credential it was given, and that must
//! not reach the agent.

use std::sync::Arc;

use serde_json::Value;
use tpt_mcpbox_config::Redactor;
use tpt_mcpbox_protocol::jsonrpc::{Error as RpcError, Id, Request, Response, ServerMessage};
use tpt_mcpbox_protocol::method;
use tpt_mcpbox_protocol::server::{Handler, HandlerFuture};
use tpt_mcpbox_protocol::session::Session;
use tpt_mcpbox_protocol::tools::{CallToolRequest, CallToolResult, ListToolsResult};
use tpt_mcpbox_runtime::CancelToken;

use crate::dispatch::{Router, RouterError, ToolOutput};

/// Serves `tools/list` and `tools/call` from a shared [`Router`].
#[derive(Debug)]
pub struct ToolHandler {
    router: Arc<Router>,
    redactor: Option<Arc<Redactor>>,
}

impl ToolHandler {
    /// Wraps the router. The router is shared, so it must be fully built first.
    #[must_use]
    pub fn new(router: Arc<Router>) -> Self {
        Self {
            router,
            redactor: None,
        }
    }

    /// Scrubs every reply with `redactor`. Without it, replies are sent as-is.
    #[must_use]
    pub fn with_redactor(mut self, redactor: Arc<Redactor>) -> Self {
        self.redactor = Some(redactor);
        self
    }

    async fn answer(&self, session: &Session, request: Request) -> ServerMessage {
        let id = request.id.clone();
        match request.method.as_str() {
            method::tools::LIST => self.list(id),
            method::tools::CALL => self.call(session, id, request.params).await,
            other => self.failure(id, RpcError::method_not_found(other)),
        }
    }

    fn list(&self, id: Id) -> ServerMessage {
        let result = ListToolsResult {
            tools: self.router.list(),
            next_cursor: None,
        };
        self.success(id, &result)
    }

    async fn call(&self, session: &Session, id: Id, params: Option<Value>) -> ServerMessage {
        let Some(params) = params else {
            return self.failure(id, RpcError::invalid_params("tools/call requires params"));
        };
        let params: CallToolRequest = match serde_json::from_value(params) {
            Ok(params) => params,
            Err(err) => {
                return self.failure(
                    id,
                    RpcError::invalid_params(format!("invalid tools/call params: {err}")),
                );
            }
        };

        let outcome = self
            .router
            .call(
                session.id().as_str(),
                &params.name,
                params.arguments,
                CancelToken::new(),
            )
            .await;

        let result = match outcome {
            Ok(ToolOutput::Upstream(result)) => result,
            Ok(ToolOutput::Wasm(text)) => CallToolResult::text(text),
            Err(RouterError::UnknownTool(name)) => {
                return self.failure(
                    id,
                    RpcError::invalid_params(format!("unknown tool `{name}`")),
                );
            }
            Err(err) => CallToolResult::error(err.to_string()),
        };
        self.success(id, &result)
    }

    /// Serialises `result` as a success reply, scrubbed when a redactor is set.
    fn success<T: serde::Serialize>(&self, id: Id, result: &T) -> ServerMessage {
        match serde_json::to_value(result) {
            Ok(mut value) => {
                self.scrub(&mut value);
                ServerMessage::Response(Response::success(id, value))
            }
            Err(err) => self.failure(id, RpcError::internal().with_data(err.to_string())),
        }
    }

    /// Error reply. The message is scrubbed too, since upstream error text is
    /// passed through.
    fn failure(&self, id: Id, error: RpcError) -> ServerMessage {
        let error = match &self.redactor {
            Some(redactor) => RpcError {
                message: redactor.scrub(&error.message),
                ..error
            },
            None => error,
        };
        ServerMessage::Response(Response::failure(error.with_id(id)))
    }

    fn scrub(&self, value: &mut Value) {
        let Some(redactor) = &self.redactor else {
            return;
        };
        match value {
            Value::String(text) => *text = redactor.scrub(text),
            Value::Array(items) => items.iter_mut().for_each(|item| self.scrub(item)),
            Value::Object(map) => map.values_mut().for_each(|item| self.scrub(item)),
            _ => {}
        }
    }
}

impl Handler for ToolHandler {
    fn handle<'a>(&'a self, session: &'a Arc<Session>, request: Request) -> HandlerFuture<'a> {
        Box::pin(async move { Ok(Some(self.answer(session, request).await)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> ToolHandler {
        ToolHandler::new(Arc::new(Router::new(
            crate::Limiter::new([], crate::Limits::default()),
            Arc::new(
                tpt_mcpbox_policy::Policy::from_config(
                    &tpt_mcpbox_config::model::PolicyConfig::default(),
                )
                .expect("empty policy compiles"),
            ),
        )))
    }

    #[test]
    fn method_not_found_keeps_the_request_id() {
        let message =
            handler().failure(Id::Number(7), RpcError::method_not_found("resources/list"));
        let ServerMessage::Response(response) = message else {
            panic!("expected a response");
        };
        assert_eq!(response.id, Id::Number(7));
        assert_eq!(response.error.unwrap().code.0, -32601);
    }

    #[test]
    fn replies_are_scrubbed_at_every_depth() {
        let mut redactor = Redactor::new();
        redactor.add("sk-live-123456789");
        let handler = handler().with_redactor(Arc::new(redactor));

        let mut value = serde_json::json!({
            "content": [{ "type": "text", "text": "token sk-live-123456789" }],
            "nested": { "deep": ["sk-live-123456789"] }
        });
        handler.scrub(&mut value);
        let rendered = value.to_string();
        assert!(!rendered.contains("sk-live-123456789"), "{rendered}");
    }

    #[test]
    fn error_messages_are_scrubbed() {
        let mut redactor = Redactor::new();
        redactor.add("sk-live-123456789");
        let handler = handler().with_redactor(Arc::new(redactor));

        let ServerMessage::Response(response) =
            handler.failure(Id::Number(1), RpcError::internal().with_data("x"))
        else {
            panic!("expected a response");
        };
        assert!(response.error.is_some());

        let ServerMessage::Response(response) = handler.failure(
            Id::Number(2),
            RpcError::invalid_params("bad sk-live-123456789"),
        ) else {
            panic!("expected a response");
        };
        let message = response.error.unwrap().message;
        assert!(!message.contains("sk-live-123456789"), "{message}");
    }
}
