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

use std::sync::Arc;

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
}

impl ToolHandler {
    /// Wraps the router. The router is shared, so it must be fully built first.
    #[must_use]
    pub fn new(router: Arc<Router>) -> Self {
        Self { router }
    }

    async fn answer(&self, session: &Session, request: Request) -> ServerMessage {
        let id = request.id.clone();
        match request.method.as_str() {
            method::tools::LIST => self.list(id),
            method::tools::CALL => self.call(session, id, request.params).await,
            other => failure(id, RpcError::method_not_found(other)),
        }
    }

    fn list(&self, id: Id) -> ServerMessage {
        let result = ListToolsResult {
            tools: self.router.list(),
            next_cursor: None,
        };
        success(id, &result)
    }

    async fn call(
        &self,
        session: &Session,
        id: Id,
        params: Option<serde_json::Value>,
    ) -> ServerMessage {
        let Some(params) = params else {
            return failure(id, RpcError::invalid_params("tools/call requires params"));
        };
        let params: CallToolRequest = match serde_json::from_value(params) {
            Ok(params) => params,
            Err(err) => {
                return failure(
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
                return failure(
                    id,
                    RpcError::invalid_params(format!("unknown tool `{name}`")),
                );
            }
            Err(err) => CallToolResult::error(err.to_string()),
        };
        success(id, &result)
    }
}

impl Handler for ToolHandler {
    fn handle<'a>(&'a self, session: &'a Arc<Session>, request: Request) -> HandlerFuture<'a> {
        Box::pin(async move { Ok(Some(self.answer(session, request).await)) })
    }
}

fn success<T: serde::Serialize>(id: Id, result: &T) -> ServerMessage {
    match Response::success_serde(id.clone(), result) {
        Ok(response) => ServerMessage::Response(response),
        Err(err) => failure(id, RpcError::internal().with_data(err.to_string())),
    }
}

fn failure(id: Id, error: RpcError) -> ServerMessage {
    ServerMessage::Response(Response::failure(error.with_id(id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_not_found_keeps_the_request_id() {
        let message = failure(Id::Number(7), RpcError::method_not_found("resources/list"));
        let ServerMessage::Response(response) = message else {
            panic!("expected a response");
        };
        assert_eq!(response.id, Id::Number(7));
        assert_eq!(response.error.unwrap().code.0, -32601);
    }
}
