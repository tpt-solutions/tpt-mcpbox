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

use serde::de::DeserializeOwned;
use serde_json::Value;
use tpt_mcpbox_config::Redactor;
use tpt_mcpbox_protocol::completion::CompleteRequest;
use tpt_mcpbox_protocol::jsonrpc::{
    Error as RpcError, ErrorCode, Id, Request, Response, ServerMessage,
};
use tpt_mcpbox_protocol::method;
use tpt_mcpbox_protocol::prompts::{GetPromptRequest, ListPromptsResult};
use tpt_mcpbox_protocol::resources::{
    ListResourceTemplatesResult, ListResourcesResult, ReadResourceRequest,
};
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
            method::resources::LIST => self.resources_list(id),
            method::resources::TEMPLATES_LIST => self.templates_list(id),
            method::resources::READ => self.resource_read(session, id, request.params).await,
            method::prompts::LIST => self.prompts_list(id),
            method::prompts::GET => self.prompt_get(session, id, request.params).await,
            method::completion::COMPLETE => self.complete(session, id, request.params).await,
            other => self.failure(id, RpcError::method_not_found(other)),
        }
    }

    fn resources_list(&self, id: Id) -> ServerMessage {
        let result = ListResourcesResult {
            resources: self.router.list_resources(),
            next_cursor: None,
        };
        self.success(id, &result)
    }

    fn templates_list(&self, id: Id) -> ServerMessage {
        let result = ListResourceTemplatesResult {
            resource_templates: self.router.list_resource_templates(),
            next_cursor: None,
        };
        self.success(id, &result)
    }

    async fn resource_read(
        &self,
        session: &Session,
        id: Id,
        params: Option<Value>,
    ) -> ServerMessage {
        let Some(request) = parse::<ReadResourceRequest>(params) else {
            return self.failure(
                id,
                RpcError::invalid_params("resources/read requires a uri"),
            );
        };
        match self
            .router
            .read_resource(session.id().as_str(), &request.uri)
            .await
        {
            Ok(result) => self.success(id, &result),
            Err(RouterError::UnknownResource(uri)) => self.failure(
                id,
                RpcError::invalid_params(format!("unknown resource `{uri}`")),
            ),
            Err(err) => self.failure(
                id,
                RpcError::new(ErrorCode::INTERNAL_ERROR, err.to_string()),
            ),
        }
    }

    fn prompts_list(&self, id: Id) -> ServerMessage {
        let result = ListPromptsResult {
            prompts: self.router.list_prompts(),
            next_cursor: None,
        };
        self.success(id, &result)
    }

    async fn prompt_get(&self, session: &Session, id: Id, params: Option<Value>) -> ServerMessage {
        let Some(request) = parse::<GetPromptRequest>(params) else {
            return self.failure(id, RpcError::invalid_params("prompts/get requires a name"));
        };
        match self
            .router
            .get_prompt(session.id().as_str(), &request.name, request.arguments)
            .await
        {
            Ok(result) => self.success(id, &result),
            Err(RouterError::UnknownPrompt(name)) => self.failure(
                id,
                RpcError::invalid_params(format!("unknown prompt `{name}`")),
            ),
            Err(err) => self.failure(
                id,
                RpcError::new(ErrorCode::INTERNAL_ERROR, err.to_string()),
            ),
        }
    }

    async fn complete(&self, session: &Session, id: Id, params: Option<Value>) -> ServerMessage {
        let Some(request) = parse::<CompleteRequest>(params) else {
            return self.failure(
                id,
                RpcError::invalid_params("completion/complete requires a ref and an argument"),
            );
        };
        match self.router.complete(session.id().as_str(), request).await {
            Ok(result) => self.success(id, &result),
            Err(RouterError::UnknownPrompt(name)) => self.failure(
                id,
                RpcError::invalid_params(format!("unknown prompt `{name}`")),
            ),
            Err(RouterError::UnknownResource(uri)) => self.failure(
                id,
                RpcError::invalid_params(format!("no resource template `{uri}`")),
            ),
            Err(err) => self.failure(
                id,
                RpcError::new(ErrorCode::INTERNAL_ERROR, err.to_string()),
            ),
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

        // If the protocol layer cancels this request, it drops this future. The
        // guard then stops any running guest, which exits within one epoch tick.
        let stop = StopOnDrop(CancelToken::new());
        let outcome = self
            .router
            .call(
                session.id().as_str(),
                &params.name,
                params.arguments,
                stop.0.clone(),
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

/// Cancels the wrapped token when dropped. Dropping the call future is how a
/// cancelled request reaches the runtime, since the tool task keeps running
/// after the router future is gone.
struct StopOnDrop(CancelToken);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Deserialises request params, or `None` when they are absent or malformed.
fn parse<T: DeserializeOwned>(params: Option<Value>) -> Option<T> {
    serde_json::from_value(params?).ok()
}

impl Handler for ToolHandler {
    fn handle<'a>(&'a self, session: &'a Arc<Session>, request: Request) -> HandlerFuture<'a> {
        Box::pin(async move { Ok(Some(self.answer(session, request).await)) })
    }
}

#[cfg(test)]
mod tests {
    use tpt_mcpbox_policy::Policy;
    use tpt_mcpbox_protocol::Implementation;
    use tpt_mcpbox_protocol::model::ServerCapabilities;
    use tpt_mcpbox_protocol::session::SessionConfig;
    use tpt_mcpbox_protocol::tools::Tool;
    use tpt_mcpbox_proxy::{Client, PolicyGate, UpstreamOptions};

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
    fn dropping_the_stop_guard_cancels_the_call() {
        let token = CancelToken::new();
        let guard = StopOnDrop(token.clone());
        assert!(!token.is_cancelled());
        drop(guard);
        assert!(token.is_cancelled());
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

    /// Upstream whose `tools/call` fails with a message that echoes a credential.
    fn leaky_gate(policy: Arc<Policy>) -> PolicyGate {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(client_side);
        let client = Client::connect(read, write, UpstreamOptions::default());
        let (sread, mut swrite) = tokio::io::split(server_side);
        tokio::spawn(async move {
            let mut lines = BufReader::new(sread).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let msg: Value = serde_json::from_str(&line).unwrap();
                if msg["method"] == "tools/call" {
                    let reply = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "error": { "code": -32000, "message": "auth failed for sk-live-LEAK-1234" }
                    });
                    swrite
                        .write_all(format!("{reply}\n").as_bytes())
                        .await
                        .unwrap();
                }
            }
        });
        PolicyGate::new("leaky", client, policy)
    }

    /// A router that allows tool `t` and sends it to [`leaky_gate`].
    fn leaky_router() -> Router {
        let rule = tpt_mcpbox_config::model::Rule {
            id: "allow-t".to_owned(),
            description: None,
            effect: tpt_mcpbox_config::model::Effect::Allow,
            tool: Some("t".to_owned()),
            prompt: None,
            method: None,
            args: Default::default(),
            hosts: Vec::new(),
            paths: Vec::new(),
            caller: None,
            uris: Vec::new(),
            constraints: None,
        };
        let policy = Arc::new(
            Policy::from_config(&tpt_mcpbox_config::model::PolicyConfig {
                rules: vec![rule],
                ..Default::default()
            })
            .expect("policy compiles"),
        );
        let mut router = Router::new(
            crate::Limiter::new([], crate::limiter::Limits::default()),
            Arc::clone(&policy),
        );
        let tool: Tool = serde_json::from_value(serde_json::json!({
            "name": "t",
            "inputSchema": { "type": "object" }
        }))
        .expect("tool parses");
        router
            .add_upstream(None, Arc::new(leaky_gate(policy)), vec![tool])
            .unwrap();
        router
    }

    #[tokio::test]
    async fn upstream_error_text_is_scrubbed_before_it_reaches_the_agent() {
        let secret = "sk-live-LEAK-1234";
        let router = leaky_router();
        let mut redactor = Redactor::new();
        redactor.add(secret);
        let handler = ToolHandler::new(Arc::new(router)).with_redactor(Arc::new(redactor));
        let session = Arc::new(Session::new(SessionConfig::new(
            Implementation::new("tpt-mcpbox", "0.1.0"),
            ServerCapabilities::full(),
        )));
        let request = Request::new(Id::Number(1), method::tools::CALL)
            .with_params(serde_json::json!({ "name": "t", "arguments": {} }));

        let message = handler
            .handle(&session, request)
            .await
            .expect("handled")
            .expect("replied");
        let rendered = message.into_value().unwrap().to_string();
        assert!(rendered.contains("auth failed"), "{rendered}");
        assert!(
            !rendered.contains(secret),
            "credential reached the agent: {rendered}"
        );
    }

    /// Collects whatever the tracing subscriber writes, for inspection.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// One capture for the whole test binary. A thread-local subscriber did not
    /// see events reliably here, because tracing caches call-site interest
    /// across tests.
    fn captured_logs() -> &'static Captured {
        static CAPTURED: std::sync::OnceLock<Captured> = std::sync::OnceLock::new();
        CAPTURED.get_or_init(|| {
            let captured = Captured::default();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .with_writer(captured.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no other subscriber is installed in this test binary");
            captured
        })
    }

    #[tokio::test]
    async fn logs_and_metrics_never_carry_argument_values_or_upstream_secrets() {
        let captured = captured_logs();
        let router = leaky_router();
        let metrics = router.metrics();
        let argument_secret = "sk-live-ARG-5678";
        let arguments = serde_json::json!({ "token": argument_secret })
            .as_object()
            .cloned();
        // A caller name no other test uses, so finding it proves this call's
        // events were captured.
        let outcome = router
            .call("logs-test-caller", "t", arguments, CancelToken::new())
            .await;
        assert!(outcome.is_err(), "the leaky upstream fails the call");

        let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("logs-test-caller"),
            "capture missed the call: {logs}"
        );
        let rendered_metrics = metrics.render();
        for secret in [argument_secret, "sk-live-LEAK-1234"] {
            assert!(!logs.contains(secret), "log leaked {secret}: {logs}");
            assert!(
                !rendered_metrics.contains(secret),
                "metrics leaked {secret}: {rendered_metrics}"
            );
        }
    }
}
