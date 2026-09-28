// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Request dispatch and server → agent request plumbing.
//!
//! [`Dispatcher`] is the seam between transport and business logic. It owns
//! everything that must be true for *any* MCP session regardless of policy:
//! the handshake state machine, `ping`, `logging/setLevel`, JSON-RPC error
//! shaping, and the correlation table used to call back into the agent
//! (`roots/list`, `sampling/createMessage`, `elicitation/create`).
//!
//! Policy evaluation is **not** here — it belongs in the router, which
//! implements [`Handler`].

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::error::{ProtocolError, Result};
use crate::jsonrpc::{
    ClientMessage, Error, ErrorCode, Id, Notification, Request, Response, ServerMessage,
};
use crate::method;
use crate::model::{CreateMessageParams, CreateMessageResult, ElicitParams, ElicitResult, InitializeParams, ListRootsResult};
use crate::session::{Session, SessionState};
use crate::utilities::SetLevelRequest;

/// Default time budget for a server → agent request.
pub const DEFAULT_CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Boxed future returned by [`Handler::handle`].
pub type HandlerFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<ServerMessage>>> + Send + 'a>>;

/// Business logic for one session.
pub trait Handler: Send + Sync + 'static {
    /// Handle a client request that passed the lifecycle checks.
    ///
    /// Returning `Ok(None)` means "no response", which is only correct for
    /// handlers that have already emitted one out-of-band (the HTTP transport
    /// does this for SSE replies).
    fn handle<'a>(&'a self, session: &'a Arc<Session>, request: Request) -> HandlerFuture<'a>;

    /// Handle an unsolicited notification. The default ignores everything.
    fn notify(&self, _session: &Arc<Session>, _notification: Notification) {}
}

/// Optional dispatcher tuning.
#[derive(Debug, Clone, Copy)]
pub struct DispatcherOptions {
    /// Time budget for a server → agent request before it fails with
    /// [`ErrorCode::REQUEST_CANCELLED`].
    pub client_request_timeout: Duration,
}

impl Default for DispatcherOptions {
    fn default() -> Self {
        Self {
            client_request_timeout: DEFAULT_CLIENT_REQUEST_TIMEOUT,
        }
    }
}

/// Routes inbound messages and correlates server → agent requests.
///
/// Outbound traffic is pushed to the channel returned by [`Dispatcher::new`];
/// the owning transport is responsible for framing it onto a writer (stdio) or
/// an SSE stream (HTTP).
#[derive(Debug)]
pub struct Dispatcher {
    session: Arc<Session>,
    handler: Arc<dyn Handler>,
    outbound: mpsc::UnboundedSender<ServerMessage>,
    pending: Mutex<HashMap<Id, oneshot::Sender<Response>>>,
    options: DispatcherOptions,
}

impl Dispatcher {
    /// Create a dispatcher for `session` with default options, returning it
    /// together with the outbound message stream.
    #[must_use]
    pub fn new(
        session: Arc<Session>,
        handler: Arc<dyn Handler>,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<ServerMessage>) {
        Self::with_options(session, handler, DispatcherOptions::default())
    }

    /// Create a dispatcher with explicit options.
    #[must_use]
    pub fn with_options(
        session: Arc<Session>,
        handler: Arc<dyn Handler>,
        options: DispatcherOptions,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<ServerMessage>) {
        let (outbound, receiver) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                session,
                handler,
                outbound,
                pending: Mutex::new(HashMap::new()),
                options,
            }),
            receiver,
        )
    }

    /// The session this dispatcher serves.
    #[must_use]
    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }

    /// Tuning this dispatcher was built with.
    #[must_use]
    pub fn options(&self) -> &DispatcherOptions {
        &self.options
    }

    /// Emit an unsolicited notification or server → agent request.
    ///
    /// # Errors
    /// Returns [`ProtocolError::Transport`] when the transport has gone away.
    pub fn emit(&self, message: ServerMessage) -> Result<()> {
        self.outbound
            .send(message)
            .map_err(|_| ProtocolError::Transport("outbound channel closed".to_owned()))
    }

    /// Send a notification to the agent.
    ///
    /// # Errors
    /// Propagates [`Dispatcher::emit`] failures.
    pub fn notify(&self, notification: Notification) -> Result<()> {
        self.emit(ServerMessage::Notification(notification))
    }

    /// Dispatch a raw payload that may be a single message or a batch.
    ///
    /// Returns the responses produced for the requests in `payload`, in the
    /// order they appeared. Notifications are handled inline and never
    /// contribute to the returned vector, matching JSON-RPC batching rules.
    ///
    /// A malformed message does not fail the whole payload: it is answered
    /// with `-32600` so the remaining entries still complete.
    ///
    /// # Errors
    /// Returns [`ProtocolError::Batch`] when the payload is an empty array.
    pub async fn dispatch_payload(&self, payload: Value) -> Result<Vec<ServerMessage>> {
        let items = match crate::jsonrpc::Incoming::from_value(payload)? {
            crate::jsonrpc::Incoming::Single(value) => vec![value],
            crate::jsonrpc::Incoming::Batch(values) => values,
        };

        let mut responses = Vec::new();
        for item in items {
            match ClientMessage::from_value(item) {
                Ok(message) => {
                    if let Some(reply) = self.dispatch(message).await {
                        responses.push(reply);
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, "rejecting malformed JSON-RPC message");
                    responses.push(ServerMessage::Response(Response::from_error(
                        Id::Number(0),
                        ErrorCode::INVALID_REQUEST,
                        "invalid JSON-RPC message",
                    )));
                }
            }
        }
        Ok(responses)
    }

    async fn route_request(&self, request: Request) -> Response {
        let id = request.id.clone();
        match self.serve(request).await {
            Ok(Some(ServerMessage::Response(response))) => response,
            // A handler that answered out-of-band leaves nothing to return here.
            Ok(Some(other)) => {
                let _ = self.emit(other);
                Response::success(id, Value::Object(Default::default()))
            }
            Ok(None) => Response::success(id, Value::Object(Default::default())),
            Err(error) => Response::failure(error.to_json_rpc().with_id(id)),
        }
    }

    async fn serve(&self, request: Request) -> Result<Option<ServerMessage>> {
        match request.method.as_str() {
            method::lifecycle::INITIALIZE => {
                let params: InitializeParams = request.parse_params()?;
                let result = self.session.negotiate(params).await?;
                Ok(Some(ServerMessage::Response(Response::success(request.id, result))))
            }
            method::lifecycle::PING => {
                self.session.ensure_servable(request.method.as_str()).await?;
                Ok(Some(ServerMessage::Response(Response::success(
                    request.id,
                    Value::Object(Default::default()),
                ))))
            }
            method::lifecycle::SHUTDOWN => {
                self.session.begin_closing().await;
                Ok(Some(ServerMessage::Response(Response::success(
                    request.id,
                    Value::Object(Default::default()),
                ))))
            }
            method::utilities::SET_LEVEL => {
                let params: SetLevelRequest = request.parse_params()?;
                self.session.set_logging_level(params.level).await;
                Ok(Some(ServerMessage::Response(Response::success(
                    request.id,
                    Value::Object(Default::default()),
                ))))
            }
            _ => {
                self.session.ensure_servable(request.method.as_str()).await?;
                self.handler.handle(&self.session, request).await
            }
        }
    }

    async fn route_notification(&self, notification: Notification) {
        match notification.method.as_str() {
            method::lifecycle::INITIALIZED => self.session.mark_ready().await,
            // Cancellation is cooperative: the runtime observes it while the
            // call is in flight.
            _ => self.handler.notify(&self.session, notification),
        }
    }

    async fn complete_pending(&self, response: Response) {
        let sender = self.pending.lock().await.remove(&response.id);
        match sender {
            Some(sender) => {
                let _ = sender.send(response);
            }
            None => tracing::debug!(
                id = %response.id,
                "response for an unknown server request; ignoring"
            ),
        }
    }

    /// Send a server → agent request and await the agent's response.
    ///
    /// # Errors
    /// * [`ProtocolError::State`] when the session is not ready.
    /// * [`ProtocolError::Transport`] when the agent never answers or the
    ///   outbound channel is gone.
    /// * [`ProtocolError::Envelope`] when the agent answered with an error.
    pub async fn client_request(&self, method: &str, params: Option<Value>) -> Result<Value> {
        self.session.ensure_servable(method).await?;

        let id = self.session.next_request_id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id.clone(), tx);

        let request = match params {
            Some(params) => Request::new(id.clone(), method).with_params(params),
            None => Request::new(id.clone(), method),
        };
        self.emit(ServerMessage::Request(request))?;

        match tokio::time::timeout(self.options.client_request_timeout, rx).await {
            Ok(Ok(response)) => response.into_result(),
            // The dispatcher was dropped while waiting.
            Ok(Err(_)) => Err(ProtocolError::Transport(
                "agent request was abandoned".to_owned(),
            )),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(ProtocolError::Transport(format!(
                    "agent did not answer `{method}` within {:?}",
                    self.options.client_request_timeout
                )))
            }
        }
    }

    /// Ask the agent for its filesystem roots.
    ///
    /// # Errors
    /// Returns [`ProtocolError::State`] when the agent did not advertise
    /// `roots`, plus the failures of [`Dispatcher::client_request`].
    pub async fn list_roots(&self) -> Result<ListRootsResult> {
        if !self.session.supports_roots().await {
            return Err(ProtocolError::State(
                "agent does not support `roots/list`".to_owned(),
            ));
        }
        let value = self
            .client_request(method::client_features::ROOTS_LIST, None)
            .await?;
        serde_json::from_value(value).map_err(ProtocolError::from)
    }

    /// Ask the agent to run inference (`sampling/createMessage`).
    ///
    /// # Errors
    /// Returns [`ProtocolError::State`] when the agent did not advertise
    /// `sampling`, plus the failures of [`Dispatcher::client_request`].
    pub async fn create_message(&self, params: &CreateMessageParams) -> Result<CreateMessageResult> {
        if !self.session.supports_sampling().await {
            return Err(ProtocolError::State(
                "agent does not support `sampling/createMessage`".to_owned(),
            ));
        }
        let value = self
            .client_request(
                method::client_features::SAMPLING_CREATE_MESSAGE,
                Some(serde_json::to_value(params)?),
            )
            .await?;
        serde_json::from_value(value).map_err(ProtocolError::from)
    }

    /// Ask the agent to collect structured user input
    /// (`elicitation/create`).
    ///
    /// # Errors
    /// Returns [`ProtocolError::State`] when the agent did not advertise
    /// `elicitation`, plus the failures of [`Dispatcher::client_request`].
    pub async fn elicit(&self, params: &ElicitParams) -> Result<ElicitResult> {
        if !self.session.supports_elicitation().await {
            return Err(ProtocolError::State(
                "agent does not support `elicitation/create`".to_owned(),
            ));
        }
        let value = self
            .client_request(
                method::client_features::ELICITATION_CREATE,
                Some(serde_json::to_value(params)?),
            )
            .await?;
        serde_json::from_value(value).map_err(ProtocolError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonrpc::JSONRPC_VERSION;
    use crate::model::ServerCapabilities;
    use crate::session::SessionConfig;
    use crate::shared::{Implementation, LATEST_PROTOCOL_VERSION};
    use crate::tools::{CallToolRequest, CallToolResult};

    /// Handler that answers `tools/call` and records the methods it saw.
    #[derive(Debug, Default)]
    struct RecordingHandler {
        calls: Mutex<Vec<String>>,
    }

    impl Handler for RecordingHandler {
        fn handle<'a>(&'a self, _session: &'a Arc<Session>, request: Request) -> HandlerFuture<'a> {
            Box::pin(async move {
                self.calls.lock().await.push(request.method.clone());
                let result = match request.method.as_str() {
                    method::tools::CALL => {
                        let params: CallToolRequest = request.parse_params()?;
                        CallToolResult::text(format!("called {}", params.name))
                    }
                    method::tools::LIST => crate::tools::ListToolsResult::new(vec![]),
                    _ => Value::Object(Default::default()),
                };
                Ok(Some(ServerMessage::Response(Response::success(request.id, result))))
            })
        }
    }

    fn initialize_payload() -> Value {
        serde_json::json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {"roots": {"listChanged": true}, "sampling": {}},
                "clientInfo": {"name": "claude-code", "version": "1.0"}
            }
        })
    }

    fn build_session() -> Arc<Session> {
        Arc::new(Session::new(SessionConfig::new(
            Implementation::new("tpt-mcpbox", "0.1.0"),
            ServerCapabilities::full(),
        )))
    }

    fn setup() -> (Arc<Dispatcher>, mpsc::UnboundedReceiver<ServerMessage>) {
        let (dispatcher, outbound) = Dispatcher::new(build_session(), Arc::new(RecordingHandler::default()));
        (dispatcher, outbound)
    }

    async fn ready_dispatcher() -> (Arc<Dispatcher>, mpsc::UnboundedReceiver<ServerMessage>) {
        let (dispatcher, outbound) = setup();
        dispatcher
            .dispatch_payload(initialize_payload())
            .await
            .expect("initialize");
        dispatcher
            .dispatch(ClientMessage::Notification(Notification::new(
                method::lifecycle::INITIALIZED,
            )))
            .await;
        (dispatcher, outbound)
    }

    #[tokio::test]
    async fn initialize_returns_negotiated_capabilities() {
        let (dispatcher, _outbound) = setup();
        let responses = dispatcher
            .dispatch_payload(initialize_payload())
            .await
            .expect("dispatch");
        assert_eq!(responses.len(), 1);
        let ServerMessage::Response(response) = &responses[0] else {
            panic!("expected a response");
        };
        let result = response.clone().into_result().expect("result");
        assert_eq!(result["protocolVersion"], LATEST_PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], "tpt-mcpbox");
        assert_eq!(result["capabilities"]["tools"]["listChanged"], true);
    }

    #[tokio::test]
    async fn requests_before_initialization_are_refused() {
        let (dispatcher, _outbound) = setup();
        let responses = dispatcher
            .dispatch_payload(serde_json::json!({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}))
            .await
            .expect("dispatch");
        let ServerMessage::Response(response) = &responses[0] else {
            panic!("expected a response");
        };
        assert!(response.is_error());
        assert_eq!(response.id, Id::Number(9));
    }

    #[tokio::test]
    async fn tools_call_reaches_the_handler() {
        let (dispatcher, _outbound) = ready_dispatcher().await;
        let responses = dispatcher
            .dispatch_payload(serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "fs_read", "arguments": {"path": "a.txt"}}
            }))
            .await
            .expect("dispatch");
        let ServerMessage::Response(response) = &responses[0] else {
            panic!("expected a response");
        };
        let result = response.clone().into_result().expect("result");
        assert_eq!(result["content"][0]["text"], "called fs_read");
    }

    #[tokio::test]
    async fn unknown_methods_report_method_not_found() {
        let (dispatcher, _outbound) = ready_dispatcher().await;
        let responses = dispatcher
            .dispatch_payload(serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/unknown"}))
            .await
            .expect("dispatch");
        let ServerMessage::Response(response) = &responses[0] else {
            panic!("expected a response");
        };
        assert_eq!(
            response.error.as_ref().expect("error").code,
            ErrorCode::METHOD_NOT_FOUND
        );
    }

    #[tokio::test]
    async fn malformed_entries_do_not_abort_a_batch() {
        let (dispatcher, _outbound) = ready_dispatcher().await;
        let responses = dispatcher
            .dispatch_payload(serde_json::json!([
                {"jsonrpc": "1.0", "id": 1, "method": "ping"},
                {"jsonrpc": "2.0", "id": 2, "method": "ping"}
            ]))
            .await
            .expect("dispatch");
        assert_eq!(responses.len(), 2);

        let mut errors = 0;
        let mut successes = 0;
        for message in &responses {
            let ServerMessage::Response(response) = message else {
                panic!("expected responses");
            };
            if response.is_error() {
                errors += 1;
                assert_eq!(
                    response.error.as_ref().expect("error").code,
                    ErrorCode::INVALID_REQUEST
                );
            } else {
                successes += 1;
            }
        }
        assert_eq!((errors, successes), (1, 1));
    }

    #[tokio::test]
    async fn empty_batches_are_rejected() {
        let (dispatcher, _outbound) = ready_dispatcher().await;
        let error = dispatcher
            .dispatch_payload(serde_json::json!([]))
            .await
            .expect_err("empty batch rejected");
        assert!(matches!(error, ProtocolError::Batch(_)));
    }

    #[tokio::test]
    async fn set_level_updates_the_session() {
        let (dispatcher, _outbound) = ready_dispatcher().await;
        dispatcher
            .dispatch_payload(serde_json::json!({
                "jsonrpc": "2.0", "id": 4, "method": "logging/setLevel",
                "params": {"level": "error"}
            }))
            .await
            .expect("dispatch");
        assert_eq!(
            dispatcher.session().logging_level().await,
            crate::model::LoggingLevel::Error
        );
    }

    #[tokio::test]
    async fn notifications_do_not_produce_responses() {
        let (dispatcher, _outbound) = ready_dispatcher().await;
        let responses = dispatcher
            .dispatch_payload(serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await
            .expect("dispatch");
        assert!(responses.is_empty());
    }

    #[tokio::test]
    async fn agent_responses_resolve_pending_requests() {
        let (dispatcher, mut outbound) = ready_dispatcher().await;

        let task = tokio::spawn({
            let dispatcher = Arc::clone(&dispatcher);
            async move { dispatcher.list_roots().await }
        });

        let Some(ServerMessage::Request(request)) = outbound.recv().await else {
            panic!("expected a server request");
        };
        assert_eq!(request.method, method::client_features::ROOTS_LIST);

        let roots = serde_json::json!({"roots": [{"uri": "file:///workspace", "name": "workspace"}]});
        dispatcher
            .dispatch(ClientMessage::Response(Response::success(request.id.clone(), roots)))
            .await;

        let result = task.await.expect("task joins").expect("roots");
        assert_eq!(result.roots[0].uri, "file:///workspace");
    }

    #[tokio::test]
    async fn unsupported_client_features_never_leave_the_process() {
        let (dispatcher, mut outbound) = ready_dispatcher().await;
        let error = dispatcher
            .elicit(&crate::model::ElicitParams {
                message: "continue?".to_owned(),
                requested_schema: serde_json::json!({"type": "object"}),
            })
            .await
            .expect_err("must refuse");
        assert!(error.to_string().contains("elicitation"), "unexpected: {error}");
        // Nothing was written to the agent.
        assert!(outbound.try_recv().is_err());
    }

    #[tokio::test]
    async fn agent_request_timeouts_are_bounded() {
        let (dispatcher, _outbound) = Dispatcher::with_options(
            build_session(),
            Arc::new(RecordingHandler::default()),
            DispatcherOptions {
                client_request_timeout: Duration::from_millis(50),
            },
        );
        dispatcher
            .dispatch_payload(initialize_payload())
            .await
            .expect("initialize");
        dispatcher
            .dispatch(ClientMessage::Notification(Notification::new(
                method::lifecycle::INITIALIZED,
            )))
            .await;

        let error = dispatcher.list_roots().await.expect_err("times out");
        assert!(error.to_string().contains("did not answer"), "unexpected: {error}");
    }

    #[tokio::test]
    async fn shutdown_closes_the_session() {
        let (dispatcher, _outbound) = ready_dispatcher().await;
        dispatcher
            .dispatch_payload(serde_json::json!({"jsonrpc": "2.0", "id": 5, "method": "shutdown"}))
            .await
            .expect("dispatch");
        assert_eq!(dispatcher.session().state().await, SessionState::Closing);
    }
}
