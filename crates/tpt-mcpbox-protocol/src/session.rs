// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Session lifecycle and capability negotiation.
//!
//! One [`Session`] per agent connection (one stdio process, one HTTP session).
//! It owns the state machine — `initialize` → `initialized` → requests →
//! shutdown — and the negotiated view of what the agent can do.
//!
//! The state machine is a security boundary, not a formality: `tools/call`,
//! `resources/read` and friends are rejected until the handshake completed, so
//! a half-initialised peer never reaches the policy engine or the sandbox.

use std::fmt;
use std::sync::atomic::{AtomicI64, Ordering};

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::{ProtocolError, Result};
use crate::model::{
    ClientCapabilities, InitializeParams, InitializeResult, LoggingLevel, ServerCapabilities,
};
use crate::shared::{Implementation, LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};

/// Opaque session identifier, used as the `Mcp-Session-Id` HTTP header.
///
/// Must be unguessable: it authorises resumption of an HTTP event stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a new random identifier (128 bits of UUIDv4 entropy).
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4().simple().to_string())
    }

    /// Validate an identifier supplied by a peer.
    ///
    /// # Errors
    /// Returns [`ProtocolError::State`] unless the value is 32 lowercase hex
    /// digits, which keeps attacker-controlled strings out of the session map.
    pub fn parse(value: &str) -> Result<Self> {
        let valid = value.len() == 32
            && value
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(ProtocolError::State("malformed session id".to_owned()))
        }
    }

    /// Borrow the identifier as sent on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lifecycle position of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Connected; `initialize` seen but `notifications/initialized` not yet.
    Initializing,
    /// Handshake complete; requests are accepted.
    Ready,
    /// Shutdown requested; new requests are refused, in-flight work drains.
    Closing,
    /// Session terminated.
    Closed,
}

/// What the server offers, supplied by the router at startup.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Identity reported in `initialize`.
    pub server_info: Implementation,
    /// Capabilities reported in `initialize`.
    pub capabilities: ServerCapabilities,
    /// Optional usage instructions for the agent.
    pub instructions: Option<String>,
    /// Protocol revisions this build can speak, newest first.
    pub supported_versions: Vec<String>,
}

impl SessionConfig {
    /// Build a configuration advertising the given capabilities.
    #[must_use]
    pub fn new(server_info: Implementation, capabilities: ServerCapabilities) -> Self {
        Self {
            server_info,
            capabilities,
            instructions: None,
            supported_versions: SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .map(|version| (*version).to_owned())
                .collect(),
        }
    }

    /// Attach usage instructions.
    #[must_use]
    pub fn with_instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }
}

/// Negotiated peer details captured during `initialize`.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Protocol revision agreed with the peer.
    pub protocol_version: String,
    /// Client identity.
    pub client_info: Implementation,
    /// Client capabilities.
    pub capabilities: ClientCapabilities,
}

/// One agent connection.
#[derive(Debug)]
pub struct Session {
    id: SessionId,
    config: SessionConfig,
    state: RwLock<SessionState>,
    peer: RwLock<Option<PeerInfo>>,
    logging_level: RwLock<LoggingLevel>,
    next_request_id: AtomicI64,
}

impl Session {
    /// Create a session with a freshly generated identifier.
    #[must_use]
    pub fn new(config: SessionConfig) -> Self {
        Self::with_id(config, SessionId::generate())
    }

    /// Create a session with a caller-supplied identifier (tests, HTTP resume).
    #[must_use]
    pub fn with_id(config: SessionConfig, id: SessionId) -> Self {
        Self {
            id,
            config,
            state: RwLock::new(SessionState::Initializing),
            peer: RwLock::new(None),
            logging_level: RwLock::new(LoggingLevel::Info),
            next_request_id: AtomicI64::new(0),
        }
    }

    /// This session's identifier.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The configuration this session was created with.
    #[must_use]
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Current lifecycle state.
    pub async fn state(&self) -> SessionState {
        *self.state.read().await
    }

    /// Negotiate the handshake and produce the `initialize` result.
    ///
    /// Version negotiation follows MCP: when the client's revision is
    /// supported it is echoed back, otherwise the server answers with its own
    /// preferred revision and the client decides whether to continue.
    ///
    /// # Errors
    /// Returns [`ProtocolError::State`] when `initialize` is sent twice.
    pub async fn negotiate(&self, params: InitializeParams) -> Result<InitializeResult> {
        {
            let state = self.state.read().await;
            if *state != SessionState::Initializing {
                return Err(ProtocolError::State(format!(
                    "cannot initialize a session in state {state:?}"
                )));
            }
        }
        if self.peer.read().await.is_some() {
            return Err(ProtocolError::State(
                "initialize may only be sent once per session".to_owned(),
            ));
        }

        let protocol_version = if self
            .config
            .supported_versions
            .contains(&params.protocol_version)
        {
            params.protocol_version.clone()
        } else {
            self.config
                .supported_versions
                .first()
                .cloned()
                .unwrap_or_else(|| LATEST_PROTOCOL_VERSION.to_owned())
        };

        *self.peer.write().await = Some(PeerInfo {
            protocol_version: protocol_version.clone(),
            client_info: params.client_info,
            capabilities: params.capabilities,
        });

        Ok(InitializeResult {
            protocol_version,
            capabilities: self.config.capabilities.clone(),
            server_info: self.config.server_info.clone(),
            instructions: self.config.instructions.clone(),
        })
    }

    /// Mark the handshake complete; only then are requests served.
    pub async fn mark_ready(&self) {
        let mut state = self.state.write().await;
        if *state == SessionState::Initializing {
            *state = SessionState::Ready;
        }
    }

    /// Begin an orderly shutdown.
    pub async fn begin_closing(&self) {
        let mut state = self.state.write().await;
        if matches!(*state, SessionState::Initializing | SessionState::Ready) {
            *state = SessionState::Closing;
        }
    }

    /// Terminate the session.
    pub async fn close(&self) {
        *self.state.write().await = SessionState::Closed;
    }

    /// Reject a request that arrived out of lifecycle order.
    ///
    /// # Errors
    /// Returns [`ProtocolError::State`] for requests issued before
    /// `notifications/initialized`, or after shutdown started.
    pub async fn ensure_servable(&self, method: &str) -> Result<()> {
        match self.state().await {
            SessionState::Ready => Ok(()),
            SessionState::Initializing => Err(ProtocolError::State(format!(
                "received `{method}` before the initialization handshake completed"
            ))),
            SessionState::Closing | SessionState::Closed => Err(ProtocolError::State(format!(
                "received `{method}` on a closing session"
            ))),
        }
    }

    /// Negotiated peer details, or `None` before `initialize`.
    pub async fn peer(&self) -> Option<PeerInfo> {
        self.peer.read().await.clone()
    }

    /// `true` when the agent can expose filesystem roots.
    pub async fn supports_roots(&self) -> bool {
        self.peer
            .read()
            .await
            .as_ref()
            .is_some_and(|peer| peer.capabilities.supports_roots())
    }

    /// `true` when the agent accepts `sampling/createMessage`.
    pub async fn supports_sampling(&self) -> bool {
        self.peer
            .read()
            .await
            .as_ref()
            .is_some_and(|peer| peer.capabilities.supports_sampling())
    }

    /// `true` when the agent accepts `elicitation/create`.
    pub async fn supports_elicitation(&self) -> bool {
        self.peer
            .read()
            .await
            .as_ref()
            .is_some_and(|peer| peer.capabilities.supports_elicitation())
    }

    /// Current minimum log severity for `notifications/message`.
    pub async fn logging_level(&self) -> LoggingLevel {
        *self.logging_level.read().await
    }

    /// Apply `logging/setLevel`.
    pub async fn set_logging_level(&self, level: LoggingLevel) {
        *self.logging_level.write().await = level;
    }

    /// Next identifier for a server → client request.
    ///
    /// Ids start at `0` per session and strictly increase, which keeps
    /// correlation unambiguous when the agent pipelines requests.
    pub fn next_request_id(&self) -> crate::jsonrpc::Id {
        crate::jsonrpc::Id::Number(self.next_request_id.fetch_add(1, Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::{Implementation, LATEST_PROTOCOL_VERSION};

    fn session() -> Session {
        Session::new(SessionConfig::new(
            Implementation::new("tpt-mcpbox", "0.1.0"),
            ServerCapabilities::full(),
        ))
    }

    fn params(version: &str) -> InitializeParams {
        InitializeParams {
            protocol_version: version.to_owned(),
            capabilities: ClientCapabilities::default(),
            client_info: Implementation::new("claude-code", "1.0"),
        }
    }

    #[test]
    fn session_ids_are_validated() {
        let generated = SessionId::generate();
        assert!(SessionId::parse(generated.as_str()).is_ok());
        assert!(SessionId::parse("short").is_err());
        assert!(SessionId::parse(&"A".repeat(32)).is_err());
        assert!(SessionId::parse("../../etc/passwd").is_err());
    }

    #[tokio::test]
    async fn requests_are_refused_before_initialization() {
        let session = session();
        assert_eq!(session.state().await, SessionState::Initializing);
        let error = session
            .ensure_servable("tools/call")
            .await
            .expect_err("must refuse");
        assert!(error.to_string().contains("tools/call"));
    }

    #[tokio::test]
    async fn handshake_opens_the_session() {
        let session = session();
        let result = session
            .negotiate(params(LATEST_PROTOCOL_VERSION))
            .await
            .expect("negotiates");
        assert_eq!(result.protocol_version, LATEST_PROTOCOL_VERSION);
        assert_eq!(result.server_info.name, "tpt-mcpbox");

        // Still not servable until `notifications/initialized` arrives.
        assert!(session.ensure_servable("tools/call").await.is_err());
        session.mark_ready().await;
        assert_eq!(session.state().await, SessionState::Ready);
        assert!(session.ensure_servable("tools/call").await.is_ok());
    }

    #[tokio::test]
    async fn initialize_is_single_use() {
        let session = session();
        session
            .negotiate(params(LATEST_PROTOCOL_VERSION))
            .await
            .expect("first");
        let error = session
            .negotiate(params(LATEST_PROTOCOL_VERSION))
            .await
            .expect_err("second must fail");
        assert!(matches!(error, ProtocolError::State(_)));
    }

    #[tokio::test]
    async fn unknown_versions_fall_back_to_the_preferred_one() {
        let session = session();
        let result = session
            .negotiate(params("1999-01-01"))
            .await
            .expect("negotiates");
        assert_eq!(result.protocol_version, LATEST_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn older_supported_versions_are_echoed() {
        let session = session();
        let result = session
            .negotiate(params("2024-11-05"))
            .await
            .expect("negotiates");
        assert_eq!(result.protocol_version, "2024-11-05");
    }

    #[tokio::test]
    async fn client_features_are_reported_from_the_handshake() {
        let session = session();
        let mut params = params(LATEST_PROTOCOL_VERSION);
        params.capabilities.roots = Some(Default::default());
        params.capabilities.sampling = Some(serde_json::json!({}));
        session.negotiate(params).await.expect("negotiates");

        assert!(session.supports_roots().await);
        assert!(session.supports_sampling().await);
        assert!(!session.supports_elicitation().await);
    }

    #[tokio::test]
    async fn closing_blocks_further_requests() {
        let session = session();
        session
            .negotiate(params(LATEST_PROTOCOL_VERSION))
            .await
            .expect("negotiates");
        session.mark_ready().await;
        session.begin_closing().await;
        assert_eq!(session.state().await, SessionState::Closing);
        assert!(session.ensure_servable("tools/call").await.is_err());
        session.close().await;
        assert_eq!(session.state().await, SessionState::Closed);
    }

    #[tokio::test]
    async fn logging_level_is_session_scoped() {
        let session = session();
        assert_eq!(session.logging_level().await, LoggingLevel::Info);
        session.set_logging_level(LoggingLevel::Error).await;
        assert_eq!(session.logging_level().await, LoggingLevel::Error);
    }

    #[tokio::test]
    async fn server_request_ids_increase_per_session() {
        let session = session();
        let first = session.next_request_id();
        let second = session.next_request_id();
        assert!(matches!(first, crate::jsonrpc::Id::Number(0)));
        assert!(matches!(second, crate::jsonrpc::Id::Number(1)));
    }
}
