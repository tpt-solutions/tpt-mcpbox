// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! MCP capability negotiation and the client-feature payloads the proxy routes
//! back to the agent (`roots`, `sampling`, `elicitation`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::content::Content;
use crate::shared::{Experimental, Implementation, Role};

/// Server-side `tools` capability.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolsCapability {
    /// Whether the server emits `notifications/tools/list_changed`.
    #[serde(
        default,
        rename = "listChanged",
        skip_serializing_if = "Option::is_none"
    )]
    pub list_changed: Option<bool>,
}

/// Server-side `resources` capability.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourcesCapability {
    /// Whether the server supports `resources/subscribe`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<bool>,
    /// Whether the server emits `notifications/resources/list_changed`.
    #[serde(
        default,
        rename = "listChanged",
        skip_serializing_if = "Option::is_none"
    )]
    pub list_changed: Option<bool>,
}

/// Server-side `prompts` capability.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PromptsCapability {
    /// Whether the server emits `notifications/prompts/list_changed`.
    #[serde(
        default,
        rename = "listChanged",
        skip_serializing_if = "Option::is_none"
    )]
    pub list_changed: Option<bool>,
}

/// What this server can do.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Tool support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    /// Resource support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    /// Prompt support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
    /// Whether the server emits `notifications/message`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<Value>,
    /// Whether the server implements `completion/complete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completions: Option<Value>,
    /// Opt-in, non-standard extensions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Experimental>,
}

impl ServerCapabilities {
    /// Declare full tools + resources + prompts + logging + completions support
    /// with `list_changed` notifications enabled.
    #[must_use]
    pub fn full() -> Self {
        Self {
            tools: Some(ToolsCapability {
                list_changed: Some(true),
            }),
            resources: Some(ResourcesCapability {
                subscribe: Some(true),
                list_changed: Some(true),
            }),
            prompts: Some(PromptsCapability {
                list_changed: Some(true),
            }),
            logging: Some(Value::Object(Default::default())),
            completions: Some(Value::Object(Default::default())),
            experimental: None,
        }
    }

    /// `true` when tools are advertised.
    #[must_use]
    pub fn supports_tools(&self) -> bool {
        self.tools.is_some()
    }

    /// `true` when the tool list may change at runtime.
    #[must_use]
    pub fn emits_tool_list_changed(&self) -> bool {
        self.tools
            .as_ref()
            .and_then(|tools| tools.list_changed)
            .unwrap_or(false)
    }
}

/// Client-side `roots` capability.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RootsCapability {
    /// Whether the client emits `notifications/roots/list_changed`.
    #[serde(
        default,
        rename = "listChanged",
        skip_serializing_if = "Option::is_none"
    )]
    pub list_changed: Option<bool>,
}

/// What the connected agent can do.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientCapabilities {
    /// The agent can expose filesystem roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roots: Option<RootsCapability>,
    /// The agent can run inference on request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<Value>,
    /// The agent can collect structured user input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elicitation: Option<Value>,
    /// Opt-in, non-standard extensions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Experimental>,
}

impl ClientCapabilities {
    /// `true` when the agent exposes roots.
    #[must_use]
    pub fn supports_roots(&self) -> bool {
        self.roots.is_some()
    }

    /// `true` when the agent accepts `sampling/createMessage`.
    #[must_use]
    pub fn supports_sampling(&self) -> bool {
        self.sampling.is_some()
    }

    /// `true` when the agent accepts `elicitation/create`.
    #[must_use]
    pub fn supports_elicitation(&self) -> bool {
        self.elicitation.is_some()
    }
}

/// Params of the opening `initialize` request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InitializeParams {
    /// Protocol revision the client speaks.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Client capabilities.
    #[serde(default)]
    pub capabilities: ClientCapabilities,
    /// Client identity.
    #[serde(rename = "clientInfo")]
    pub client_info: Implementation,
}

/// Result of `initialize`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InitializeResult {
    /// Protocol revision the server settled on.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Server capabilities.
    #[serde(default)]
    pub capabilities: ServerCapabilities,
    /// Server identity.
    #[serde(rename = "serverInfo")]
    pub server_info: Implementation,
    /// Optional usage guidance shown to the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

/// A filesystem root exposed by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    /// `file://` URI of the root.
    pub uri: String,
    /// Human-readable label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Result of the server → client `roots/list` request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRootsResult {
    /// Roots exposed by the agent.
    #[serde(default)]
    pub roots: Vec<Root>,
}

/// Hint about a model the agent should prefer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelHint {
    /// Model name hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// One turn of a `sampling/createMessage` conversation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SamplingMessage {
    /// Author of the message.
    pub role: Role,
    /// Message content.
    pub content: Content,
}

/// Model preference sent with a sampling request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingModelPreferences {
    /// Cost/quality trade-off hints, most preferred first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<ModelHint>,
}

/// Params of `sampling/createMessage`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateMessageParams {
    /// Conversation to continue.
    pub messages: Vec<SamplingMessage>,
    /// Model preference.
    #[serde(
        default,
        rename = "modelPreferences",
        skip_serializing_if = "Option::is_none"
    )]
    pub model_preferences: Option<SamplingModelPreferences>,
    /// System prompt for this call only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// Requested token budget.
    #[serde(default, rename = "maxTokens", skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Opaque stop sequences.
    #[serde(
        default,
        rename = "stopSequences",
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_sequences: Option<Vec<String>>,
}

/// Result of `sampling/createMessage`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateMessageResult {
    /// Who authored the reply.
    pub role: Role,
    /// Reply content.
    pub content: Content,
    /// Which model produced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Why sampling stopped.
    #[serde(
        default,
        rename = "stopReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_reason: Option<String>,
}

/// Params of `elicitation/create`: a restricted JSON Schema for user input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElicitParams {
    /// Message shown to the user.
    pub message: String,
    /// Restricted subset of JSON Schema describing the expected answer.
    #[serde(rename = "requestedSchema")]
    pub requested_schema: Value,
}

/// Action taken by the user in response to an elicitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElicitAction {
    /// The user submitted the requested values.
    Accept,
    /// The user explicitly declined.
    Decline,
    /// The user dismissed the prompt without deciding.
    Cancel,
}

impl ElicitAction {
    /// Wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Decline => "decline",
            Self::Cancel => "cancel",
        }
    }
}

/// Result of `elicitation/create`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElicitResult {
    /// What the user did.
    pub action: ElicitAction,
    /// Submitted values, present only when `action == "accept"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
}

/// Severity levels from RFC 5424, as used by MCP logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingLevel {
    /// Detailed debugging information.
    Debug,
    /// Normal operational messages.
    Info,
    /// Normal but significant events.
    Notice,
    /// Warning conditions.
    Warning,
    /// Error conditions.
    Error,
    /// Critical conditions.
    Critical,
    /// Action must be taken immediately.
    Alert,
    /// System is unusable.
    Emergency,
}

impl LoggingLevel {
    /// Ordered severities, lowest first, matching `syslog` ranking.
    pub const ALL: [Self; 8] = [
        Self::Debug,
        Self::Info,
        Self::Notice,
        Self::Warning,
        Self::Error,
        Self::Critical,
        Self::Alert,
        Self::Emergency,
    ];

    /// `true` when `self` is at least as severe as `threshold`.
    #[must_use]
    pub fn is_at_least(self, threshold: Self) -> bool {
        self >= threshold
    }

    /// Wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
            Self::Alert => "alert",
            Self::Emergency => "emergency",
        }
    }
}

/// Identifier correlating a long-running request with its progress
/// notifications. MCP allows either a number or a string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProgressToken {
    /// Numeric token.
    Number(i64),
    /// String token.
    String(String),
}

impl From<i64> for ProgressToken {
    fn from(value: i64) -> Self {
        Self::Number(value)
    }
}

impl From<String> for ProgressToken {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::LATEST_PROTOCOL_VERSION;

    #[test]
    fn full_capabilities_serialize_with_camel_case_keys() {
        let json = serde_json::to_value(ServerCapabilities::full()).expect("serializes");
        assert_eq!(json["tools"]["listChanged"], true);
        assert_eq!(json["resources"]["subscribe"], true);
        assert_eq!(json["prompts"]["listChanged"], true);
        assert!(json["logging"].is_object());
        assert!(json["completions"].is_object());
    }

    #[test]
    fn empty_capabilities_serialize_to_an_empty_object() {
        assert_eq!(
            serde_json::to_value(ServerCapabilities::default()).expect("serializes"),
            serde_json::json!({})
        );
    }

    #[test]
    fn initialize_params_round_trip() {
        let json = serde_json::json!({
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {"roots": {"listChanged": true}},
            "clientInfo": {"name": "claude-code", "version": "1.0"}
        });
        let params: InitializeParams = serde_json::from_value(json.clone()).expect("parses");
        assert_eq!(params.protocol_version, LATEST_PROTOCOL_VERSION);
        assert!(params.capabilities.supports_roots());
        assert!(!params.capabilities.supports_sampling());
        assert_eq!(params.client_info.name, "claude-code");
        assert_eq!(serde_json::to_value(&params).expect("serializes"), json);
    }

    #[test]
    fn client_features_are_opt_in() {
        let params: InitializeParams = serde_json::from_value(serde_json::json!({
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "clientInfo": {"name": "agent", "version": "1"}
        }))
        .expect("parses");
        assert!(!params.capabilities.supports_sampling());
        assert!(!params.capabilities.supports_elicitation());
        assert!(!params.capabilities.supports_roots());
    }

    #[test]
    fn logging_levels_are_ordered() {
        assert!(LoggingLevel::Error.is_at_least(LoggingLevel::Info));
        assert!(!LoggingLevel::Debug.is_at_least(LoggingLevel::Info));
        assert_eq!(LoggingLevel::ALL.len(), 8);
        assert_eq!(
            serde_json::to_string(&LoggingLevel::Warning).expect("serializes"),
            "\"warning\""
        );
    }

    #[test]
    fn progress_tokens_accept_both_kinds() {
        let numeric: ProgressToken = serde_json::from_str("7").expect("parses");
        let text: ProgressToken = serde_json::from_str("\"job-7\"").expect("parses");
        assert_eq!(numeric, ProgressToken::Number(7));
        assert_eq!(text, ProgressToken::String("job-7".to_owned()));
    }

    #[test]
    fn elicit_actions_use_lowercase() {
        assert_eq!(ElicitAction::Accept.as_str(), "accept");
        assert_eq!(
            serde_json::to_string(&ElicitAction::Decline).expect("serializes"),
            "\"decline\""
        );
    }
}
