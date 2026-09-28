// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Prompt descriptors and the `prompts/*` payloads.
//!
//! `prompts/get` arguments are attacker-influenced (an agent supplies them),
//! so the policy engine inspects the argument values before a template is
//! rendered or its resources are read.

use serde::{Deserialize, Serialize};

use crate::content::Content;
use crate::shared::{PaginatedRequest, Role};

/// A prompt template the server exposes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Prompt {
    /// Unique name used in `prompts/get`.
    pub name: String,
    /// Human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// What the prompt is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Declared arguments, in presentation order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
}

/// One argument accepted by a prompt template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromptArgument {
    /// Argument name as used in `prompts/get`.
    pub name: String,
    /// What the argument controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the prompt can be rendered without it.
    #[serde(default, rename = "required", skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// One rendered message of a prompt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromptMessage {
    /// Author of the message.
    pub role: Role,
    /// Message content.
    pub content: Content,
}

impl PromptMessage {
    /// Build a message with the given role and text.
    pub fn text(role: Role, text: impl Into<String>) -> Self {
        Self {
            role,
            content: Content::text(text),
        }
    }
}

/// Params of `prompts/list`.
pub type ListPromptsParams = PaginatedRequest;

/// Result of `prompts/list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListPromptsResult {
    /// Prompts in this page.
    pub prompts: Vec<Prompt>,
    /// Cursor for the next page.
    #[serde(default, rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Params of `prompts/get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetPromptRequest {
    /// Prompt name or URI.
    pub name: String,
    /// Argument values keyed by `PromptArgument::name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Map<String, serde_json::Value>>,
}

impl GetPromptRequest {
    /// Render `name` with no arguments.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            arguments: None,
        }
    }

    /// Attach one argument.
    #[must_use]
    pub fn with_argument(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.arguments
            .get_or_insert_with(Default::default)
            .insert(key.into(), value);
        self
    }

    /// Borrow an argument value.
    #[must_use]
    pub fn argument_value(&self, key: &str) -> Option<&serde_json::Value> {
        self.arguments.as_ref().and_then(|map| map.get(key))
    }
}

/// Result of `prompts/get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetPromptResult {
    /// Optional prompt description, when it differs from `prompts/list`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Rendered messages.
    pub messages: Vec<PromptMessage>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_omit_empty_argument_lists() {
        let json = r#"{"name":"review","description":"Review a PR"}"#;
        let prompt: Prompt = serde_json::from_str(json).expect("parses");
        assert_eq!(serde_json::to_string(&prompt).expect("serializes"), json);
    }

    #[test]
    fn prompt_arguments_round_trip() {
        let json = r#"{"name":"review","arguments":[{"name":"pr","description":"number","required":true}]}"#;
        let prompt: Prompt = serde_json::from_str(json).expect("parses");
        assert_eq!(prompt.arguments[0].name, "pr");
        assert_eq!(prompt.arguments[0].required, Some(true));
        assert_eq!(serde_json::to_string(&prompt).expect("serializes"), json);
    }

    #[test]
    fn get_prompt_builds_argument_maps() {
        let request = GetPromptRequest::new("review").with_argument("pr", serde_json::json!(42));
        assert_eq!(request.argument_value("pr"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn get_prompt_result_serializes_messages() {
        let result = GetPromptResult {
            description: None,
            messages: vec![PromptMessage::text(Role::User, "review PR 42")],
        };
        let json = serde_json::to_value(&result).expect("serializes");
        assert_eq!(json["messages"][0]["role"], "user");
        assert_eq!(json["messages"][0]["content"]["type"], "text");
    }
}
