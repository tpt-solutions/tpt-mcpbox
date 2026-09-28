// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Argument and URI completion (`completion/complete`).
//!
//! Completion suggestions are surfaced to the agent, so they are treated as
//! untrusted output: tpt-mcpbox only ever returns values that already passed
//! the tool's own visibility filtering.

use serde::{Deserialize, Serialize};

/// What is being completed: a prompt argument or a resource template variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Reference {
    /// A prompt and the argument being typed.
    #[serde(rename = "ref/prompt")]
    Prompt {
        /// Prompt name.
        name: String,
        /// Argument name.
        argument: Option<String>,
    },
    /// A resource URI template.
    #[serde(rename = "ref/resource")]
    Resource {
        /// URI template.
        uri: String,
    },
}

/// The partially typed value plus its surrounding context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Argument {
    /// Argument name.
    pub name: String,
    /// Value typed so far.
    pub value: String,
}

/// Extra context, e.g. previously resolved arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletionContext {
    /// Already-resolved arguments for this completion request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<Argument>,
}

/// Params of `completion/complete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteRequest {
    /// What is being completed.
    pub r#ref: Reference,
    /// Argument being completed.
    pub argument: Argument,
    /// Surrounding context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<CompletionContext>,
}

/// A page of completion suggestions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Completion {
    /// Suggested values, at most 100 per the specification.
    pub values: Vec<String>,
    /// Total number of matches before truncation.
    pub total: Option<usize>,
    /// Whether more matches exist than were returned.
    #[serde(rename = "hasMore")]
    pub has_more: Option<bool>,
}

/// Result of `completion/complete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteResult {
    /// The suggestion page.
    pub completion: Completion,
}

impl CompleteResult {
    /// Build a final, untruncated suggestion page.
    pub fn new(values: Vec<String>) -> Self {
        let total = values.len();
        Self {
            completion: Completion {
                values,
                total: Some(total),
                has_more: Some(false),
            },
        }
    }

    /// Build a truncated page.
    pub fn truncated(values: Vec<String>, total: usize) -> Self {
        Self {
            completion: Completion {
                values,
                total: Some(total),
                has_more: Some(true),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_reference_round_trips() {
        let json = r#"{"ref":{"type":"ref/prompt","name":"review","argument":"pr"},"argument":{"name":"pr","value":"4"}}"#;
        let request: CompleteRequest = serde_json::from_str(json).expect("parses");
        assert!(matches!(
            request.r#ref,
            Reference::Prompt {
                name: _,
                argument: Some(_)
            }
        ));
    }

    #[test]
    fn resource_reference_round_trips() {
        let json = r#"{"ref":{"type":"ref/resource","uri":"file:///{path}"},"argument":{"name":"path","value":""}}"#;
        let request: CompleteRequest = serde_json::from_str(json).expect("parses");
        assert_eq!(
            serde_json::to_value(&request).expect("serializes"),
            serde_json::from_str::<serde_json::Value>(json).expect("valid json")
        );
    }

    #[test]
    fn complete_result_reports_truncation() {
        let final_page = CompleteResult::new(vec!["a".to_owned()]);
        assert_eq!(final_page.completion.has_more, Some(false));
        assert_eq!(final_page.completion.total, Some(1));

        let truncated = CompleteResult::truncated(vec!["a".to_owned()], 12);
        assert_eq!(truncated.completion.has_more, Some(true));
        assert_eq!(truncated.completion.total, Some(12));
    }

    #[test]
    fn completion_uses_camel_case_keys() {
        let json = serde_json::to_value(CompleteResult::new(vec![])).expect("serializes");
        assert!(json["completion"]["hasMore"].is_boolean());
        assert_eq!(json["completion"]["values"], serde_json::json!([]));
    }
}
