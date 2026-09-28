// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Resource descriptors and the `resources/*` payloads.
//!
//! Resource URIs are untrusted input: the policy engine resolves them against
//! the tool's filesystem grants before any `resources/read` reaches the runtime.

use serde::{Deserialize, Serialize};

use crate::content::ResourceContents;
use crate::shared::{Annotations, PaginatedRequest};

/// A concrete resource the server can read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    /// Resource URI, e.g. `file:///workspace/output/report.md`.
    pub uri: String,
    /// Short display name.
    pub name: String,
    /// Human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// What the resource contains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// IANA media type, when known.
    #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Advisory hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
}

/// A parameterised family of resources, e.g. `logs://{app}/{date}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceTemplate {
    /// RFC 6570 URI template.
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
    /// Short display name.
    pub name: String,
    /// Human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// What the template produces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// IANA media type, when known.
    #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Advisory hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
}

/// Params of `resources/list` and `resources/templates/list`.
pub type ListResourcesParams = PaginatedRequest;

/// Result of `resources/list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListResourcesResult {
    /// Resources in this page.
    pub resources: Vec<Resource>,
    /// Cursor for the next page.
    #[serde(
        default,
        rename = "nextCursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

/// Result of `resources/templates/list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListResourceTemplatesResult {
    /// Templates in this page.
    #[serde(rename = "resourceTemplates")]
    pub resource_templates: Vec<ResourceTemplate>,
    /// Cursor for the next page.
    #[serde(
        default,
        rename = "nextCursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

/// Params of `resources/read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadResourceRequest {
    /// URI to read.
    pub uri: String,
}

/// Result of `resources/read`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadResourceResult {
    /// One or more resource bodies. Servers may split large payloads, hence
    /// the list.
    pub contents: Vec<ResourceContents>,
}

/// Params of `resources/subscribe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeRequest {
    /// URI to watch.
    pub uri: String,
}

/// Params of `resources/unsubscribe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    /// URI to stop watching.
    pub uri: String,
}

/// Params of `notifications/resources/updated`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUpdatedParams {
    /// URI whose contents changed.
    pub uri: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resources_rename_mime_type() {
        let json = r#"{"uri":"file:///a.txt","name":"a","mimeType":"text/plain"}"#;
        let resource: Resource = serde_json::from_str(json).expect("parses");
        assert_eq!(resource.mime_type.as_deref(), Some("text/plain"));
        assert_eq!(serde_json::to_string(&resource).expect("serializes"), json);
    }

    #[test]
    fn templates_use_uri_template() {
        let json = r#"{"uriTemplate":"logs://{app}","name":"logs"}"#;
        let template: ResourceTemplate = serde_json::from_str(json).expect("parses");
        assert_eq!(template.uri_template, "logs://{app}");
        assert_eq!(serde_json::to_string(&template).expect("serializes"), json);
    }

    #[test]
    fn read_result_requires_contents() {
        let json = r#"{"contents":[{"uri":"file:///a.txt","text":"hi"}]}"#;
        let result: ReadResourceResult = serde_json::from_str(json).expect("parses");
        assert_eq!(result.contents.len(), 1);
        assert_eq!(result.contents[0].uri(), "file:///a.txt");
        assert_eq!(serde_json::to_string(&result).expect("serializes"), json);
    }

    #[test]
    fn subscribe_requires_a_uri() {
        assert!(serde_json::from_value::<SubscribeRequest>(serde_json::json!({})).is_err());
        assert!(
            serde_json::from_value::<UnsubscribeRequest>(serde_json::json!({"uri": "x"})).is_ok()
        );
    }

    #[test]
    fn template_list_renames_its_collection() {
        let result = ListResourceTemplatesResult {
            resource_templates: vec![],
            next_cursor: None,
        };
        assert_eq!(
            serde_json::to_value(&result).expect("serializes"),
            serde_json::json!({"resourceTemplates": []})
        );
    }
}
