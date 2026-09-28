// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Small types shared by every MCP message: protocol version, implementation
//! identity, prompt roles, annotations and the pagination envelope.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The MCP protocol revision this build implements.
pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

/// Protocol revisions understood by this build, newest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Name/version pair identifying a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Implementation {
    /// Program name, e.g. `tpt-mcpbox`.
    pub name: String,
    /// Human-readable title, when the peer has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Version string.
    pub version: String,
    /// Optional homepage / documentation URL.
    #[serde(
        default,
        rename = "websiteUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub website_url: Option<String>,
}

impl Implementation {
    /// Build an implementation identity with only the required fields.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            title: None,
            version: version.into(),
            website_url: None,
        }
    }
}

/// Who authored a prompt message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The end user.
    User,
    /// The model.
    Assistant,
}

impl Role {
    /// Wire representation (`"user"` / `"assistant"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

/// Optional hints attached to content, resources and tools.
///
/// `audience` is advisory; clients that do not understand the hint may ignore
/// it. tpt-mcpbox does **not** rely on annotations for security decisions.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Annotations {
    /// Who the content is intended for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<Role>>,
    /// Importance hint, `0.0`–`1.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<f32>,
    /// Last modification time, milliseconds since the Unix epoch.
    #[serde(
        default,
        rename = "lastModified",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_modified: Option<i64>,
}

/// Cursor request parameters shared by every paginated `list` method.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginatedRequest {
    /// Opaque cursor returned by a previous page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// A page of results plus the cursor for the next page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Page<T> {
    /// Items in this page.
    pub items: Vec<T>,
    /// Cursor to pass back for the next page; absent on the last page.
    #[serde(
        default,
        rename = "nextCursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// A single, final page.
    pub fn single(items: Vec<T>) -> Self {
        Self {
            items,
            next_cursor: None,
        }
    }

    /// A page that is followed by another one.
    pub fn with_cursor(items: Vec<T>, next_cursor: impl Into<String>) -> Self {
        Self {
            items,
            next_cursor: Some(next_cursor.into()),
        }
    }

    /// `true` when more pages remain.
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

/// Experimental, opt-in capability namespaces.
pub type Experimental = BTreeMap<String, Value>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_versions_are_declared_newest_first() {
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS[0], LATEST_PROTOCOL_VERSION);
    }

    #[test]
    fn implementation_serializes_only_required_fields() {
        let json =
            serde_json::to_string(&Implementation::new("tpt-mcpbox", "0.1.0")).expect("serializes");
        assert_eq!(json, r#"{"name":"tpt-mcpbox","version":"0.1.0"}"#);
    }

    #[test]
    fn roles_use_lowercase_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&Role::Assistant).expect("serializes"),
            "\"assistant\""
        );
    }

    #[test]
    fn pages_omit_the_cursor_when_final() {
        let page: Page<u8> = Page::single(vec![1, 2]);
        assert_eq!(
            serde_json::to_string(&page).expect("serializes"),
            r#"{"items":[1,2]}"#
        );
        assert!(!page.has_more());
    }

    #[test]
    fn pages_rename_the_cursor_to_next_cursor() {
        let page: Page<u8> = Page::with_cursor(vec![1], "cursor-2");
        assert!(page.has_more());
        assert_eq!(
            serde_json::to_value(&page).expect("serializes")["nextCursor"],
            "cursor-2"
        );
    }

    #[test]
    fn annotations_are_omitted_when_absent() {
        let json = serde_json::to_string(&Annotations::default()).expect("serializes");
        assert_eq!(json, "{}");
    }
}
