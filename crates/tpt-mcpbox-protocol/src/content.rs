// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Content blocks exchanged in tool results, prompts and resources.
//!
//! MCP models these as a tagged union on `type`
//! (`text` | `image` | `audio` | `resource` | `resource_link`). Binary payloads
//! are base64 strings; tpt-mcpbox additionally enforces size caps at the
//! transport layer before these types are constructed.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::shared::Annotations;

/// UTF-8 text content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextContent {
    /// The text itself.
    pub text: String,
    /// Optional hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
}

impl TextContent {
    /// Wrap a string.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            annotations: None,
        }
    }
}

/// Base64-encoded image content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageContent {
    /// Base64-encoded bytes.
    pub data: String,
    /// IANA media type, e.g. `image/png`.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Optional hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
}

/// Base64-encoded audio content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AudioContent {
    /// Base64-encoded bytes.
    pub data: String,
    /// IANA media type, e.g. `audio/wav`.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Optional hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
}

/// Inline textual resource contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextResourceContents {
    /// Resource URI.
    pub uri: String,
    /// IANA media type, when known.
    #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// The resource body.
    pub text: String,
}

/// Inline binary resource contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlobResourceContents {
    /// Resource URI.
    pub uri: String,
    /// IANA media type, when known.
    #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Base64-encoded bytes.
    pub blob: String,
}

/// The contents of an embedded resource, inline in a message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceContents {
    /// Text body.
    Text(TextResourceContents),
    /// Binary body.
    Blob(BlobResourceContents),
}

impl ResourceContents {
    /// Resource URI regardless of the variant.
    #[must_use]
    pub fn uri(&self) -> &str {
        match self {
            Self::Text(contents) => &contents.uri,
            Self::Blob(contents) => &contents.uri,
        }
    }

    /// Approximate in-memory size, used for payload caps.
    #[must_use]
    pub fn size_hint(&self) -> usize {
        match self {
            Self::Text(contents) => contents.uri.len() + contents.text.len(),
            Self::Blob(contents) => contents.uri.len() + contents.blob.len(),
        }
    }
}

/// A pointer to a resource the client may read separately.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceLink {
    /// Resource URI.
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
    /// Optional hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
}

/// A single content block inside a tool result, prompt message or resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Content {
    /// Text block.
    Text(TextContent),
    /// Image block.
    Image(ImageContent),
    /// Audio block.
    Audio(AudioContent),
    /// Embedded resource body.
    Resource(ResourceContents),
    /// Link to a resource.
    ResourceLink(ResourceLink),
}

impl Content {
    /// Build a text block.
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text(TextContent::new(text))
    }

    /// Build a text block containing pretty-printed JSON.
    ///
    /// # Errors
    /// Returns [`serde_json::Error`] when `value` cannot be serialized.
    pub fn json(value: &Value) -> serde_json::Result<Self> {
        Ok(Self::text(serde_json::to_string_pretty(value)?))
    }

    /// Borrow the text of a [`Content::Text`] block.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(&text.text),
            _ => None,
        }
    }

    /// Wire discriminator (`"text"`, `"image"`, …).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Image(_) => "image",
            Self::Audio(_) => "audio",
            Self::Resource(_) => "resource",
            Self::ResourceLink(_) => "resource_link",
        }
    }

    /// Total payload size of the block, used for transport caps.
    #[must_use]
    pub fn size_hint(&self) -> usize {
        match self {
            Self::Text(text) => text.text.len(),
            Self::Image(image) => image.data.len() + image.mime_type.len(),
            Self::Audio(audio) => audio.data.len() + audio.mime_type.len(),
            Self::Resource(contents) => contents.size_hint(),
            Self::ResourceLink(link) => link.uri.len() + link.name.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_content_round_trips() {
        let json = r#"{"type":"text","text":"hello"}"#;
        let content: Content = serde_json::from_str(json).expect("parses");
        assert_eq!(content.as_text(), Some("hello"));
        assert_eq!(serde_json::to_string(&content).expect("serializes"), json);
    }

    #[test]
    fn image_content_renames_mime_type() {
        let json = r#"{"type":"image","data":"AA==","mimeType":"image/png"}"#;
        let content: Content = serde_json::from_str(json).expect("parses");
        assert_eq!(serde_json::to_string(&content).expect("serializes"), json);
    }

    #[test]
    fn resource_contents_are_untagged() {
        let json = r#"{"type":"resource","uri":"file:///a.txt","mimeType":"text/plain","text":"body"}"#;
        let content: Content = serde_json::from_str(json).expect("parses");
        let Content::Resource(ResourceContents::Text(text)) = &content else {
            panic!("expected embedded text resource, got {content:?}");
        };
        assert_eq!(text.uri, "file:///a.txt");
        assert_eq!(content.size_hint(), "file:///a.txt".len() + "body".len());
    }

    #[test]
    fn blob_resources_keep_their_payload() {
        let json = r#"{"type":"resource","uri":"file:///a.bin","blob":"AA=="}"#;
        let content: Content = serde_json::from_str(json).expect("parses");
        let Content::Resource(ResourceContents::Blob(blob)) = &content else {
            panic!("expected embedded blob resource");
        };
        assert_eq!(blob.blob, "AA==");
    }

    #[test]
    fn resource_links_use_the_snake_case_tag() {
        let json = r#"{"type":"resource_link","uri":"file:///a.txt","name":"a"}"#;
        let content: Content = serde_json::from_str(json).expect("parses");
        assert_eq!(content.kind(), "resource_link");
        assert_eq!(serde_json::to_string(&content).expect("serializes"), json);
    }

    #[test]
    fn json_helper_produces_a_text_block() {
        let content = Content::json(&serde_json::json!({"ok": true})).expect("serializes");
        assert!(content.as_text().expect("text").contains("\"ok\""));
    }

    #[test]
    fn unknown_content_types_are_rejected() {
        assert!(serde_json::from_str::<Content>(r#"{"type":"video","data":"AA=="}"#).is_err());
    }
}
