// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Tool descriptors plus the `tools/list` and `tools/call` payloads.
//!
//! `input_schema` is a JSON Schema document as defined by the MCP tool
//! specification. tpt-mcpbox treats it as *documentation for the agent* only:
//! the authoritative check is the policy engine's argument validation, because
//! a schema is supplied by the tool author and therefore untrusted.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::content::Content;
use crate::shared::PaginatedRequest;

/// Behavioural hints for a tool.
///
/// These are advisory hints for the agent. tpt-mcpbox never derives a security
/// decision from them — `destructive_hint: false` grants nothing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolAnnotations {
    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The tool does not modify its environment.
    #[serde(
        default,
        rename = "readOnlyHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub read_only_hint: Option<bool>,
    /// The tool may perform destructive updates.
    #[serde(
        default,
        rename = "destructiveHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub destructive_hint: Option<bool>,
    /// Repeating a call with the same arguments has no additional effect.
    #[serde(
        default,
        rename = "idempotentHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub idempotent_hint: Option<bool>,
    /// The tool may interact with an open world (e.g. the network).
    #[serde(
        default,
        rename = "openWorldHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub open_world_hint: Option<bool>,
}

/// A tool exposed by the hub: a Wasm tool, or a renamed proxied upstream tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    /// Unique, policy-checked name the agent calls.
    pub name: String,
    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// What the tool does; agents rely on this heavily.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema describing `tools/call` arguments.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    /// JSON Schema describing the structured result, when the tool provides one.
    #[serde(
        default,
        rename = "outputSchema",
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema: Option<Value>,
    /// Behavioural hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

impl Tool {
    /// Build a tool with an explicit JSON Schema document.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
    ) -> Self {
        Self {
            name: name.into(),
            title: None,
            description: Some(description.into()),
            input_schema,
            output_schema: None,
            annotations: None,
        }
    }

    /// The canonical object schema: `{"type":"object"}`.
    #[must_use]
    pub fn empty_object_schema() -> Value {
        serde_json::json!({ "type": "object", "properties": {} })
    }

    /// Attach an output schema.
    #[must_use]
    pub fn with_output_schema(mut self, schema: Value) -> Self {
        self.output_schema = Some(schema);
        self
    }
}

/// Params of `tools/list`.
pub type ListToolsParams = PaginatedRequest;

/// Result of `tools/list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListToolsResult {
    /// Tools visible to this session.
    pub tools: Vec<Tool>,
    /// Cursor for the next page, when more remain.
    #[serde(
        default,
        rename = "nextCursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

impl ListToolsResult {
    /// A single, complete page.
    pub fn new(tools: Vec<Tool>) -> Self {
        Self {
            tools,
            next_cursor: None,
        }
    }

    /// `true` when another page is available.
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

/// Params of `tools/call`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallToolRequest {
    /// Name of the tool to invoke.
    pub name: String,
    /// Arguments, validated against the tool schema and the policy rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Map<String, Value>>,
}

impl CallToolRequest {
    /// Call `name` with no arguments.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            arguments: None,
        }
    }

    /// Attach arguments.
    #[must_use]
    pub fn with_arguments(mut self, arguments: impl IntoIterator<Item = (String, Value)>) -> Self {
        self.arguments = Some(arguments.into_iter().collect());
        self
    }

    /// Borrow an argument.
    #[must_use]
    pub fn argument(&self, key: &str) -> Option<&Value> {
        self.arguments.as_ref().and_then(|map| map.get(key))
    }
}

/// Result of `tools/call`.
///
/// A *tool* failure is reported as `is_error: true` with human-readable
/// content; it is not a JSON-RPC error. Protocol-level failures (unknown tool,
/// policy denial) use the JSON-RPC `error` member instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallToolResult {
    /// Content blocks returned by the tool.
    pub content: Vec<Content>,
    /// Machine-readable result, when the tool defines `outputSchema`.
    #[serde(
        default,
        rename = "structuredContent",
        skip_serializing_if = "Option::is_none"
    )]
    pub structured_content: Option<Value>,
    /// `true` when the tool itself failed.
    #[serde(default, rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

impl CallToolResult {
    /// A successful text result.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content::text(text)],
            structured_content: None,
            is_error: Some(false),
        }
    }

    /// A successful structured result carrying JSON text plus
    /// `structuredContent`.
    ///
    /// # Errors
    /// Returns [`serde_json::Error`] when `value` cannot be serialized.
    pub fn structured(value: &Value) -> serde_json::Result<Self> {
        Ok(Self {
            content: vec![Content::json(value)?],
            structured_content: Some(value.clone()),
            is_error: Some(false),
        })
    }

    /// A tool-level failure.
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content::text(text)],
            structured_content: None,
            is_error: Some(true),
        }
    }

    /// Append a content block.
    #[must_use]
    pub fn with_content(mut self, content: Content) -> Self {
        self.content.push(content);
        self
    }

    /// `true` when the tool reported a failure.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.is_error.unwrap_or(false)
    }

    /// Concatenated text of all text blocks; handy for logging and tests.
    #[must_use]
    pub fn joined_text(&self) -> String {
        self.content
            .iter()
            .filter_map(Content::as_text)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Convenience alias for tool argument maps.
pub type ToolArguments = BTreeMap<String, Value>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_serializes_input_schema_as_camel_case() {
        let tool = Tool::new("fs_read", "Read a file", Tool::empty_object_schema());
        let json = serde_json::to_value(&tool).expect("serializes");
        assert_eq!(json["inputSchema"]["type"], "object");
        assert!(json.get("outputSchema").is_none());
    }

    #[test]
    fn call_request_parses_from_params() {
        let request: CallToolRequest = serde_json::from_value(serde_json::json!({
            "name": "github_search",
            "arguments": {"query": "rust wasm"}
        }))
        .expect("parses");
        assert_eq!(request.name, "github_search");
        assert_eq!(request.argument("query").expect("arg"), "rust wasm");
    }

    #[test]
    fn call_request_without_arguments_is_valid() {
        let request: CallToolRequest =
            serde_json::from_value(serde_json::json!({"name": "ping"})).expect("parses");
        assert!(request.arguments.is_none());
    }

    #[test]
    fn call_request_requires_a_name() {
        assert!(
            serde_json::from_value::<CallToolRequest>(serde_json::json!({"arguments": {}}))
                .is_err()
        );
    }

    #[test]
    fn text_result_sets_is_error_false() {
        let result = CallToolResult::text("ok");
        assert!(!result.failed());
        assert_eq!(result.joined_text(), "ok");
        assert_eq!(
            serde_json::to_value(&result).expect("serializes")["isError"],
            serde_json::json!(false)
        );
    }

    #[test]
    fn error_result_sets_is_error_true() {
        let result = CallToolResult::error("denied by policy");
        assert!(result.failed());
        assert_eq!(result.joined_text(), "denied by policy");
    }

    #[test]
    fn structured_results_carry_both_shapes() {
        let result =
            CallToolResult::structured(&serde_json::json!({"total": 2})).expect("serializes");
        assert_eq!(
            result.structured_content.as_ref().expect("structured")["total"],
            2
        );
        assert!(result.joined_text().contains("total"));
    }

    #[test]
    fn list_results_report_more_pages() {
        let mut page = ListToolsResult::new(vec![]);
        assert!(!page.has_more());
        page.next_cursor = Some("cursor-2".to_owned());
        assert!(page.has_more());
        assert_eq!(
            serde_json::to_value(&page).expect("serializes")["nextCursor"],
            "cursor-2"
        );
    }

    #[test]
    fn annotations_are_advisory_only() {
        let tool = Tool {
            name: "t".to_owned(),
            title: None,
            description: None,
            input_schema: Tool::empty_object_schema(),
            output_schema: None,
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(true),
                ..ToolAnnotations::default()
            }),
        };
        let json = serde_json::to_value(&tool).expect("serializes");
        assert_eq!(json["annotations"]["readOnlyHint"], true);
    }
}

/// How a Wasm tool encodes its call result.
///
/// A tool that declares no format returns plain text, as before. A tool that
/// declares `envelope-v1` returns a JSON object `{"content": [...], "isError": bool}`
/// whose content blocks are MCP content, so it can return images and resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultFormat {
    /// The whole result is one text block.
    Text,
    /// A JSON envelope of MCP content blocks.
    EnvelopeV1,
}

/// A tool a component reports, with the format of its call results.
#[derive(Debug, Clone, PartialEq)]
pub struct GuestTool {
    /// The tool's descriptor.
    pub tool: Tool,
    /// How its call results are encoded.
    pub result: ResultFormat,
}

/// One tool as a Wasm component reports it: `name`, optional `description`, an
/// `input_schema` object, and optional `result` format. Unknown fields are
/// refused, so a guest cannot slip extra data past the host.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestDescriptor {
    name: String,
    #[serde(default)]
    description: Option<String>,
    input_schema: serde_json::Value,
    #[serde(default)]
    result: Option<String>,
}

/// Parses the JSON array of descriptors a Wasm component reports at load time.
///
/// The component is untrusted, so the input is treated as hostile: any
/// malformed entry fails the whole parse, names must be non-empty, each
/// `input_schema` must be a JSON object, and the result format must be one this
/// host knows.
///
/// # Errors
///
/// Returns the JSON error for malformed input, or a message for an empty name, a
/// non-object schema or an unknown result format.
pub fn parse_descriptors(json: &str) -> Result<Vec<GuestTool>, String> {
    let items: Vec<GuestDescriptor> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    items
        .into_iter()
        .map(|item| {
            if item.name.is_empty() {
                return Err("a tool has an empty name".to_owned());
            }
            if !item.input_schema.is_object() {
                return Err(format!(
                    "tool `{}` has a non-object input_schema",
                    item.name
                ));
            }
            let result = match item.result.as_deref() {
                None | Some("text") => ResultFormat::Text,
                Some("envelope-v1") => ResultFormat::EnvelopeV1,
                Some(other) => {
                    return Err(format!(
                        "tool `{}` declares unknown result format `{other}`",
                        item.name
                    ));
                }
            };
            Ok(GuestTool {
                tool: Tool {
                    name: item.name,
                    title: None,
                    description: item.description,
                    input_schema: item.input_schema,
                    output_schema: None,
                    annotations: None,
                },
                result,
            })
        })
        .collect()
}

/// The envelope a tool returns under [`ResultFormat::EnvelopeV1`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    content: Vec<Content>,
    #[serde(default, rename = "isError")]
    is_error: bool,
}

/// Decodes a call result under `format`.
///
/// # Errors
///
/// Returns a message for an envelope that is not valid JSON of the expected
/// shape, or that names a content type outside MCP. The message does not repeat
/// the result, which may be large or sensitive.
pub fn decode_result(format: ResultFormat, raw: &str) -> Result<CallToolResult, String> {
    match format {
        ResultFormat::Text => Ok(CallToolResult::text(raw)),
        ResultFormat::EnvelopeV1 => {
            // The serde message can echo the content, so it is not passed on.
            let envelope: Envelope = serde_json::from_str(raw)
                .map_err(|_| "the result is not a valid envelope".to_owned())?;
            Ok(CallToolResult {
                content: envelope.content,
                structured_content: None,
                is_error: Some(envelope.is_error),
            })
        }
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::parse_descriptors;

    #[test]
    fn well_formed_descriptors_parse() {
        let tools = parse_descriptors(
            r#"[{"name":"echo","description":"returns its arguments","input_schema":{"type":"object"}},
                {"name":"plain","input_schema":{}}]"#,
        )
        .unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(
            tools[0].tool.description.as_deref(),
            Some("returns its arguments")
        );
        assert_eq!(tools[1].tool.description, None);
    }

    #[test]
    fn one_bad_entry_fails_the_whole_list() {
        let good = r#"{"name":"ok","input_schema":{}}"#;
        for bad in [
            r#"{"name":"","input_schema":{}}"#,
            r#"{"name":"x","input_schema":null}"#,
            r#"{"name":"x","input_schema":[]}"#,
            r#"{"name":"x","input_schema":{},"extra":1}"#,
            r#"{"input_schema":{}}"#,
        ] {
            let list = format!("[{good},{bad}]");
            assert!(parse_descriptors(&list).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn non_array_input_is_refused() {
        assert!(parse_descriptors("{}").is_err());
        assert!(parse_descriptors("null").is_err());
        assert!(parse_descriptors("").is_err());
    }
}

#[cfg(test)]
mod envelope_tests {
    use super::{ResultFormat, decode_result};
    use crate::content::Content;

    #[test]
    fn plain_text_results_are_one_text_block() {
        let result = decode_result(ResultFormat::Text, "hello").unwrap();
        assert_eq!(result.content, vec![Content::text("hello")]);
        assert_eq!(result.is_error, Some(false));
    }

    #[test]
    fn an_envelope_carries_mixed_content_blocks() {
        let raw = r#"{"content":[
            {"type":"text","text":"done"},
            {"type":"image","data":"aGk=","mimeType":"image/png"},
            {"type":"resource","resource":{"uri":"file:///a","mimeType":"text/plain","text":"x"}}
        ]}"#;
        let result = decode_result(ResultFormat::EnvelopeV1, raw).unwrap();
        assert_eq!(result.content.len(), 3);
        assert_eq!(result.is_error, Some(false));
    }

    #[test]
    fn an_envelope_can_report_a_tool_failure() {
        let raw = r#"{"content":[{"type":"text","text":"no such file"}],"isError":true}"#;
        assert_eq!(
            decode_result(ResultFormat::EnvelopeV1, raw)
                .unwrap()
                .is_error,
            Some(true)
        );
    }

    #[test]
    fn malformed_envelopes_are_refused_without_echoing_them() {
        for raw in [
            "not json",
            r#"{"content":"text"}"#,
            r#"{"content":[{"type":"bogus","text":"x"}]}"#,
            r#"{"content":[],"extra":1}"#,
            r#"{"isError":false}"#,
        ] {
            let error = decode_result(ResultFormat::EnvelopeV1, raw).expect_err(raw);
            assert!(
                !error.contains("bogus") && !error.contains("extra"),
                "{error}"
            );
        }
    }
}
