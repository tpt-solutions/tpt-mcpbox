// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Conformance against the official MCP JSON Schema for protocol revision
//! 2025-06-18 (vendored under `tests/fixtures`).
//!
//! Each case feeds a message that the specification allows through our types,
//! serializes it back, and checks the output against the schema definition.
//! A negative control proves the schema check can actually fail.

use serde_json::{Value, json};
use tpt_mcpbox_protocol::completion::CompleteResult;
use tpt_mcpbox_protocol::jsonrpc::Response;
use tpt_mcpbox_protocol::model::InitializeResult;
use tpt_mcpbox_protocol::prompts::{GetPromptResult, ListPromptsResult};
use tpt_mcpbox_protocol::resources::{ListResourcesResult, ReadResourceResult};
use tpt_mcpbox_protocol::tools::{CallToolResult, ListToolsResult};

const SCHEMA: &str = include_str!("fixtures/mcp-2025-06-18.schema.json");

/// Asserts that `instance` is valid against the named schema definition.
fn assert_conforms(definition: &str, instance: &Value) {
    let schema: Value = serde_json::from_str(SCHEMA).expect("fixture parses");
    // Point at one definition, keeping the shared `definitions` table so that
    // internal references still resolve.
    let wrapper = json!({
        "$ref": format!("#/definitions/{definition}"),
        "definitions": schema["definitions"],
    });
    let validator = jsonschema::validator_for(&wrapper).expect("schema compiles");
    if let Err(error) = validator.validate(instance) {
        panic!("{definition} does not conform: {error}\n{instance:#}");
    }
}

/// Parses spec-shaped JSON through our type and returns our serialized form.
fn round_trip<T>(spec: Value) -> Value
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let parsed: T = serde_json::from_value(spec).expect("spec-shaped JSON parses");
    serde_json::to_value(&parsed).expect("serializes")
}

fn tool() -> Value {
    json!({
        "name": "echo",
        "description": "Echo the text back",
        "inputSchema": {
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        }
    })
}

#[test]
fn initialize_result_conforms() {
    let out = round_trip::<InitializeResult>(json!({
        "protocolVersion": "2025-06-18",
        "capabilities": { "tools": { "listChanged": true } },
        "serverInfo": { "name": "tpt-mcpbox", "version": "0.1.0" }
    }));
    assert_conforms("InitializeResult", &out);
}

#[test]
fn json_rpc_success_response_conforms() {
    let out = serde_json::to_value(Response::success(1_i64, json!({}))).unwrap();
    assert_conforms("JSONRPCResponse", &out);
}

#[test]
fn json_rpc_error_response_conforms() {
    let out = serde_json::to_value(Response::from_error(
        7_i64,
        tpt_mcpbox_protocol::jsonrpc::ErrorCode::METHOD_NOT_FOUND,
        "no such method",
    ))
    .unwrap();
    assert_conforms("JSONRPCError", &out);
}

#[test]
fn list_tools_result_conforms() {
    let out = round_trip::<ListToolsResult>(json!({ "tools": [tool()] }));
    assert_conforms("ListToolsResult", &out);
}

#[test]
fn call_tool_result_conforms() {
    let out = round_trip::<CallToolResult>(json!({
        "content": [{ "type": "text", "text": "hi" }],
        "isError": false
    }));
    assert_conforms("CallToolResult", &out);
}

#[test]
fn list_resources_result_conforms() {
    let out = round_trip::<ListResourcesResult>(json!({
        "resources": [{ "uri": "file:///notes.md", "name": "notes" }]
    }));
    assert_conforms("ListResourcesResult", &out);
}

#[test]
fn read_resource_result_conforms() {
    let out = round_trip::<ReadResourceResult>(json!({
        "contents": [{ "uri": "file:///notes.md", "mimeType": "text/plain", "text": "hi" }]
    }));
    assert_conforms("ReadResourceResult", &out);
}

#[test]
fn list_prompts_result_conforms() {
    let out = round_trip::<ListPromptsResult>(json!({
        "prompts": [{
            "name": "review",
            "description": "Review a diff",
            "arguments": [{ "name": "path", "required": true }]
        }]
    }));
    assert_conforms("ListPromptsResult", &out);
}

#[test]
fn get_prompt_result_conforms() {
    let out = round_trip::<GetPromptResult>(json!({
        "messages": [{ "role": "user", "content": { "type": "text", "text": "hi" } }]
    }));
    assert_conforms("GetPromptResult", &out);
}

#[test]
fn complete_result_conforms() {
    let out = round_trip::<CompleteResult>(json!({
        "completion": { "values": ["a"], "total": 1, "hasMore": false }
    }));
    assert_conforms("CompleteResult", &out);
}

#[test]
fn schema_check_rejects_a_non_conforming_result() {
    // `content` is required by the specification; without it the check must fail.
    let bad = json!({ "isError": false });
    let schema: Value = serde_json::from_str(SCHEMA).unwrap();
    let wrapper = json!({
        "$ref": "#/definitions/CallToolResult",
        "definitions": schema["definitions"],
    });
    let validator = jsonschema::validator_for(&wrapper).unwrap();
    assert!(validator.validate(&bad).is_err());
}
