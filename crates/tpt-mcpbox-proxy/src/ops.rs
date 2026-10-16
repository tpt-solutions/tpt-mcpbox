// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! MCP operations that every upstream transport supports.
//!
//! A transport only has to deliver one request/response exchange and one
//! notification through [`RpcChannel`]. The handshake, tool listing and tool
//! calls are written once here on top of that.

use std::collections::HashSet;
use std::future::Future;

use serde_json::{Map, Value};
use tpt_mcpbox_protocol::method;
use tpt_mcpbox_protocol::model::{ClientCapabilities, InitializeParams, InitializeResult};
use tpt_mcpbox_protocol::tools::{CallToolResult, ListToolsResult, Tool};
use tpt_mcpbox_protocol::{Implementation, LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};

use crate::upstream::{UpstreamError, from_value, to_value};

/// One JSON-RPC peer, however it is reached.
pub trait RpcChannel: Send + Sync {
    /// Sends a request and returns the peer's `result`.
    fn call(
        &self,
        method: &str,
        params: Value,
    ) -> impl Future<Output = Result<Value, UpstreamError>> + Send;

    /// Sends a notification. No reply is expected.
    fn notify(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> impl Future<Output = Result<(), UpstreamError>> + Send;
}

/// Performs the `initialize` handshake and sends `notifications/initialized`.
///
/// # Errors
///
/// Fails if the peer rejects the handshake, or negotiates a protocol revision
/// this build does not speak.
pub async fn initialize<C: RpcChannel>(channel: &C) -> Result<InitializeResult, UpstreamError> {
    let params = InitializeParams {
        protocol_version: LATEST_PROTOCOL_VERSION.to_owned(),
        capabilities: ClientCapabilities::default(),
        client_info: Implementation::new("tpt-mcpbox", crate::VERSION),
    };
    let value = channel
        .call(method::lifecycle::INITIALIZE, to_value(&params)?)
        .await?;
    let result: InitializeResult = from_value(value)?;

    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&result.protocol_version.as_str()) {
        return Err(UpstreamError::UnsupportedVersion(result.protocol_version));
    }

    channel.notify(method::lifecycle::INITIALIZED, None).await?;
    Ok(result)
}

/// Fetches every page of `tools/list`.
///
/// A cursor that repeats is reported as malformed rather than looping.
///
/// # Errors
///
/// Fails on transport errors, peer errors, or a repeated cursor.
pub async fn list_tools<C: RpcChannel>(channel: &C) -> Result<Vec<Tool>, UpstreamError> {
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen = HashSet::new();

    loop {
        let params = match &cursor {
            Some(next) => serde_json::json!({ "cursor": next }),
            None => serde_json::json!({}),
        };
        let page: ListToolsResult = from_value(channel.call(method::tools::LIST, params).await?)?;
        tools.extend(page.tools);

        match page.next_cursor {
            Some(next) => {
                if !seen.insert(next.clone()) {
                    return Err(UpstreamError::Malformed(
                        "tools/list cursor repeated".to_owned(),
                    ));
                }
                cursor = Some(next);
            }
            None => return Ok(tools),
        }
    }
}

/// Calls one tool on the peer.
///
/// # Errors
///
/// Fails on transport errors, peer errors, or a malformed result.
pub async fn call_tool<C: RpcChannel>(
    channel: &C,
    name: &str,
    arguments: Option<Map<String, Value>>,
) -> Result<CallToolResult, UpstreamError> {
    let mut params = Map::new();
    params.insert("name".to_owned(), Value::String(name.to_owned()));
    if let Some(arguments) = arguments {
        params.insert("arguments".to_owned(), Value::Object(arguments));
    }
    from_value(
        channel
            .call(method::tools::CALL, Value::Object(params))
            .await?,
    )
}
