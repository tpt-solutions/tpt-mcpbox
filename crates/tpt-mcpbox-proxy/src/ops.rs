// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! MCP operations that every upstream transport supports.
//!
//! A transport only has to deliver one request/response exchange and one
//! notification through [`RpcChannel`]. The handshake, tool, resource and prompt
//! operations are written once here on top of that.

use std::collections::HashSet;
use std::future::Future;

use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use tpt_mcpbox_protocol::method;
use tpt_mcpbox_protocol::model::{ClientCapabilities, InitializeParams, InitializeResult};
use tpt_mcpbox_protocol::prompts::{GetPromptResult, ListPromptsResult, Prompt};
use tpt_mcpbox_protocol::resources::{ListResourcesResult, ReadResourceResult, Resource};
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

/// Walks every page of a paginated list method.
///
/// `take` splits one page into its items and the cursor for the next page. A
/// cursor that repeats is reported as malformed rather than looping forever.
async fn collect_pages<C, R, T>(
    channel: &C,
    method: &str,
    take: impl Fn(R) -> (Vec<T>, Option<String>),
) -> Result<Vec<T>, UpstreamError>
where
    C: RpcChannel,
    R: DeserializeOwned,
{
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen = HashSet::new();

    loop {
        let params = match &cursor {
            Some(next) => json!({ "cursor": next }),
            None => json!({}),
        };
        let page: R = from_value(channel.call(method, params).await?)?;
        let (page_items, next) = take(page);
        items.extend(page_items);

        match next {
            Some(next) => {
                if !seen.insert(next.clone()) {
                    return Err(UpstreamError::Malformed(format!(
                        "{method} cursor repeated"
                    )));
                }
                cursor = Some(next);
            }
            None => return Ok(items),
        }
    }
}

/// Fetches every page of `tools/list`.
///
/// # Errors
///
/// Fails on transport errors, peer errors, or a repeated cursor.
pub async fn list_tools<C: RpcChannel>(channel: &C) -> Result<Vec<Tool>, UpstreamError> {
    collect_pages(channel, method::tools::LIST, |page: ListToolsResult| {
        (page.tools, page.next_cursor)
    })
    .await
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

/// Fetches every page of `resources/list`.
///
/// # Errors
///
/// Fails on transport errors, peer errors, or a repeated cursor.
pub async fn list_resources<C: RpcChannel>(channel: &C) -> Result<Vec<Resource>, UpstreamError> {
    collect_pages(
        channel,
        method::resources::LIST,
        |page: ListResourcesResult| (page.resources, page.next_cursor),
    )
    .await
}

/// Reads one resource by URI.
///
/// # Errors
///
/// Fails on transport errors, peer errors, or a malformed result.
pub async fn read_resource<C: RpcChannel>(
    channel: &C,
    uri: &str,
) -> Result<ReadResourceResult, UpstreamError> {
    from_value(
        channel
            .call(method::resources::READ, json!({ "uri": uri }))
            .await?,
    )
}

/// Fetches every page of `prompts/list`.
///
/// # Errors
///
/// Fails on transport errors, peer errors, or a repeated cursor.
pub async fn list_prompts<C: RpcChannel>(channel: &C) -> Result<Vec<Prompt>, UpstreamError> {
    collect_pages(channel, method::prompts::LIST, |page: ListPromptsResult| {
        (page.prompts, page.next_cursor)
    })
    .await
}

/// Renders one prompt with the given arguments.
///
/// # Errors
///
/// Fails on transport errors, peer errors, or a malformed result.
pub async fn get_prompt<C: RpcChannel>(
    channel: &C,
    name: &str,
    arguments: Option<Map<String, Value>>,
) -> Result<GetPromptResult, UpstreamError> {
    let mut params = Map::new();
    params.insert("name".to_owned(), Value::String(name.to_owned()));
    if let Some(arguments) = arguments {
        params.insert("arguments".to_owned(), Value::Object(arguments));
    }
    from_value(
        channel
            .call(method::prompts::GET, Value::Object(params))
            .await?,
    )
}
