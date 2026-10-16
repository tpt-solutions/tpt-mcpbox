// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! One upstream connection, whichever transport carries it.
//!
//! Callers that hold a [`crate::PolicyGate`] or set up an upstream do not need
//! to know whether it is a child process or an HTTP endpoint. [`Connection`]
//! forwards the MCP operations to the right client.

use serde_json::{Map, Value};
use tpt_mcpbox_protocol::model::InitializeResult;
use tpt_mcpbox_protocol::prompts::{GetPromptResult, Prompt};
use tpt_mcpbox_protocol::resources::{ReadResourceResult, Resource};
use tpt_mcpbox_protocol::tools::{CallToolResult, Tool};

use crate::http::HttpClient;
use crate::ops;
use crate::upstream::{Client, UpstreamError};

/// A connected upstream, stdio or Streamable HTTP.
#[derive(Debug)]
pub enum Connection {
    /// Child process speaking newline-delimited JSON-RPC.
    Stdio(Client),
    /// Streamable HTTP endpoint.
    Http(HttpClient),
}

impl From<Client> for Connection {
    fn from(client: Client) -> Self {
        Self::Stdio(client)
    }
}

impl From<HttpClient> for Connection {
    fn from(client: HttpClient) -> Self {
        Self::Http(client)
    }
}

impl Connection {
    /// Performs the `initialize` handshake.
    ///
    /// # Errors
    ///
    /// See [`crate::ops::initialize`].
    pub async fn initialize(&self) -> Result<InitializeResult, UpstreamError> {
        match self {
            Self::Stdio(client) => client.initialize().await,
            Self::Http(client) => client.initialize().await,
        }
    }

    /// Lists every tool, across all pages.
    ///
    /// # Errors
    ///
    /// See [`crate::ops::list_tools`].
    pub async fn list_tools(&self) -> Result<Vec<Tool>, UpstreamError> {
        match self {
            Self::Stdio(client) => client.list_tools().await,
            Self::Http(client) => client.list_tools().await,
        }
    }

    /// Calls one tool. Policy is not checked here; use [`crate::PolicyGate`]
    /// for that.
    ///
    /// # Errors
    ///
    /// See [`crate::ops::call_tool`].
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<Map<String, Value>>,
    ) -> Result<CallToolResult, UpstreamError> {
        match self {
            Self::Stdio(client) => client.call_tool(name, arguments).await,
            Self::Http(client) => client.call_tool(name, arguments).await,
        }
    }

    /// Lists every resource, across all pages.
    ///
    /// # Errors
    ///
    /// See [`crate::ops::list_resources`].
    pub async fn list_resources(&self) -> Result<Vec<Resource>, UpstreamError> {
        match self {
            Self::Stdio(client) => ops::list_resources(client).await,
            Self::Http(client) => ops::list_resources(client).await,
        }
    }

    /// Reads one resource. Policy is not checked here; see [`crate::PolicyGate`].
    ///
    /// # Errors
    ///
    /// See [`crate::ops::read_resource`].
    pub async fn read_resource(&self, uri: &str) -> Result<ReadResourceResult, UpstreamError> {
        match self {
            Self::Stdio(client) => ops::read_resource(client, uri).await,
            Self::Http(client) => ops::read_resource(client, uri).await,
        }
    }

    /// Lists every prompt, across all pages.
    ///
    /// # Errors
    ///
    /// See [`crate::ops::list_prompts`].
    pub async fn list_prompts(&self) -> Result<Vec<Prompt>, UpstreamError> {
        match self {
            Self::Stdio(client) => ops::list_prompts(client).await,
            Self::Http(client) => ops::list_prompts(client).await,
        }
    }

    /// Renders one prompt. Policy is not checked here; see [`crate::PolicyGate`].
    ///
    /// # Errors
    ///
    /// See [`crate::ops::get_prompt`].
    pub async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<Map<String, Value>>,
    ) -> Result<GetPromptResult, UpstreamError> {
        match self {
            Self::Stdio(client) => ops::get_prompt(client, name, arguments).await,
            Self::Http(client) => ops::get_prompt(client, name, arguments).await,
        }
    }
}
