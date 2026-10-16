// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! One upstream connection, whichever transport carries it.
//!
//! Callers that hold a [`crate::PolicyGate`] or set up an upstream do not need
//! to know whether it is a child process or an HTTP endpoint. [`Connection`]
//! forwards the MCP operations to the right client.

use serde_json::{Map, Value};
use tpt_mcpbox_protocol::model::InitializeResult;
use tpt_mcpbox_protocol::tools::{CallToolResult, Tool};

use crate::http::HttpClient;
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
}
