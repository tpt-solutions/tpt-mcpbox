// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! MCP (Model Context Protocol) types and transports used by tpt-mcpbox.
//!
//! This crate is the wire-format boundary of the project. It contains:
//!
//! * [`jsonrpc`] â€” JSON-RPC 2.0 envelopes (request / response / notification /
//!   batch) plus the JSON-RPC and MCP error codes.
//! * [`model`] â€” MCP data model shared by tools, resources and prompts.
//! * [`method`] â€” canonical MCP method names.
//! * [`transport::stdio`] â€” newline-delimited JSON stdio transport.
//! * [`transport::http`] â€” Streamable HTTP transport (POST/GET/DELETE, SSE,
//!   resumable event IDs, `Mcp-Session-Id`).
//! * [`session`] â€” lifecycle, capability negotiation and the request dispatcher
//!   that lets the server call back into the agent (`roots`, `sampling`,
//!   `elicitation`).
//!
//! The crate deliberately performs no policy, sandbox or I/O policy decisions: it
//! is a faithful, strictly-validated implementation of the protocol so that
//! enforcement can be layered on top of it.
//!
//! # Example
//!
//! ```
//! use tpt_mcpbox_protocol::jsonrpc::Request;
//! use tpt_mcpbox_protocol::tools::{CallToolRequest, CallToolResult};
//!
//! let request = Request::new(1.into(), "tools/call");
//! let call: CallToolRequest = request.parse_params()?;
//! assert_eq!(call.params.name, "github_search");
//!
//! let result = CallToolResult::text("ok");
//! assert_eq!(result.is_error, Some(false));
//! # Ok::<(), tpt_mcpbox_protocol::ProtocolError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod content;
pub mod error;
pub mod jsonrpc;
pub mod method;
pub mod model;
pub mod server;
pub mod session;
pub mod tools;
pub mod transport;

mod shared;

pub use error::{ProtocolError, Result};
pub use jsonrpc::{
    Error as JsonRpcError, ErrorCode, Id, JSONRPC_VERSION, Notification, Request, Response, ServerToClientRequest,
    CLIENT_INFO_KEY,
};
pub use model::{
    Annotations, ClientCapabilities, Content, Implementation, LoggingLevel, ModelHint, ProgressToken, Prompt,
    PromptArgument, PromptMessage, Resource, ResourceContents, ResourceLink, ResourceTemplate, Role, Root, ServerCapabilities,
};
pub use session::{Session, SessionConfig, SessionState};
pub use tools::{CallToolRequest, CallToolResult, Tool};
