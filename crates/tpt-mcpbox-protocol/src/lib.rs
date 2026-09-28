// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! MCP (Model Context Protocol) types and transports used by tpt-mcpbox.
//!
//! This crate is the wire-format boundary of the project. It contains:
//!
//! * [`jsonrpc`] - JSON-RPC 2.0 envelopes (request / response / notification /
//!   batch) plus the JSON-RPC and MCP error codes.
//! * [`model`] - capability negotiation and the client-feature payloads routed
//!   back to the agent (`roots`, `sampling`, `elicitation`).
//! * [`tools`], [`resources`], [`prompts`], [`completion`], [`utilities`] - the
//!   MCP method payloads.
//! * [`transport::stdio`] - newline-delimited JSON stdio transport.
//! * [`transport::http`] - Streamable HTTP transport (POST/GET/DELETE, SSE,
//!   resumable event ids, `Mcp-Session-Id`, origin validation).
//! * [`session`] - lifecycle, capability negotiation and session identity.
//! * [`server`] - dispatch, JSON-RPC error shaping and server-to-agent requests.
//!
//! The crate deliberately performs no policy, sandbox or I/O-authority
//! decisions: it is a faithful, strictly validated implementation of the
//! protocol so that enforcement can be layered on top of it.
//!
//! # Example
//!
//! ```
//! use tpt_mcpbox_protocol::Id;
//! use tpt_mcpbox_protocol::jsonrpc::Request;
//! use tpt_mcpbox_protocol::tools::{CallToolRequest, CallToolResult};
//!
//! let request = Request::new(Id::Number(1), "tools/call")
//!     .with_params(serde_json::json!({"name": "fs_read", "arguments": {"path": "a.txt"}}));
//! let call: CallToolRequest = request.parse_params()?;
//! assert_eq!(call.argument("path").expect("path"), "a.txt");
//!
//! let result = CallToolResult::text("ok");
//! assert_eq!(result.is_error, Some(false));
//! # Ok::<(), tpt_mcpbox_protocol::ProtocolError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod completion;
pub mod content;
pub mod error;
pub mod jsonrpc;
pub mod method;
pub mod model;
pub mod prompts;
pub mod resources;
pub mod server;
pub mod session;
pub mod tools;
pub mod transport;
pub mod utilities;

mod shared;

pub use error::{ProtocolError, Result};
pub use jsonrpc::{
    ClientMessage, Error as JsonRpcError, ErrorCode, Id, Incoming, JSONRPC_VERSION, Notification,
    Request, Response, ServerMessage,
};
pub use server::{Dispatcher, DispatcherOptions, Handler, HandlerFuture};
pub use session::{Session, SessionConfig, SessionId, SessionState};
pub use shared::{
    Annotations, Experimental, Implementation, LATEST_PROTOCOL_VERSION, Page, PaginatedRequest,
    Role, SUPPORTED_PROTOCOL_VERSIONS,
};
pub use tools::{CallToolRequest, CallToolResult, Tool};
