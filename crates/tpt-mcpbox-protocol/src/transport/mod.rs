// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Transports that carry MCP messages between an agent and the hub.
//!
//! Both transports are thin: they frame bytes, enforce size and origin limits,
//! and hand payloads to [`crate::server::Dispatcher`]. Neither performs policy
//! decisions, so a transport bug cannot grant authority on its own.

pub mod http;
pub mod stdio;

/// Header carrying the Streamable HTTP session identifier.
pub const SESSION_HEADER: &str = "mcp-session-id";

/// Media type for a single JSON-RPC message.
pub const JSON_MEDIA_TYPE: &str = "application/json";

/// Media type for server-sent event streams.
pub const SSE_MEDIA_TYPE: &str = "text/event-stream";

/// Default cap for a single inbound payload (4 MiB).
///
/// Tool arguments are agent-controlled, so an unbounded body is a
/// denial-of-service vector; oversized payloads are rejected with
/// `ErrorCode::CONTENT_TOO_LARGE`.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
