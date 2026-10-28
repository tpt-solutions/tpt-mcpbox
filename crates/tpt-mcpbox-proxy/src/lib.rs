// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Policy-enforcing passthrough proxy for external MCP servers (Phase 6).
//!
//! Upstreams are reached over stdio (spawned, supervised child processes) or
//! Streamable HTTP. Every forwarded call is inspected by the policy engine
//! before it leaves the process.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod connection;
pub mod gate;
pub mod http;
pub mod ops;
pub mod supervise;
pub mod upstream;

pub use connection::Connection;
pub use gate::{PolicyGate, ProxyError};
pub use http::HttpClient;
pub use upstream::{Client, UpstreamError, UpstreamOptions};

/// Crate version, surfaced by `mcpbox --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
