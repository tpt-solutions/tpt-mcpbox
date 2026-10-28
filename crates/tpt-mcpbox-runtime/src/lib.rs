// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Wasm component runtime, warm instance pool and WASI capability mapper for
//! tpt-mcpbox (Phase 4).
//!
//! Every tool invocation runs inside a `wasmtime` component instance whose only
//! ambient authority is derived from its configured capabilities. Filesystem
//! grants become preopened directories, network access goes through a host
//! `wasi:http` handler that enforces the domain allowlist and injects secret
//! headers, and environment variables are exposed only when granted. Secrets
//! never enter the guest.
//!
//! Entry points: [`Runtime::new`] builds the engine, [`Runtime::load_tool`]
//! compiles a tool from its configuration, [`LoadedTool::call`] runs it, and
//! [`Runtime::self_test`] proves the sandbox at startup.
//!
//! Not yet built: OCI module pulls and signature verification. Modules are
//! loaded from local paths and pinned by SHA-256.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

mod bindings;
mod error;
mod module;
mod outbound;
mod probe;
mod runtime;
mod sandbox;
mod tool;

pub use error::ToolError;
pub use outbound::HostCheck;
pub use probe::{PROBE_SHA256, PROBE_WASM};
pub use runtime::{CancelToken, Runtime};
pub use tool::{
    DEFAULT_MAX_CONCURRENT, DEFAULT_MEMORY_BYTES, DEFAULT_PAYLOAD_BYTES, DEFAULT_RECYCLE_AFTER,
    DEFAULT_TIME_LIMIT, LoadedTool, PoolUsage,
};

/// Crate version, surfaced by `mcpbox --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
