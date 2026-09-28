// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Wasm component runtime, warm instance pool and WASI capability mapper for
//! tpt-mcpbox (Phase 4).
//!
//! Every tool invocation runs inside a `wasmtime` component instance whose only
//! ambient authority is derived from the policy engine's decision. The host
//! intercepts `wasi:http/outgoing-handler` to enforce the domain allowlist and
//! injects secret headers at the proxy layer, so secrets never enter the guest.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

/// Crate version, surfaced by `mcpbox --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
