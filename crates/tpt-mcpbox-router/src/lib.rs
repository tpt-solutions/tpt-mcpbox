// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Request routing, namespaced aggregation and rate limiting for tpt-mcpbox
//! (Phase 5).
//!
//! The router merges tools/resources/prompts contributed by the local Wasm
//! runtime and by every proxied upstream into a single namespaced view, applies
//! per-tool and per-client rate limits, and drains in-flight work on shutdown.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

/// Crate version, surfaced by `mcpbox --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
