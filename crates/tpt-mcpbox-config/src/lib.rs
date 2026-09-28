// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Configuration model, loading, validation and secret handling for tpt-mcpbox.
//!
//! Scope (Phase 2): the `tpt-mcpbox.yaml` schema (tools, upstreams, server,
//! policy, audit, metrics, logging), strict validation with actionable
//! diagnostics, config discovery/layering, `.env` + environment secret sources,
//! [`config::SecretString`] zeroizing redaction, and the hot-reload
//! configuration store.
//!
//! Until Phase 2 lands this crate intentionally exposes only the crate root so
//! the workspace keeps building and linting.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

/// Crate version, surfaced by `mcpbox --version` and `/healthz`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
