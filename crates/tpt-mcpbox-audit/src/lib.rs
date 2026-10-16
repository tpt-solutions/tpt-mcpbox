// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Tamper-evident audit log and observability plumbing for tpt-mcpbox (Phase 9).
//!
//! Audit entries are append-only and chained: every entry embeds the hash of
//! its predecessor, so `mcpbox audit verify` can detect any modification of the
//! recorded history. Entries record secret *names* only — never values.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod chain;

pub use chain::{AuditError, AuditLog, Entry, GENESIS, VerifyReport, verify};

/// Crate version, surfaced by `mcpbox --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
