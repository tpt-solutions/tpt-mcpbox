// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Capability-based policy engine for tpt-mcpbox (Phase 3).
//!
//! Two evaluators are planned: a simplified YAML DSL (default) and embedded Rego
//! via `regorus`. Only the YAML DSL is built so far; see [`Engine`]. Evaluation
//! is deny-by-default, and every decision carries a reason and a rule id so the
//! audit log can explain *why* a call was blocked.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

mod decision;
mod dsl;
mod error;
mod normalize;

pub use decision::{Decision, PolicyInput};
pub use dsl::Engine;
pub use error::PolicyError;

/// Crate version, surfaced by `mcpbox --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
