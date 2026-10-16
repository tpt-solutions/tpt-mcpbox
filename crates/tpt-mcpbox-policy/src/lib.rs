// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Capability-based policy engine for tpt-mcpbox (Phase 3).
//!
//! Two evaluators compose into one [`Policy`]: a simplified YAML DSL and an
//! embedded Rego module evaluated with `regorus`. Evaluation is deny-by-default,
//! and every decision carries a reason and a rule id so the audit log can explain
//! *why* a call was blocked. See [`Policy`] for how the two are combined.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

mod decision;
mod dsl;
mod error;
pub mod normalize;
mod policy;
mod rego;

pub use decision::{Decision, PolicyInput};
pub use dsl::Engine;
pub use error::PolicyError;
pub use policy::Policy;

/// Crate version, surfaced by `mcpbox --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
