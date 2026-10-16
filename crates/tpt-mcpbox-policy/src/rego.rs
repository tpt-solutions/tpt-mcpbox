// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The embedded Rego evaluator, backed by `regorus`.
//!
//! A Rego module is a complete policy, so it is always consulted when configured
//! and never yields "no opinion". The module contract is:
//!
//! - it declares `package tpt.mcpbox`;
//! - it defines `allow` (normally `default allow := false`);
//! - it reads the request from `input`, whose shape is [`crate::PolicyInput`]
//!   serialised as JSON.
//!
//! Any evaluation error (a runtime type error, an undefined `allow`) is treated
//! as a refusal. A broken module therefore fails closed.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use crate::decision::PolicyInput;
use crate::error::PolicyError;

/// The query whose boolean value decides a request.
const ALLOW_QUERY: &str = "data.tpt.mcpbox.allow";

/// A compiled Rego module, ready to evaluate.
pub(crate) struct RegoEngine {
    engine: Mutex<regorus::Engine>,
}

impl std::fmt::Debug for RegoEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegoEngine").finish_non_exhaustive()
    }
}

impl RegoEngine {
    /// Read and compile the module at `path`.
    pub(crate) fn load(path: &Path) -> Result<Self, PolicyError> {
        let source = std::fs::read_to_string(path).map_err(|source| PolicyError::RegoRead {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_source(&path.display().to_string(), source)
    }

    /// Compile a module from source. `name` is used only in diagnostics.
    pub(crate) fn from_source(name: &str, source: String) -> Result<Self, PolicyError> {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy(name.to_owned(), source)
            .map_err(|error| PolicyError::RegoCompile {
                module: name.to_owned(),
                message: error.to_string(),
            })?;
        Ok(Self {
            engine: Mutex::new(engine),
        })
    }

    /// Ask the module whether `input` is allowed.
    ///
    /// Returns `Err` with a message when evaluation fails. Callers must treat
    /// that as a refusal.
    pub(crate) fn allows(&self, input: &PolicyInput) -> Result<bool, String> {
        let json = serde_json::to_string(input).map_err(|error| error.to_string())?;
        let mut engine = self.engine.lock().unwrap_or_else(PoisonError::into_inner);
        engine
            .set_input_json(&json)
            .map_err(|error| error.to_string())?;
        engine
            .eval_bool_query(ALLOW_QUERY.to_owned(), false)
            .map_err(|error| error.to_string())
    }
}
