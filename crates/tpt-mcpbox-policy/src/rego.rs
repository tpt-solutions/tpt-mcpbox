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
//!
//! The module sees the same normalised host, path and URIs as the DSL, so a
//! check written against `api.github.com` or `secret/` cannot be stepped around
//! with `API.GitHub.com.` or `x/../secret/`. A request whose host, path or URI
//! cannot be normalised is refused before the module runs.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use crate::decision::PolicyInput;
use crate::error::PolicyError;
use crate::normalize::{normalize_host, normalize_path, normalize_uri};

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
        register_normalisers(&mut engine).map_err(|error| PolicyError::RegoCompile {
            module: name.to_owned(),
            message: error.to_string(),
        })?;
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
        let input = normalized(input)?;
        let json = serde_json::to_string(&input).map_err(|error| error.to_string())?;
        let mut engine = self.engine.lock().unwrap_or_else(PoisonError::into_inner);
        engine
            .set_input_json(&json)
            .map_err(|error| error.to_string())?;
        engine
            .eval_bool_query(ALLOW_QUERY.to_owned(), false)
            .map_err(|error| error.to_string())
    }
}

/// Registers the builtins a module can call to normalise a raw value the way
/// the DSL normalises fields: `tpt.normalize_host`, `tpt.normalize_path` and
/// `tpt.normalize_uri`. Arguments are untrusted, so a module that compares one
/// should normalise it first.
///
/// A value that cannot be normalised is undefined rather than an error, so an
/// expression comparing it is false and an allow rule built on it does not
/// fire. Refusals stay fail-closed.
fn register_normalisers(engine: &mut regorus::Engine) -> anyhow::Result<()> {
    engine.add_extension(
        "tpt.normalize_host".to_owned(),
        1,
        Box::new(
            |args: Vec<regorus::Value>| -> anyhow::Result<regorus::Value> {
                Ok(normalise_argument(&args, normalize_host))
            },
        ),
    )?;
    engine.add_extension(
        "tpt.normalize_path".to_owned(),
        1,
        Box::new(
            |args: Vec<regorus::Value>| -> anyhow::Result<regorus::Value> {
                Ok(normalise_argument(&args, normalize_path))
            },
        ),
    )?;
    engine.add_extension(
        "tpt.normalize_uri".to_owned(),
        1,
        Box::new(
            |args: Vec<regorus::Value>| -> anyhow::Result<regorus::Value> {
                Ok(normalise_argument(&args, normalize_uri))
            },
        ),
    )?;
    Ok(())
}

/// The normalised first argument, or undefined when it is not a string or
/// cannot be normalised.
fn normalise_argument(
    args: &[regorus::Value],
    normalise: fn(&str) -> Option<String>,
) -> regorus::Value {
    args.first()
        .and_then(|arg| arg.as_string().ok())
        .and_then(|text| normalise(text))
        .map_or(regorus::Value::Undefined, regorus::Value::from)
}

/// The input with its host, path and URIs normalised as the DSL sees them.
///
/// The offending value is left out of the error, because the reason can reach
/// logs and the audit trail.
fn normalized(input: &PolicyInput) -> Result<PolicyInput, String> {
    let refuse = |field: &str| format!("the request's {field} cannot be normalised");
    let host = match input.host.as_deref() {
        Some(host) => Some(normalize_host(host).ok_or_else(|| refuse("host"))?),
        None => None,
    };
    let fs_path = match input.fs_path.as_deref() {
        Some(path) => Some(normalize_path(path).ok_or_else(|| refuse("path"))?),
        None => None,
    };
    let uris = input
        .uris
        .iter()
        .map(|uri| normalize_uri(uri).ok_or_else(|| refuse("URI")))
        .collect::<Result<_, _>>()?;
    Ok(PolicyInput {
        host,
        fs_path,
        uris,
        ..input.clone()
    })
}
