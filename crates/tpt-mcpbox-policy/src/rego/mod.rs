// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The embedded Rego evaluator: an in-house interpreter for a documented subset
//! of Rego v1 (see [`parse`] for the subset). It replaces the `regorus` engine,
//! so the policy engine carries no third-party Rego implementation.
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
//! as a refusal, and anything outside the subset is refused when the module
//! loads. A broken module therefore fails closed.
//!
//! The module sees the same normalised host, path and URIs as the DSL, so a
//! check written against `api.github.com` or `secret/` cannot be stepped around
//! with `API.GitHub.com.` or `x/../secret/`. A request whose host, path or URI
//! cannot be normalised is refused before the module runs.

mod builtins;
mod eval;
mod lex;
mod parse;

use std::path::Path;

use crate::decision::PolicyInput;
use crate::error::PolicyError;
use crate::normalize::{normalize_host, normalize_path, normalize_uri};

/// A compiled Rego module, ready to evaluate.
pub(crate) struct RegoEngine {
    module: parse::Module,
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
        let module = parse::compile(&source).map_err(|message| PolicyError::RegoCompile {
            module: name.to_owned(),
            message,
        })?;
        Ok(Self { module })
    }

    /// Ask the module whether `input` is allowed.
    ///
    /// Returns `Err` with a message when evaluation fails. Callers must treat
    /// that as a refusal.
    pub(crate) fn allows(&self, input: &PolicyInput) -> Result<bool, String> {
        let input = normalized(input)?;
        let value = serde_json::to_value(&input).map_err(|error| error.to_string())?;
        eval::allows(&self.module, &value)
    }
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

#[cfg(test)]
mod tests {
    use super::RegoEngine;
    use crate::decision::PolicyInput;

    /// Every prefix of a valid module is compiled and, if it compiles, evaluated.
    /// None may panic: truncated text is what a broken edit looks like.
    #[test]
    fn truncated_modules_never_panic() {
        const MODULE: &str = "package tpt.mcpbox\n\ndefault allow := false\n\nhelper if {\n    input.uris[_] == \"file:///a\"\n}\n\nallow if {\n    some u in input.uris\n    not startswith(u, \"x\")\n    count(input.arguments) > 0\n    helper\n}\n";
        let input = PolicyInput {
            tool: Some("t".to_owned()),
            uris: vec!["file:///a".to_owned()],
            arguments: serde_json::json!({"k": [1, "two"]}),
            ..PolicyInput::default()
        };
        for end in 0..=MODULE.len() {
            if let Ok(engine) = RegoEngine::from_source("prefix.rego", MODULE[..end].to_owned()) {
                let _ = engine.allows(&input);
            }
        }
    }
}
