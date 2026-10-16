// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Errors raised while compiling a policy.

use std::path::PathBuf;

/// Why a policy could not be compiled.
///
/// Compilation fails closed: a policy that cannot be fully understood is never
/// partially applied.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// Two rules share an id. Ids appear in audit entries, so they must be
    /// unambiguous.
    #[error("duplicate policy rule id `{0}`")]
    DuplicateRuleId(String),

    /// A `tool`, `caller`, `hosts`, `paths` or `uris` glob does not compile.
    #[error("rule `{rule}`: invalid glob `{pattern}`: {source}")]
    InvalidGlob {
        /// Id of the rule holding the glob.
        rule: String,
        /// The offending pattern as written.
        pattern: String,
        /// The underlying parse error.
        #[source]
        source: globset::Error,
    },

    /// `policy.rego` is set on a DSL-only engine, which would ignore it. Build a
    /// [`crate::Policy`] instead, which evaluates both.
    #[error(
        "`policy.rego` is set; build a `Policy`, not a DSL-only `Engine`, so the module is evaluated"
    )]
    RegoInDslOnly,

    /// The Rego module could not be read.
    #[error("cannot read Rego module {}: {source}", path.display())]
    RegoRead {
        /// Path that was read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The Rego module does not parse or compile.
    #[error("Rego module `{module}` does not compile: {message}")]
    RegoCompile {
        /// Module name, normally its path.
        module: String,
        /// Compiler message.
        message: String,
    },
}
