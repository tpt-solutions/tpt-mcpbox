// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Errors raised while compiling a policy.

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

    /// A `tool`, `hosts` or `paths` glob does not compile.
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

    /// `policy.rego` is set, but the Rego evaluator is not built yet.
    #[error("`policy.rego` is set, but the Rego evaluator is not implemented yet")]
    RegoNotSupported,
}
