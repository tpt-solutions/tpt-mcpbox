// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Errors raised while loading or running a tool.

use std::path::PathBuf;

/// Why a tool could not be loaded, or why one invocation failed.
///
/// The variants separate faults from refusals. A [`ToolError::ToolFailed`] means
/// the tool ran and reported an error, so its instance is still good. A trap,
/// timeout, cancellation or host panic means the instance is discarded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ToolError {
    /// The `.wasm` file could not be read.
    #[error("cannot read tool module {}: {source}", path.display())]
    Io {
        /// Path that was read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The module's signature is missing or does not verify under the configured
    /// public key. The module is never compiled.
    #[error("tool `{tool}`: module signature is not valid: {reason}")]
    SignatureInvalid {
        /// Tool name.
        tool: String,
        /// What failed: the signature file, its format, or the check itself.
        reason: String,
    },
    /// The module's SHA-256 does not match the pin in configuration. The module
    /// is never compiled.
    #[error("tool `{tool}`: module digest {actual} does not match the pinned sha256 {expected}")]
    IntegrityMismatch {
        /// Tool name.
        tool: String,
        /// Digest the configuration pins.
        expected: String,
        /// Digest of the bytes read.
        actual: String,
    },

    /// The configuration cannot be turned into a sandbox or a module source.
    #[error("tool `{tool}`: {message}")]
    InvalidConfig {
        /// Tool name.
        tool: String,
        /// What is wrong and how to fix it.
        message: String,
    },

    /// The configuration names a module source this build cannot load yet.
    #[error("tool `{tool}`: {message}")]
    Unsupported {
        /// Tool name.
        tool: String,
        /// Explanation.
        message: String,
    },

    /// The bytes are not a valid WebAssembly component, or they do not
    /// implement the `tpt:mcpbox/tool` world.
    #[error("tool `{tool}` cannot be compiled or instantiated: {message}")]
    Compile {
        /// Tool name.
        tool: String,
        /// Compiler or linker message.
        message: String,
    },

    /// Every instance of the tool is busy and the concurrency cap is reached.
    #[error("tool `{tool}` is at its concurrency limit of {limit}; retry later")]
    Overloaded {
        /// Tool name.
        tool: String,
        /// The configured cap.
        limit: usize,
    },

    /// The argument payload is larger than the tool's limit.
    #[error("tool `{tool}`: arguments are {size} bytes, over the {limit}-byte limit")]
    ArgumentsTooLarge {
        /// Tool name.
        tool: String,
        /// Size received.
        size: usize,
        /// Configured limit.
        limit: usize,
    },

    /// The result payload is larger than the tool's limit.
    #[error("tool `{tool}`: result is {size} bytes, over the {limit}-byte limit")]
    ResultTooLarge {
        /// Tool name.
        tool: String,
        /// Size produced.
        size: usize,
        /// Configured limit.
        limit: usize,
    },

    /// The invocation ran past its time limit and was interrupted.
    #[error("tool `{tool}` exceeded its time limit of {limit:?}")]
    TimedOut {
        /// Tool name.
        tool: String,
        /// Configured limit.
        limit: std::time::Duration,
    },

    /// The caller cancelled the invocation.
    #[error("tool `{tool}` was cancelled")]
    Cancelled {
        /// Tool name.
        tool: String,
    },

    /// The guest trapped: it panicked, ran out of memory, or hit a sandbox
    /// boundary the host refused. The instance is discarded.
    #[error("tool `{tool}` trapped: {message}")]
    Trapped {
        /// Tool name.
        tool: String,
        /// First line of the trap message.
        message: String,
    },

    /// The guest returned an error result. The instance is kept.
    #[error("tool `{tool}` reported an error: {message}")]
    ToolFailed {
        /// Tool name.
        tool: String,
        /// The message the tool returned.
        message: String,
    },

    /// The host panicked while running the tool. This is a bug in the runtime,
    /// reported without its payload so that nothing from the guest leaks.
    #[error("tool `{tool}` caused an internal runtime fault")]
    HostPanic {
        /// Tool name.
        tool: String,
    },

    /// The startup self-test found the sandbox exposing something it should not.
    #[error("sandbox self-test failed: {0}")]
    SelfTestFailed(String),
}
