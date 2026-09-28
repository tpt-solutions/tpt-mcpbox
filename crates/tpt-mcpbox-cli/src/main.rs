// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! `tpt-mcpbox` command-line entry point.
//!
//! Implemented incrementally per Phase 10: `run`, `validate`, `schema`,
//! `policy test`, `tools ls|call`, `pull`, `audit verify`, `init [tool]`.
//!
//! Writing to stdout is this binary's job, so the workspace-wide
//! `print_stdout` lint is relaxed here only.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]
#![warn(missing_docs, missing_debug_implementations)]

/// Binary version string, also reported in the `initialize` handshake.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> std::process::ExitCode {
    println!("tpt-mcpbox {VERSION}");
    std::process::ExitCode::SUCCESS
}
