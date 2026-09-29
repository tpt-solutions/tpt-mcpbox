// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! `tpt-mcpbox` command-line entry point.
//!
//! Phase 2 ships `validate` and `schema`; the remaining commands from Phase 10
//! (`run`, `policy test`, `tools`, `pull`, `audit verify`, `init`) are added as
//! the corresponding crates land.
//!
//! Writing to stdout is this binary's job, so the workspace-wide
//! `print_stdout` lint is relaxed here only.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]
#![warn(missing_docs, missing_debug_implementations)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tpt_mcpbox_config::load;
use tpt_mcpbox_config::secrets::{self, SecretStore, SourceKind};
use tpt_mcpbox_config::validate::{self, Severity, ValidationMode};

/// Binary version string, also reported in the `initialize` handshake.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Secure MCP hub: policy engine, Wasm runtime and upstream proxy.
#[derive(Debug, Parser)]
#[command(
    name = "tpt-mcpbox",
    version,
    about = "Local-first, zero-trust MCP proxy and WebAssembly tool runtime",
    long_about = None
)]
struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Load a configuration file and report every problem with it.
    Validate {
        /// Configuration file; discovered from the working directory when
        /// omitted.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Advisory mode: report warnings without failing the run.
        #[arg(long)]
        warn_only: bool,
        /// Do not check referenced secrets or paths on disk.
        #[arg(long)]
        offline: bool,
    },
    /// Print the JSON Schema for `tpt-mcpbox.yaml`.
    Schema {
        /// Also write the schema to this file.
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Print the version and exit.
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let outcome: Result<ExitCode, String> = match cli.command {
        Command::Validate {
            config,
            warn_only,
            offline,
        } => validate_command(config.as_deref(), warn_only, offline),
        Command::Schema { output } => schema_command(output.as_deref()),
        Command::Version => {
            println!("tpt-mcpbox {VERSION}");
            Ok(ExitCode::SUCCESS)
        }
    };

    match outcome {
        Ok(code) => code,
        Err(message) => {
            eprintln!("tpt-mcpbox: {message}");
            ExitCode::FAILURE
        }
    }
}

fn validate_command(
    config_path: Option<&Path>,
    warn_only: bool,
    offline: bool,
) -> Result<ExitCode, String> {
    let cwd = std::env::current_dir()
        .map_err(|error| format!("cannot read the working directory: {error}"))?;
    let (path, source) = load::discover(config_path, &|name| std::env::var(name).ok(), &cwd)
        .map_err(|error| error.to_string())?;

    let loaded = load::load_file(&path).map_err(|error| error.to_string())?;

    // Audit mode is advisory: it exists for editors and CI, not for the serve
    // path, where `policy.default: allow` must be an error.
    let mode = if warn_only || offline {
        ValidationMode::Audit
    } else {
        ValidationMode::Serve
    };

    if !offline {
        report_environment(&loaded, &path);
    }

    println!(
        "configuration: {} ({}), {} tool(s), {} upstream(s)",
        path.display(),
        source.label(),
        loaded.config.tools.len(),
        loaded.config.upstreams.len()
    );
    if let Some(overlay) = &loaded.overlay {
        println!("merged overlay: {}", overlay.display());
    }

    let report = validate::validate(&loaded.config, mode);
    println!("{report}");

    if report.is_ok() || warn_only {
        Ok(ExitCode::SUCCESS)
    } else {
        Err(format!(
            "{} error(s) must be fixed before the hub can serve traffic",
            report.of_severity(Severity::Error).len()
        ))
    }
}

/// Print whether the referenced secrets are actually available.
///
/// Values are never printed: only names and whether they resolved.
fn report_environment(loaded: &load::LoadedConfig, path: &Path) {
    let dotenv = path.with_file_name(".env");
    let mut names: Vec<&str> =
        loaded
            .config
            .tools
            .iter()
            .flat_map(|tool| tool.secrets.iter().map(|binding| binding.env.as_str()))
            .chain(
                loaded.config.upstreams.iter().flat_map(|upstream| {
                    upstream.secrets.iter().map(|binding| binding.env.as_str())
                }),
            )
            .collect();
    names.sort_unstable();
    names.dedup();

    if names.is_empty() {
        return;
    }

    let file_values = secrets::read_dotenv(&dotenv);
    let mut store = SecretStore::new();
    for name in names {
        let resolved = std::env::var(name)
            .ok()
            .or_else(|| file_values.get(name).cloned());
        match resolved {
            Some(value) => {
                let source = if std::env::var(name).is_ok() {
                    SourceKind::ProcessEnv
                } else {
                    SourceKind::DotEnv
                };
                store.insert(name, value, source);
            }
            None => println!(
                "warning: secret `{name}` is referenced but not set (also checked {})",
                dotenv.display()
            ),
        }
    }
    if !store.is_empty() {
        println!("resolved secret(s): {}", store.names().join(", "));
    }
}

fn schema_command(output: Option<&Path>) -> Result<ExitCode, String> {
    let rendered = tpt_mcpbox_config::schema::json_schema_string();
    match output {
        Some(path) => std::fs::write(path, format!("{rendered}\n"))
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?,
        None => println!("{rendered}"),
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn schema_renders_to_stdout_sized_output() {
        assert!(tpt_mcpbox_config::schema::json_schema_string().len() > 100);
    }
}
