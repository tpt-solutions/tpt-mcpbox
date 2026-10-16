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

mod serve;

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
    /// Audit log commands.
    Audit {
        /// Audit subcommand to run.
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Serve the configured tools and upstreams on stdio.
    Run {
        /// Configuration file; discovered from the working directory when
        /// omitted.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Print the version and exit.
    Version,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Check the hash chain of an audit log and report the first break.
    Verify {
        /// Log file to check. Defaults to `audit.path` from the configuration.
        #[arg(value_name = "PATH")]
        log: Option<PathBuf>,
        /// Configuration to read `audit.path` from when PATH is omitted;
        /// discovered from the working directory when omitted.
        #[arg(short, long, value_name = "CONFIG")]
        config: Option<PathBuf>,
    },
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
        Command::Run { config } => run_command(config.as_deref()),
        Command::Audit {
            command: AuditCommand::Verify { log, config },
        } => audit_verify_command(log.as_deref(), config.as_deref()),
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

/// Start the hub. Stdout carries the protocol, so logs go to stderr only.
fn run_command(config_path: Option<&Path>) -> Result<ExitCode, String> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cwd = std::env::current_dir()
        .map_err(|error| format!("cannot read the working directory: {error}"))?;
    let (path, _) = load::discover(config_path, &|name| std::env::var(name).ok(), &cwd)
        .map_err(|error| error.to_string())?;
    let loaded = load::load_file(&path).map_err(|error| error.to_string())?;
    let base = path.parent().unwrap_or(Path::new("."));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the async runtime: {error}"))?;
    runtime.block_on(async {
        let hub = serve::build_router(&loaded.config, base).await?;
        serve::serve(hub, loaded.config.server.clone()).await
    })?;
    Ok(ExitCode::SUCCESS)
}

/// Verify the audit chain and print its length and head hash.
///
/// A broken chain is an error, so the exit code is non-zero and scripts can
/// depend on it.
fn audit_verify_command(log: Option<&Path>, config: Option<&Path>) -> Result<ExitCode, String> {
    let path = match log {
        Some(path) => path.to_path_buf(),
        None => {
            let cwd = std::env::current_dir()
                .map_err(|error| format!("cannot read the working directory: {error}"))?;
            let (config_path, _) = load::discover(config, &|name| std::env::var(name).ok(), &cwd)
                .map_err(|error| error.to_string())?;
            let loaded = load::load_file(&config_path).map_err(|error| error.to_string())?;
            // Relative audit paths are relative to the configuration file.
            let base = config_path.parent().unwrap_or(Path::new("."));
            base.join(&loaded.config.audit.path)
        }
    };

    // An absent file would verify as an empty log, which is not the same thing
    // as "nothing was tampered with": the log is missing.
    if !path.exists() {
        return Err(format!("no audit log at {}", path.display()));
    }

    let report = tpt_mcpbox_audit::verify(&path).map_err(|error| error.to_string())?;
    println!(
        "audit log {}: {} entries verified, head {}",
        path.display(),
        report.entries,
        report.head
    );
    Ok(ExitCode::SUCCESS)
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

    #[test]
    fn audit_verify_accepts_an_intact_log_and_rejects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = tpt_mcpbox_audit::AuditLog::open(&path).unwrap();
        log.append("tool_call", serde_json::json!({ "tool": "echo" }))
            .unwrap();
        drop(log);

        assert!(audit_verify_command(Some(&path), None).is_ok());

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("echo", "rm")).unwrap();
        assert!(audit_verify_command(Some(&path), None).is_err());
    }

    #[test]
    fn audit_verify_reports_a_missing_log_as_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = audit_verify_command(Some(&dir.path().join("none.jsonl")), None).unwrap_err();
        assert!(err.contains("no audit log"));
    }
}
