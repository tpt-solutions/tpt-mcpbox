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

use clap::{CommandFactory, Parser, Subcommand};
use tpt_mcpbox_config::load;
use tpt_mcpbox_config::model::{LogLevel, LoggingConfig};
use tpt_mcpbox_config::secrets::{self, SecretStore, SourceKind};
use tpt_mcpbox_config::validate::{self, Severity, ValidationMode};

mod init;
mod serve;
mod tools;

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
    /// List the configured tools, or call one for debugging.
    Tools {
        /// Tools subcommand to run.
        #[command(subcommand)]
        command: ToolsCommand,
    },
    /// Policy commands.
    Policy {
        /// Policy subcommand to run.
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Serve the configured tools and upstreams on stdio.
    Run {
        /// Configuration file; discovered from the working directory when
        /// omitted.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Scaffold a starter configuration, or a new project with `init tool`.
    Init {
        /// Configuration file to write when no subcommand is given.
        #[arg(short, long, value_name = "PATH", default_value = "tpt-mcpbox.yaml")]
        output: PathBuf,
        /// Overwrite the file if it already exists.
        #[arg(long)]
        force: bool,
        /// What to scaffold; omit to write a starter configuration.
        #[command(subcommand)]
        command: Option<InitCommand>,
    },
    /// Print a shell completion script to stdout.
    Completions {
        /// Shell to generate the script for.
        #[arg(value_name = "SHELL")]
        shell: clap_complete::Shell,
    },
    /// Write man pages for the command and its subcommands.
    Manpage {
        /// Directory to write the `.1` files into; created when missing.
        #[arg(value_name = "DIR")]
        dir: PathBuf,
    },
    /// Print the version and exit.
    Version,
}

#[derive(Debug, Subcommand)]
enum InitCommand {
    /// Create a tool component project that builds against the guest SDK.
    Tool {
        /// Directory to create; it must be empty or absent.
        #[arg(value_name = "DIR")]
        dir: PathBuf,
        /// Path to the `tpt-mcpbox-sdk` crate. Written as a path dependency,
        /// since the SDK is not published yet.
        #[arg(long, value_name = "PATH")]
        sdk_path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ToolsCommand {
    /// Print each tool the configuration exposes.
    Ls {
        /// Configuration file; discovered from the working directory when
        /// omitted.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Call one tool and print its result. Goes through the same policy,
    /// limits and audit log as `run`, so it is refused while a hub is running
    /// against the same audit log.
    Call {
        /// Exposed tool name, as shown by `tools ls`.
        #[arg(value_name = "NAME")]
        name: String,
        /// Arguments as a JSON object, e.g. '{"path":"notes.md"}'.
        #[arg(short, long, value_name = "JSON")]
        args: Option<String>,
        /// Configuration file; discovered from the working directory when
        /// omitted.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Evaluate one request against the configured policy and explain the
    /// decision. Exits 0 when allowed and 1 when denied.
    Test {
        /// JSON file holding a policy input: `method`, `tool`, `arguments`,
        /// and optionally `caller`, `host`, `fs_path` and `uris`.
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Configuration to read the policy from; discovered from the working
        /// directory when omitted.
        #[arg(short, long, value_name = "CONFIG")]
        config: Option<PathBuf>,
    },
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
        Command::Init {
            command: Some(InitCommand::Tool { dir, sdk_path }),
            ..
        } => init_tool_command(&dir, &sdk_path),
        Command::Init {
            output,
            force,
            command: None,
        } => init_config_command(&output, force),
        Command::Audit {
            command: AuditCommand::Verify { log, config },
        } => audit_verify_command(log.as_deref(), config.as_deref()),
        Command::Policy {
            command: PolicyCommand::Test { input, config },
        } => policy_test_command(&input, config.as_deref()),
        Command::Tools {
            command: ToolsCommand::Ls { config },
        } => tools::list_command(config.as_deref()),
        Command::Tools {
            command: ToolsCommand::Call { name, args, config },
        } => tools::call_command(config.as_deref(), &name, args.as_deref()),
        Command::Completions { shell } => {
            let mut command = Cli::command();
            clap_complete::generate(shell, &mut command, "tpt-mcpbox", &mut std::io::stdout());
            Ok(ExitCode::SUCCESS)
        }
        Command::Manpage { dir } => manpage_command(&dir),
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

/// Write a starter configuration and say what to do next.
fn init_config_command(output: &Path, force: bool) -> Result<ExitCode, String> {
    let path = init::scaffold_config(output, force)?;
    println!("created {}", path.display());
    println!(
        "check it with: tpt-mcpbox validate --config {}",
        path.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// Scaffold a tool component project and list the files written.
fn init_tool_command(dir: &Path, sdk_path: &Path) -> Result<ExitCode, String> {
    let written = init::scaffold_tool(dir, sdk_path)?;
    for path in &written {
        println!("created {}", path.display());
    }
    println!(
        "build it with: cd {} && cargo build --release --target wasm32-wasip2",
        dir.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// Start the hub. Stdout carries the protocol, so logs go to stderr only.
fn run_command(config_path: Option<&Path>) -> Result<ExitCode, String> {
    let cwd = std::env::current_dir()
        .map_err(|error| format!("cannot read the working directory: {error}"))?;
    let (path, _) = load::discover(config_path, &|name| std::env::var(name).ok(), &cwd)
        .map_err(|error| error.to_string())?;
    let loaded = load::load_file(&path).map_err(|error| error.to_string())?;
    init_logging(&loaded.config.logging);
    let base = path.parent().unwrap_or(Path::new("."));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the async runtime: {error}"))?;
    runtime.block_on(async {
        let hub = serve::build_router(&loaded.config, base).await?;
        serve::serve(
            hub,
            loaded.config.server.clone(),
            loaded.config.metrics.clone(),
        )
        .await
    })?;
    Ok(ExitCode::SUCCESS)
}

/// Write `tpt-mcpbox.1` and one page per subcommand, e.g. `tpt-mcpbox-tools-ls.1`.
fn manpage_command(dir: &Path) -> Result<ExitCode, String> {
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    let mut written = 0_usize;
    // Each page is named after its full command path, so `ls` under `tools`
    // does not collide with any other `ls`.
    let mut pending = vec![("tpt-mcpbox".to_owned(), Cli::command())];
    while let Some((name, command)) = pending.pop() {
        let mut buffer = Vec::new();
        clap_mangen::Man::new(command.clone().bin_name(name.clone()))
            .render(&mut buffer)
            .map_err(|error| format!("cannot render {name}: {error}"))?;
        let path = dir.join(format!("{name}.1"));
        std::fs::write(&path, buffer)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        println!("created {}", path.display());
        written += 1;
        for sub in command.get_subcommands() {
            pending.push((format!("{name}-{}", sub.get_name()), sub.clone()));
        }
    }
    println!("wrote {written} man page(s)");
    Ok(ExitCode::SUCCESS)
}

/// Install the stderr log subscriber from the `logging` section.
///
/// `RUST_LOG` overrides the configured level for a single run. JSON output
/// (the default) carries the enclosing request span, so each log line names the
/// tool, caller, outcome and duration of the call it belongs to.
fn init_logging(settings: &LoggingConfig) {
    let level = match settings.level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter);
    if settings.json {
        builder
            .json()
            .with_current_span(settings.spans)
            .with_span_list(settings.spans)
            .init();
    } else {
        builder.init();
    }
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

/// Evaluate one policy input and print the decision as JSON.
///
/// Exits 0 when the call would be allowed and 1 when denied, so a script can
/// gate on the result. Dry-run mode reports `effect: allow` with a
/// `would_be` of `deny`; that is printed as-is, not rewritten.
fn policy_test_command(input: &Path, config: Option<&Path>) -> Result<ExitCode, String> {
    let cwd = std::env::current_dir()
        .map_err(|error| format!("cannot read the working directory: {error}"))?;
    let (config_path, _) = load::discover(config, &|name| std::env::var(name).ok(), &cwd)
        .map_err(|error| error.to_string())?;
    let loaded = load::load_file(&config_path).map_err(|error| error.to_string())?;
    let policy = tpt_mcpbox_policy::Policy::from_config(&loaded.config.policy)
        .map_err(|error| format!("policy: {error}"))?;

    let text = std::fs::read_to_string(input)
        .map_err(|error| format!("cannot read {}: {error}", input.display()))?;
    let request: tpt_mcpbox_policy::PolicyInput = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not a policy input: {error}", input.display()))?;

    let decision = policy.evaluate(&request);
    let rendered = serde_json::to_string_pretty(&decision)
        .map_err(|error| format!("cannot render the decision: {error}"))?;
    println!("{rendered}");

    Ok(if decision.is_allowed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
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

    fn policy_fixture(dir: &Path) -> PathBuf {
        let config = dir.join("tpt-mcpbox.yaml");
        std::fs::write(
            &config,
            r#"version: 1
server:
  transports: [stdio]
policy:
  default: deny
  rules:
    - id: allow-read
      effect: allow
      tool: read_file
"#,
        )
        .unwrap();
        config
    }

    #[test]
    fn policy_test_exits_zero_when_allowed_and_one_when_denied() {
        let dir = tempfile::tempdir().unwrap();
        let config = policy_fixture(dir.path());
        let allowed = dir.path().join("allowed.json");
        std::fs::write(&allowed, r#"{"method":"tools/call","tool":"read_file"}"#).unwrap();
        let denied = dir.path().join("denied.json");
        std::fs::write(&denied, r#"{"method":"tools/call","tool":"rm_rf"}"#).unwrap();

        assert_eq!(
            policy_test_command(&allowed, Some(&config)).unwrap(),
            ExitCode::SUCCESS
        );
        assert_eq!(
            policy_test_command(&denied, Some(&config)).unwrap(),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn policy_test_rejects_input_that_is_not_a_policy_input() {
        let dir = tempfile::tempdir().unwrap();
        let config = policy_fixture(dir.path());
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, r#"{"method": 7}"#).unwrap();

        let err = policy_test_command(&bad, Some(&config)).unwrap_err();
        assert!(err.contains("not a policy input"), "{err}");
    }

    #[test]
    fn manpage_writes_a_page_per_command_path() {
        let dir = tempfile::tempdir().unwrap();
        assert!(manpage_command(dir.path()).is_ok());
        assert!(dir.path().join("tpt-mcpbox.1").is_file());
        assert!(dir.path().join("tpt-mcpbox-tools-call.1").is_file());
        assert!(dir.path().join("tpt-mcpbox-audit-verify.1").is_file());
    }

    #[test]
    fn audit_verify_reports_a_missing_log_as_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = audit_verify_command(Some(&dir.path().join("none.jsonl")), None).unwrap_err();
        assert!(err.contains("no audit log"));
    }
}

#[cfg(test)]
mod sample_config_tests {
    use std::path::Path;

    #[test]
    fn the_sample_configuration_passes_serve_validation() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/tpt-mcpbox.yaml");
        let loaded = tpt_mcpbox_config::load::load_file(&path).expect("sample loads");
        let report = tpt_mcpbox_config::validate::validate(
            &loaded.config,
            tpt_mcpbox_config::validate::ValidationMode::Serve,
        );
        assert!(report.is_ok(), "{report}");
    }
}
