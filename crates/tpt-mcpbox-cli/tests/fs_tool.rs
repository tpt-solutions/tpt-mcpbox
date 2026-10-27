// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! End-to-end check of the example filesystem tool through the real binary:
//! `tools call` runs the same policy, sandbox and audit path as `run`.
//!
//! The tool is a guest crate outside the host workspace, so this test builds it
//! for `wasm32-wasip2` itself. When that target is not installed the test says
//! so and passes without checking anything, rather than failing a host that
//! cannot build the guest.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const WASM_TARGET: &str = "wasm32-wasip2";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Builds the fs tool and returns the path of the component, or `None` when the
/// guest target is not installed.
fn build_fs_tool() -> Option<PathBuf> {
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .ok()?;
    if !String::from_utf8_lossy(&installed.stdout)
        .lines()
        .any(|line| line.trim() == WASM_TARGET)
    {
        eprintln!("skipping fs tool test: the {WASM_TARGET} target is not installed");
        return None;
    }

    let manifest = repo_root().join("tools/tpt-mcpbox-tool-fs/Cargo.toml");
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--release",
            "--target",
            WASM_TARGET,
            "--manifest-path",
        ])
        .arg(&manifest)
        .status()
        .expect("cargo runs");
    assert!(status.success(), "the fs tool must build for {WASM_TARGET}");

    let component = repo_root()
        .join("tools/tpt-mcpbox-tool-fs/target")
        .join(WASM_TARGET)
        .join("release/tpt_mcpbox_tool_fs.wasm");
    assert!(component.is_file(), "missing {}", component.display());
    Some(component)
}

/// A forward-slash path, safe to put in a double-quoted YAML string on Windows.
fn yaml_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

/// A workspace with one readable file and a writable output directory, plus a
/// configuration granting exactly that and the given policy rules.
fn fixture(component: &Path, rules: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir_all(dir.path().join("workspace/output")).expect("mkdir");
    std::fs::write(dir.path().join("workspace/notes.md"), "hello from notes").expect("write");

    let config = dir.path().join("tpt-mcpbox.yaml");
    std::fs::write(
        &config,
        format!(
            r#"version: 1
server:
  transports: [stdio]
tools:
  - name: local_files
    wasm_path: "{wasm}"
    capabilities:
      filesystem:
        read: ["./workspace/**"]
        write: ["./workspace/output/**"]
      memory_limit: "64MB"
      time_limit: "10s"
policy:
  default: deny
  rules:
{rules}
audit:
  enabled: true
  path: audit.log
"#,
            wasm = yaml_path(component),
        ),
    )
    .expect("config");
    (dir, config)
}

const ALLOW_ALL: &str = "    - id: allow-read
      effect: allow
      tool: read_file
    - id: allow-write
      effect: allow
      tool: write_file";

const READ_ONLY: &str = "    - id: allow-read
      effect: allow
      tool: read_file";

fn call(config: &Path, tool: &str, args: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tpt-mcpbox"))
        .args(["tools", "call", tool, "--args", args, "--config"])
        .arg(config)
        .output()
        .expect("tpt-mcpbox runs")
}

#[test]
fn the_fs_tool_reads_writes_and_refuses_as_configured() {
    let Some(component) = build_fs_tool() else {
        return;
    };

    let (dir, config) = fixture(&component, ALLOW_ALL);

    let read = call(&config, "read_file", r#"{"path":"notes.md"}"#);
    assert!(
        read.status.success(),
        "{}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert!(String::from_utf8_lossy(&read.stdout).contains("hello from notes"));

    let write = call(
        &config,
        "write_file",
        r#"{"path":"a.md","content":"written"}"#,
    );
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("workspace/output/a.md")).expect("written"),
        "written"
    );

    let escape = call(
        &config,
        "write_file",
        r#"{"path":"../escape.md","content":"x"}"#,
    );
    assert!(!escape.status.success());
    assert!(String::from_utf8_lossy(&escape.stderr).contains("must be relative"));
    assert!(!dir.path().join("workspace/escape.md").exists());
    assert!(!dir.path().join("escape.md").exists());
}

#[test]
fn a_policy_without_a_write_rule_refuses_the_write() {
    let Some(component) = build_fs_tool() else {
        return;
    };

    let (dir, config) = fixture(&component, READ_ONLY);

    let write = call(&config, "write_file", r#"{"path":"b.md","content":"x"}"#);
    assert!(!write.status.success());
    assert!(String::from_utf8_lossy(&write.stderr).contains("denied by policy"));
    assert!(!dir.path().join("workspace/output/b.md").exists());

    let verify = Command::new(env!("CARGO_BIN_EXE_tpt-mcpbox"))
        .args(["audit", "verify"])
        .arg(dir.path().join("audit.log"))
        .output()
        .expect("audit verify runs");
    assert!(verify.status.success(), "the audit chain must verify");
}
