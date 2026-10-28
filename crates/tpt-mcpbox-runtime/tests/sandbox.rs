// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

#![allow(clippy::field_reassign_with_default)]

//! End-to-end sandbox tests: real guest components, run through the host.
//!
//! The fixture in `tests/guest` is built for `wasm32-wasip2` on first use, which
//! needs that target installed (`rustup target add wasm32-wasip2`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tpt_mcpbox_config::{Capabilities, Limits, RateLimit, SecretStore, ToolConfig};
use tpt_mcpbox_runtime::{CancelToken, LoadedTool, Runtime, ToolError};

const GUEST_PACKAGE: &str = "tpt_mcpbox_test_guest";

/// Build the fixture once per test binary and return the component's path.
fn guest_path() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            let manifest = crate_dir.join("tests/guest/Cargo.toml");
            // A separate target directory, so the nested build never waits on the
            // outer cargo's lock.
            let target = crate_dir.join("../../target/guest");
            let status = Command::new(env!("CARGO"))
                .args([
                    "build",
                    "--release",
                    "--target",
                    "wasm32-wasip2",
                    "--manifest-path",
                ])
                .arg(&manifest)
                .env("CARGO_TARGET_DIR", &target)
                .status()
                .expect("cargo runs");
            assert!(status.success(), "building the guest fixture failed");
            target.join(format!("wasm32-wasip2/release/{GUEST_PACKAGE}.wasm"))
        })
        .clone()
}

/// One shared engine: each engine reserves a pooled allocation up front.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().expect("runtime builds"))
}

fn config(name: &str) -> ToolConfig {
    ToolConfig {
        name: name.to_owned(),
        description: None,
        wasm_path: Some(guest_path()),
        oci_ref: None,
        sha256: None,
        minisign_key: None,
        enabled: true,
        capabilities: Capabilities::default(),
        secrets: Vec::new(),
        limits: Limits::default(),
        rate_limit: RateLimit::default(),
    }
}

fn load(config: &ToolConfig, base: &Path) -> LoadedTool {
    runtime()
        .load_tool(config, &SecretStore::new(), base)
        .expect("tool loads")
}

fn call(tool: &LoadedTool, name: &str, args: &str) -> Result<String, ToolError> {
    tool.call(name, args, &CancelToken::new())
}

/// The test binary itself: a file that always exists and is never granted.
fn an_ungranted_file() -> String {
    std::env::current_exe()
        .expect("exe path")
        .display()
        .to_string()
}

fn json_string(value: &str) -> String {
    serde_json::Value::String(value.to_owned()).to_string()
}

#[test]
fn describe_reports_the_components_tools() {
    let dir = tempfile::tempdir().expect("temp dir");
    let tool = load(&config("fixture"), dir.path());
    let descriptors: serde_json::Value =
        serde_json::from_str(tool.descriptors()).expect("descriptors are JSON");
    let names: Vec<&str> = descriptors
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|d| d["name"].as_str())
        .collect();
    assert!(names.contains(&"echo"));
    assert!(names.contains(&"probe"));
}

#[test]
fn a_tool_returns_its_result() {
    let dir = tempfile::tempdir().expect("temp dir");
    let tool = load(&config("fixture"), dir.path());
    assert_eq!(call(&tool, "echo", r#"{"x":1}"#).expect("ok"), r#"{"x":1}"#);
    assert_eq!(
        tool.digest().len(),
        64,
        "digest of the loaded module is recorded"
    );
}

#[test]
fn an_ungranted_file_is_unreadable() {
    let dir = tempfile::tempdir().expect("temp dir");
    let tool = load(&config("fixture"), dir.path());
    let args = format!(r#"{{"path":{}}}"#, json_string(&an_ungranted_file()));
    match call(&tool, "read-file", &args) {
        Err(ToolError::ToolFailed { message, .. }) => {
            assert!(
                message.starts_with("read "),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected the guest to be refused, got {other:?}"),
    }
}

#[test]
fn a_read_grant_reaches_its_directory_and_nothing_else() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir_all(dir.path().join("data")).expect("mkdir");
    std::fs::write(dir.path().join("data/hello.txt"), "granted").expect("write");

    let mut cfg = config("fixture");
    cfg.capabilities.filesystem.read = vec!["data/**".to_owned()];
    let tool = load(&cfg, dir.path());

    // The guest sees the preopen under a relative name.
    let granted = r#"{"path":"data/hello.txt"}"#;
    assert_eq!(
        call(&tool, "read-file", granted).expect("granted read"),
        "granted"
    );

    let outside = format!(r#"{{"path":{}}}"#, json_string(&an_ungranted_file()));
    assert!(matches!(
        call(&tool, "read-file", &outside),
        Err(ToolError::ToolFailed { .. })
    ));
}

#[test]
fn a_relative_traversal_out_of_the_grant_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir_all(dir.path().join("data")).expect("mkdir");
    std::fs::write(dir.path().join("secret.txt"), "outside").expect("write");

    let mut cfg = config("fixture");
    cfg.capabilities.filesystem.read = vec!["data/**".to_owned()];
    let tool = load(&cfg, dir.path());

    let escape = r#"{"path":"../secret.txt"}"#;
    assert!(matches!(
        call(&tool, "read-file", escape),
        Err(ToolError::ToolFailed { .. })
    ));
}

/// A symlink inside a granted directory must not reach its target. Creating a
/// directory symlink needs a privilege on Windows, so the test is skipped when
/// the link cannot be made, and says so.
#[test]
fn a_symlink_inside_the_grant_cannot_escape_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let outside = tempfile::tempdir().expect("outside dir");
    std::fs::write(outside.path().join("secret.txt"), "outside").expect("write");
    std::fs::create_dir_all(dir.path().join("data")).expect("mkdir");

    let link = dir.path().join("data/escape");
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(outside.path(), &link);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_dir(outside.path(), &link);
    if let Err(error) = made {
        eprintln!("skipping symlink escape test: cannot create symlink ({error})");
        return;
    }

    let mut cfg = config("fixture");
    cfg.capabilities.filesystem.read = vec!["data/**".to_owned()];
    let tool = load(&cfg, dir.path());

    let through_link = r#"{"path":"data/escape/secret.txt"}"#;
    assert!(
        matches!(
            call(&tool, "read-file", through_link),
            Err(ToolError::ToolFailed { .. })
        ),
        "a symlink must not lead out of the granted directory"
    );
}

#[test]
fn a_read_grant_cannot_write() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir_all(dir.path().join("data")).expect("mkdir");
    let mut cfg = config("fixture");
    cfg.capabilities.filesystem.read = vec!["data/**".to_owned()];
    let tool = load(&cfg, dir.path());

    let args = r#"{"path":"data/new.txt"}"#;
    assert!(matches!(
        call(&tool, "write-file", args),
        Err(ToolError::ToolFailed { .. })
    ));
    assert!(!dir.path().join("data/new.txt").exists());
}

#[test]
fn a_write_grant_writes_inside_its_directory() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir_all(dir.path().join("out")).expect("mkdir");
    let mut cfg = config("fixture");
    cfg.capabilities.filesystem.write = vec!["out/**".to_owned()];
    let tool = load(&cfg, dir.path());

    call(&tool, "write-file", r#"{"path":"out/result.txt"}"#).expect("write granted");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out/result.txt")).expect("host sees it"),
        "written"
    );
}

#[test]
fn only_granted_environment_variables_are_visible() {
    let dir = tempfile::tempdir().expect("temp dir");

    let ungranted = load(&config("fixture"), dir.path());
    assert_eq!(
        call(&ungranted, "env", r#"{"name":"PATH"}"#).expect("ok"),
        r#"{"value":null}"#,
        "PATH must not leak to a tool that was not granted it"
    );

    let mut cfg = config("fixture");
    cfg.capabilities.env = vec!["PATH".to_owned()];
    let granted = load(&cfg, dir.path());
    let value = call(&granted, "env", r#"{"name":"PATH"}"#).expect("ok");
    assert!(
        value.contains("\"value\":\""),
        "granted variable is visible: {value}"
    );
}

#[test]
fn outbound_requests_to_ungranted_hosts_are_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let tool = load(&config("fixture"), dir.path());
    let args = r#"{"url":"https://example.invalid/"}"#;
    assert!(matches!(
        call(&tool, "fetch", args),
        Err(ToolError::ToolFailed { .. })
    ));
}

#[test]
fn plain_http_is_refused_even_on_an_allowed_host() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.capabilities.network = vec!["example.invalid".to_owned()];
    let tool = load(&cfg, dir.path());
    let args = r#"{"url":"http://example.invalid/"}"#;
    assert!(matches!(
        call(&tool, "fetch", args),
        Err(ToolError::ToolFailed { .. })
    ));
}

#[test]
fn the_sandbox_self_test_passes_for_the_real_fixture() {
    let bytes = std::fs::read(guest_path()).expect("guest built");
    runtime()
        .self_test(&bytes, Path::new(&an_ungranted_file()))
        .expect("sandbox denies everything it was not granted");
}

#[test]
fn a_runaway_tool_is_interrupted_at_its_time_limit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.capabilities.time_limit = Some(Duration::from_millis(200));
    let tool = load(&cfg, dir.path());

    let started = Instant::now();
    let result = call(&tool, "spin", "{}");
    let elapsed = started.elapsed();

    assert!(
        matches!(result, Err(ToolError::TimedOut { .. })),
        "got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "interrupted promptly, took {elapsed:?}"
    );
    assert_eq!(call(&tool, "echo", "ok").expect("still serving"), "ok");
}

#[test]
fn cancellation_interrupts_a_running_call() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.capabilities.time_limit = Some(Duration::from_secs(30));
    let tool = Arc::new(load(&cfg, dir.path()));

    let cancel = CancelToken::new();
    let trigger = cancel.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        trigger.cancel();
    });

    let started = Instant::now();
    let result = tool.call("spin", "{}", &cancel);
    canceller.join().expect("canceller finishes");

    assert!(
        matches!(result, Err(ToolError::Cancelled { .. })),
        "got {result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn exceeding_the_memory_limit_traps_without_taking_the_host_down() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.capabilities.memory_limit = Some(32 * 1024 * 1024);
    let tool = load(&cfg, dir.path());

    let result = call(&tool, "grow", r#"{"mb":128}"#);
    assert!(
        matches!(result, Err(ToolError::Trapped { .. })),
        "got {result:?}"
    );
    assert_eq!(
        call(&tool, "echo", "still-here").expect("serving"),
        "still-here"
    );
}

#[test]
fn a_guest_panic_is_a_trap_and_the_host_keeps_serving() {
    let dir = tempfile::tempdir().expect("temp dir");
    let tool = load(&config("fixture"), dir.path());

    let result = call(&tool, "panic", "{}");
    assert!(
        matches!(result, Err(ToolError::Trapped { .. })),
        "got {result:?}"
    );
    assert_eq!(call(&tool, "echo", "after").expect("serving"), "after");
}

#[test]
fn a_tool_error_is_reported_without_discarding_the_instance() {
    let dir = tempfile::tempdir().expect("temp dir");
    let tool = load(&config("fixture"), dir.path());

    match call(&tool, "fail", "{}") {
        Err(ToolError::ToolFailed { message, .. }) => {
            assert_eq!(message, "fixture refused the request");
        }
        other => panic!("expected a tool error, got {other:?}"),
    }
    assert_eq!(call(&tool, "echo", "next").expect("serving"), "next");
}

#[test]
fn pool_usage_counts_checked_out_instances() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.limits.max_concurrent_calls = Some(2);
    cfg.capabilities.time_limit = Some(Duration::from_millis(800));
    let tool = Arc::new(load(&cfg, dir.path()));
    assert_eq!(
        tool.pool_usage(),
        tpt_mcpbox_runtime::PoolUsage {
            leased: 0,
            capacity: 2
        }
    );

    let busy = Arc::clone(&tool);
    let spinner = std::thread::spawn(move || busy.call("spin", "{}", &CancelToken::new()));
    // Wait until the spinning call holds its instance.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while tool.pool_usage().leased == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the call never leased"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(tool.pool_usage().leased, 1);

    let _ = spinner.join().expect("spinner finishes");
    assert_eq!(tool.pool_usage().leased, 0, "the lease is returned");
}

#[test]
fn concurrency_cap_is_enforced() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.limits.max_concurrent_calls = Some(1);
    cfg.capabilities.time_limit = Some(Duration::from_millis(800));
    let tool = Arc::new(load(&cfg, dir.path()));

    let busy = Arc::clone(&tool);
    let spinner = std::thread::spawn(move || busy.call("spin", "{}", &CancelToken::new()));
    std::thread::sleep(Duration::from_millis(100));

    let refused = call(&tool, "echo", "x");
    assert!(
        matches!(refused, Err(ToolError::Overloaded { limit: 1, .. })),
        "got {refused:?}"
    );

    let _ = spinner.join().expect("spinner finishes");
    assert_eq!(call(&tool, "echo", "y").expect("slot free again"), "y");
}

#[test]
fn oversized_arguments_are_refused_before_the_guest_runs() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.limits.max_argument_bytes = Some(8);
    let tool = load(&cfg, dir.path());
    assert!(matches!(
        call(&tool, "echo", "far too many bytes"),
        Err(ToolError::ArgumentsTooLarge { limit: 8, .. })
    ));
}

#[test]
fn oversized_results_are_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.limits.max_result_bytes = Some(4);
    let tool = load(&cfg, dir.path());
    assert!(matches!(
        call(&tool, "echo", "longer than four"),
        Err(ToolError::ResultTooLarge { limit: 4, .. })
    ));
}

#[test]
fn a_digest_pin_that_does_not_match_refuses_the_module() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.sha256 = Some("0".repeat(64));
    let result = runtime().load_tool(&cfg, &SecretStore::new(), dir.path());
    assert!(matches!(result, Err(ToolError::IntegrityMismatch { .. })));
}

#[test]
fn a_correct_digest_pin_loads() {
    let bytes = std::fs::read(guest_path()).expect("guest built");
    let digest = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&bytes))
    };
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.sha256 = Some(digest.clone());
    let tool = runtime()
        .load_tool(&cfg, &SecretStore::new(), dir.path())
        .expect("pinned module loads");
    assert_eq!(tool.digest(), digest);
}

#[test]
fn oci_references_are_refused_until_implemented() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.wasm_path = None;
    cfg.oci_ref = Some("oci://ghcr.io/example/tool:1".to_owned());
    assert!(matches!(
        runtime().load_tool(&cfg, &SecretStore::new(), dir.path()),
        Err(ToolError::Unsupported { .. })
    ));
}

#[test]
fn a_missing_secret_fails_the_load() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = config("fixture");
    cfg.secrets = vec![tpt_mcpbox_config::SecretBinding {
        env: "TPT_TEST_SECRET_THAT_IS_NOT_SET".to_owned(),
        header: "Authorization".to_owned(),
        prefix: Some("Bearer".to_owned()),
        hosts: Vec::new(),
    }];
    assert!(matches!(
        runtime().load_tool(&cfg, &SecretStore::new(), dir.path()),
        Err(ToolError::InvalidConfig { .. })
    ));
}

#[test]
fn a_panic_message_does_not_cross_the_boundary() {
    // The guest's panic text stays in the guest: the host sees only the trap.
    // So a secret the guest puts in its panic message is never reported.
    let dir = tempfile::tempdir().expect("temp dir");
    let tool = load(&config("fixture"), dir.path());
    let secret = "sk-live-PANIC-9";

    match call(&tool, "panic-echo", &format!(r#"{{"token":"{secret}"}}"#)) {
        Err(ToolError::Trapped { message, .. }) => {
            assert!(
                !message.contains(secret),
                "trap text leaked the panic: {message}"
            );
        }
        other => panic!("expected a trap, got {other:?}"),
    }
    assert_eq!(call(&tool, "echo", "after").expect("serving"), "after");
}
