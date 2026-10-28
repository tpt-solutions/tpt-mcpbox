// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Per-invocation overhead of a warm pooled instance.
//!
//! The budget in `todo.md` is under 5 ms at p50 on reference hardware. Criterion
//! reports the distribution, so compare the median in its output against that
//! budget. The guest does no work here, so the figure is the host's overhead:
//! checkout, epoch and cancellation setup, the call, and checkin.

// The criterion macros generate undocumented entry points.
#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;

use criterion::{Criterion, criterion_group, criterion_main};
use tpt_mcpbox_config::{Capabilities, Limits, RateLimit, SecretStore, ToolConfig};
use tpt_mcpbox_runtime::{CancelToken, Runtime};

/// Build the fixture component the same way the integration tests do.
fn guest_path() -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = crate_dir.join("tests/guest/Cargo.toml");
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
    target.join("wasm32-wasip2/release/tpt_mcpbox_test_guest.wasm")
}

/// Measures one warm echo call through the pool.
fn bench_warm_invocation(c: &mut Criterion) {
    let runtime = Runtime::new().expect("runtime builds");
    let config = ToolConfig {
        name: "fixture".to_owned(),
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
    };
    let tool = runtime
        .load_tool(&config, &SecretStore::new(), Path::new("."))
        .expect("tool loads");
    let cancel = CancelToken::new();

    c.bench_function("warm echo invocation", |b| {
        b.iter(|| tool.call("echo", "{}", &cancel).expect("echo succeeds"));
    });
}

criterion_group!(benches, bench_warm_invocation);
criterion_main!(benches);
