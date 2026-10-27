// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Feeds arbitrary policy inputs to a fixed policy. Evaluation must never
//! panic, whatever the caller, arguments, host, path or URIs contain.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tpt_mcpbox_config::load;
use tpt_mcpbox_policy::{Policy, PolicyInput};

const POLICY: &str = r#"version: 1
server:
  transports: [stdio]
policy:
  default: deny
  rules:
    - id: allow-read
      effect: allow
      tool: read_file
      caller: "agent-*"
      hosts: ["api.github.com"]
      paths: ["./workspace/**"]
    - id: allow-search
      effect: allow
      tool: search_repos
"#;

fn policy() -> &'static Policy {
    static POLICY_CELL: OnceLock<Policy> = OnceLock::new();
    POLICY_CELL.get_or_init(|| {
        let config = load::load_str(POLICY, "fuzz-policy.yaml").expect("fixed policy loads");
        Policy::from_config(&config.policy).expect("fixed policy compiles")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = serde_json::from_slice::<PolicyInput>(data) else {
        return;
    };
    let _ = policy().evaluate(&input);
});
