// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Feeds arbitrary text to the Rego subset as a module. Compiling must never
//! panic, and a module that compiles must evaluate without panicking, whatever
//! it does with the request. Errors are refusals, so they are fine.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_mcpbox_config::PolicyConfig;
use tpt_mcpbox_policy::{Policy, PolicyInput};

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(policy) = Policy::from_config_with_rego(&PolicyConfig::default(), "fuzz.rego", source)
    else {
        return;
    };
    let input = PolicyInput {
        method: "tools/call".to_owned(),
        tool: Some("read_file".to_owned()),
        arguments: serde_json::json!({ "path": "/srv/a", "uris": ["file:///srv/a"] }),
        uris: vec!["file:///srv/a".to_owned()],
        ..PolicyInput::default()
    };
    let _ = policy.evaluate(&input);
});
