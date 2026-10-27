// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Feeds arbitrary bytes to the configuration loader and the validator. Loading
//! must never panic, and any configuration that loads must validate without
//! panicking either.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_mcpbox_config::load;
use tpt_mcpbox_config::validate::{self, ValidationMode};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(config) = load::load_str(text, "fuzz.yaml") {
        let _ = validate::validate(&config, ValidationMode::Audit);
    }
});
