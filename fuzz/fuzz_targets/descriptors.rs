// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The host side of the Wasm boundary at load time: the JSON descriptors a
//! component reports are untrusted. Parsing must never panic, and an accepted
//! list must hold only named tools with object schemas.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(tools) = tpt_mcpbox_protocol::tools::parse_descriptors(text) {
        for guest in &tools {
            assert!(!guest.tool.name.is_empty());
            assert!(guest.tool.input_schema.is_object());
        }
    }
});
