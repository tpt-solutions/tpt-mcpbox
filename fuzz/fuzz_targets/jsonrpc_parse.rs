// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Feeds arbitrary bytes to the JSON-RPC message parser. Parsing must never
//! panic; malformed input must come back as an error.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_mcpbox_protocol::jsonrpc::{ClientMessage, Incoming};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = ClientMessage::parse(text);
    if let Ok(value) = serde_json::from_str(text) {
        let _ = Incoming::from_value(value);
    }
});
