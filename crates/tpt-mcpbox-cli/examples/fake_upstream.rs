// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! A stdio MCP server used by the upstream supervisor tests. It is an example,
//! so it is built by `cargo test` but never shipped.
//!
//! Usage: `fake_upstream <state-file> <log-file>`
//!
//! * Each start appends a line to the log file, so tests can count restarts.
//! * The state file is read at start. `changed` exposes a different tool, so a
//!   restart must be refused. Anything else exposes `echo` and `crash`.
//! * `crash` exits the process without replying.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

fn tool_names(state: &str) -> Vec<&'static str> {
    if state.trim() == "changed" {
        vec!["other"]
    } else {
        vec!["echo", "crash"]
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let state_path = args.next().expect("usage: fake_upstream <state> <log>");
    let log_path = args.next().expect("usage: fake_upstream <state> <log>");

    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("log file opens");
    writeln!(log, "start").expect("log write");

    let state = std::fs::read_to_string(&state_path).unwrap_or_default();
    let tools: Vec<Value> = tool_names(&state)
        .into_iter()
        .map(|name| json!({ "name": name, "inputSchema": { "type": "object" } }))
        .collect();

    let mut stdout = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        // Notifications carry no id and get no reply.
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let result = match message["method"].as_str().unwrap_or_default() {
            "initialize" => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "fake-upstream", "version": "1" }
            }),
            "tools/list" => json!({ "tools": tools }),
            "tools/call" => {
                let name = message["params"]["name"].as_str().unwrap_or_default();
                if name == "crash" {
                    std::process::exit(3);
                }
                json!({ "content": [{ "type": "text", "text": format!("echo:{name}") }] })
            }
            _ => json!({}),
        };
        writeln!(
            stdout,
            "{}",
            json!({ "jsonrpc": "2.0", "id": id, "result": result })
        )
        .expect("reply write");
        stdout.flush().expect("reply flush");
    }
}
