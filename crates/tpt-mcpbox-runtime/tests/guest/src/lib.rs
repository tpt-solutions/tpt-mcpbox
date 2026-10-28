// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Fixture tool used by the runtime's integration tests. Each tool exercises one
//! sandbox boundary so the host-side tests can assert it holds.

wit_bindgen::generate!({
    path: "../../wit",
    world: "tool",
});

struct Fixture;

const DESCRIPTORS: &str = r#"[
  {"name": "echo", "description": "returns its arguments", "input_schema": {"type": "object"}},
  {"name": "read-file", "description": "reads a file path", "input_schema": {"type": "object"}},
  {"name": "fetch", "description": "GET a URL", "input_schema": {"type": "object"}},
  {"name": "env", "description": "reads an environment variable", "input_schema": {"type": "object"}},
  {"name": "write-file", "description": "writes a file", "input_schema": {"type": "object"}},
  {"name": "probe", "description": "reports what the sandbox exposes", "input_schema": {"type": "object"}},
  {"name": "spin", "description": "never returns", "input_schema": {"type": "object"}},
  {"name": "grow", "description": "allocates memory", "input_schema": {"type": "object"}},
  {"name": "panic", "description": "panics", "input_schema": {"type": "object"}},
  {"name": "fail", "description": "returns a tool error", "input_schema": {"type": "object"}},
  {"name": "panic-echo", "description": "panics with its arguments in the message", "input_schema": {"type": "object"}}
]"#;

/// Read one string field from the JSON arguments, or `None` when absent.
fn field(arguments: &str, key: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(arguments).ok()?;
    value.get(key)?.as_str().map(str::to_owned)
}

impl Guest for Fixture {
    fn describe() -> String {
        DESCRIPTORS.to_owned()
    }

    fn call(name: String, arguments: String) -> Result<String, String> {
        match name.as_str() {
            "echo" => Ok(arguments),
            "read-file" => {
                let path = field(&arguments, "path").ok_or("missing path")?;
                std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))
            }
            "write-file" => {
                let path = field(&arguments, "path").ok_or("missing path")?;
                std::fs::write(&path, "written").map_err(|e| format!("write {path}: {e}"))?;
                Ok("written".to_owned())
            }
            "fetch" => {
                let url = field(&arguments, "url").ok_or("missing url")?;
                let response = waki::Client::new()
                    .get(&url)
                    .send()
                    .map_err(|e| format!("fetch {url}: {e:?}"))?;
                let status = response.status_code();
                let body = response.body().map_err(|e| format!("body: {e:?}"))?;
                let text = String::from_utf8_lossy(&body);
                Ok(format!("{{\"status\":{status},\"body\":{text:?}}}"))
            }
            "env" => {
                let key = field(&arguments, "name").ok_or("missing name")?;
                Ok(match std::env::var(&key) {
                    Ok(value) => format!("{{\"value\":{value:?}}}"),
                    Err(_) => "{\"value\":null}".to_owned(),
                })
            }
            "probe" => {
                let path = field(&arguments, "path").unwrap_or_else(|| "/etc/hosts".to_owned());
                let fs = match std::fs::read(&path) {
                    Ok(_) => "readable",
                    Err(_) => "denied",
                };
                let env_home = std::env::var("USERPROFILE")
                    .or_else(|_| std::env::var("HOME"))
                    .is_ok();
                let env_count = std::env::vars().count();
                let url = field(&arguments, "url").unwrap_or_else(|| "https://example.invalid/".to_owned());
                let net = match waki::Client::new().get(&url).send() {
                    Ok(_) => "reachable",
                    Err(_) => "denied",
                };
                Ok(serde_json::json!({
                    "fs": fs,
                    "env_home": env_home,
                    "env_count": env_count,
                    "net": net,
                })
                .to_string())
            }
            "spin" => loop {
                std::hint::black_box(0u64);
            },
            "grow" => {
                let mb = field(&arguments, "mb")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(256);
                let mut buffer: Vec<u8> = Vec::new();
                for _ in 0..mb {
                    buffer.extend(std::iter::repeat_n(1u8, 1 << 20));
                }
                Ok(format!("{}", buffer.len()))
            }
            "panic" => panic!("fixture panic on request"),
            "panic-echo" => panic!("fixture panic with {arguments}"),
            "fail" => Err("fixture refused the request".to_owned()),
            other => Err(format!("unknown tool {other}")),
        }
    }
}

export!(Fixture);
