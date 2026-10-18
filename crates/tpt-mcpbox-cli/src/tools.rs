// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! `tpt-mcpbox tools`: list and call the configured tools from the command
//! line, for debugging.
//!
//! The hub is built exactly as `run` builds it, so a call here goes through
//! the same policy, rate limits and audit log. Results are scrubbed with the
//! same redactor the agent-facing transports use. Because the audit log is
//! held under an OS lock, these commands are refused while a hub is running
//! against the same configuration.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use serde_json::{Map, Value};
use tpt_mcpbox_config::load;
use tpt_mcpbox_router::ToolOutput;
use tpt_mcpbox_runtime::CancelToken;

use crate::serve;

/// Identity recorded for calls made from this command.
const CALLER: &str = "tools-cli";

/// How long to wait for in-flight calls when the command finishes.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Print every tool the configuration exposes, one per line.
pub(crate) fn list_command(config_path: Option<&Path>) -> Result<ExitCode, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the async runtime: {error}"))?;
    runtime.block_on(async {
        let hub = open_hub(config_path).await?;
        for tool in hub.router.list() {
            match tool.description.as_deref() {
                Some(description) => println!("{}\t{description}", tool.name),
                None => println!("{}", tool.name),
            }
        }
        hub.router.shutdown(DRAIN_TIMEOUT).await;
        Ok(ExitCode::SUCCESS)
    })
}

/// Call one tool with JSON arguments and print the scrubbed result.
pub(crate) fn call_command(
    config_path: Option<&Path>,
    name: &str,
    arguments: Option<&str>,
) -> Result<ExitCode, String> {
    let arguments = parse_arguments(arguments)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the async runtime: {error}"))?;
    runtime.block_on(async {
        let hub = open_hub(config_path).await?;
        let result = hub
            .router
            .call(CALLER, name, arguments, CancelToken::new())
            .await;
        hub.router.shutdown(DRAIN_TIMEOUT).await;
        let output = result.map_err(|error| error.to_string())?;
        let text = render(&output)?;
        println!("{}", hub.redactor.scrub(&text));
        Ok(ExitCode::SUCCESS)
    })
}

/// Build the hub from the configuration, as `run` does.
async fn open_hub(config_path: Option<&Path>) -> Result<serve::Hub, String> {
    let cwd = std::env::current_dir()
        .map_err(|error| format!("cannot read the working directory: {error}"))?;
    let (path, _) = load::discover(config_path, &|name| std::env::var(name).ok(), &cwd)
        .map_err(|error| error.to_string())?;
    let loaded = load::load_file(&path).map_err(|error| error.to_string())?;
    let base = path.parent().unwrap_or(Path::new("."));
    serve::build_router(&loaded.config, base).await
}

/// Parse `--args` as a JSON object. Absent arguments mean none.
fn parse_arguments(raw: Option<&str>) -> Result<Option<Map<String, Value>>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match serde_json::from_str::<Value>(raw)
        .map_err(|error| format!("--args is not valid JSON: {error}"))?
    {
        Value::Object(map) => Ok(Some(map)),
        other => Err(format!(
            "--args must be a JSON object, not {}",
            json_kind(&other)
        )),
    }
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Turn a tool result into the text printed to the terminal.
fn render(output: &ToolOutput) -> Result<String, String> {
    match output {
        ToolOutput::Wasm(text) => Ok(text.clone()),
        ToolOutput::Upstream(result) => serde_json::to_string_pretty(result)
            .map_err(|error| format!("cannot render the result: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_must_be_a_json_object() {
        assert_eq!(parse_arguments(None).unwrap(), None);
        let map = parse_arguments(Some(r#"{"name":"ada"}"#)).unwrap().unwrap();
        assert_eq!(map.get("name"), Some(&Value::String("ada".to_owned())));

        let err = parse_arguments(Some("[1,2]")).unwrap_err();
        assert!(err.contains("an array"), "{err}");
        assert!(parse_arguments(Some("{not json")).is_err());
    }

    #[test]
    fn wasm_output_is_printed_verbatim() {
        let out = ToolOutput::Wasm("Hello, Ada!".to_owned());
        assert_eq!(render(&out).unwrap(), "Hello, Ada!");
    }
}
