// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Hello-world tool component: two tools that need no grants at all.

use serde::Deserialize;
use schemars::JsonSchema;
use tpt_mcpbox_sdk::{Tool, ToolError, ToolResult, export_tools};

#[derive(Deserialize, JsonSchema)]
struct GreetArgs {
    /// Who to greet.
    name: String,
}

struct Greet;

impl Tool for Greet {
    type Args = GreetArgs;
    const NAME: &'static str = "greet";
    const DESCRIPTION: &'static str = "Greets someone by name";

    fn run(args: GreetArgs) -> Result<ToolResult, ToolError> {
        Ok(ToolResult::text(format!("Hello, {}!", args.name)))
    }
}

#[derive(Deserialize, JsonSchema)]
struct AddArgs {
    /// First number.
    a: f64,
    /// Second number.
    b: f64,
}

struct Add;

impl Tool for Add {
    type Args = AddArgs;
    const NAME: &'static str = "add";
    const DESCRIPTION: &'static str = "Adds two numbers";

    fn run(args: AddArgs) -> Result<ToolResult, ToolError> {
        ToolResult::json(&serde_json::json!({ "sum": args.a + args.b }))
    }
}

#[derive(Deserialize, JsonSchema)]
struct FetchArgs {
    /// Absolute https URL to GET. Must be on the tool's network allowlist.
    url: String,
}

struct Fetch;

impl Tool for Fetch {
    type Args = FetchArgs;
    const NAME: &'static str = "fetch";
    const DESCRIPTION: &'static str = "GETs a URL and returns its JSON body";

    fn run(args: FetchArgs) -> Result<ToolResult, ToolError> {
        let value = tpt_mcpbox_sdk::http::get_json(&args.url)?;
        ToolResult::json(&value)
    }
}

export_tools!(Greet, Add, Fetch);
