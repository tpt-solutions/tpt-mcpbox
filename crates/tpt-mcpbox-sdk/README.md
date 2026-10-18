<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) TPT Solutions -->

# tpt-mcpbox-sdk

The guest SDK for writing tpt-mcpbox tools in Rust. A tool is a Rust type; the
SDK turns it into a WebAssembly component that the hub can load.

## A tool

```rust
use schemars::JsonSchema;
use serde::Deserialize;
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

export_tools!(Greet);
```

- The agent sees `NAME`, `DESCRIPTION`, and a JSON schema generated from
  `GreetArgs`, including its doc comments.
- Arguments are validated against that type before `run` is called. A wrong
  type comes back to the agent as a tool error that names the field.
- `ToolResult::text` and `ToolResult::json` build the reply.
- Return `ToolError::new("...")` (or `?` on a `ToolError`) for a failure the
  agent should see. It reaches the agent with `isError: true`.

## Building

A tool crate is a `cdylib` with its own workspace, built for `wasm32-wasip2`:

```sh
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

The worked example is in [`examples/hello`](examples/hello). It has `greet`,
`add`, and `fetch`.

## Calling the network

`tpt_mcpbox_sdk::http::get_json` and `post_json` go through the host's
outbound handler. A URL must be on the tool's `capabilities.network` allowlist
and use HTTPS. A refused request is returned as a tool error, not a panic.

## Limits of this version

- The SDK takes its WIT world from `crates/tpt-mcpbox-runtime/wit`. A published
  crate would need its own copy of that file.
- There is no `#[tool]` attribute macro yet. `Tool` plus `export_tools!` does
  the same job without a proc-macro crate.
- Resource and prompt providers are not in the SDK yet; tools only.
- `tpt-mcpbox init tool <DIR> --sdk-path <PATH>` writes a starter project. The SDK path is required because the SDK is not published.
