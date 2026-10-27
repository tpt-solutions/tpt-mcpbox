# tpt-mcpbox-hello

A hello-world tool component built with [`tpt-mcpbox-sdk`](../../README.md). It
is the worked example for writing a tool, and it needs no grants at all.

It provides three tools:

| Tool | Arguments | Result |
|---|---|---|
| `greet` | `name` | `Hello, <name>!` as text |
| `add` | `a`, `b` (numbers) | `{"sum": a + b}` as JSON |
| `fetch` | `url` (absolute HTTPS URL) | The JSON body of a GET request |

`fetch` is the only tool that touches the network. It works only when the
configuration puts the host on the tool's `capabilities.network` allowlist.
Without that grant, the host refuses the request and the agent sees a tool error.

## Build

From this directory:

```sh
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

The output is `target/wasm32-wasip2/release/tpt_mcpbox_hello.wasm`. Pin it in
the configuration with its SHA-256 if you want the runtime to refuse any other
bytes.

## Using it

Point a tool entry at the built module:

```yaml
tools:
  - name: hello
    wasm_path: ./crates/tpt-mcpbox-sdk/examples/hello/target/wasm32-wasip2/release/tpt_mcpbox_hello.wasm
    capabilities:
      memory_limit: "16MB"
      time_limit: "5s"
```

Then check it with `tpt-mcpbox validate` and call a tool with
`tpt-mcpbox tools call greet --args '{"name":"Ada"}'`.

## Reading the source

[`src/lib.rs`](src/lib.rs) is short and shows the whole pattern: a type for the
arguments that derives `Deserialize` and `JsonSchema`, an `impl Tool` for each
tool, and one `export_tools!` call.

## License

Dual licensed under either of [Apache License 2.0](../../../../LICENSE-APACHE) or
[MIT License](../../../../LICENSE-MIT), at your option.
