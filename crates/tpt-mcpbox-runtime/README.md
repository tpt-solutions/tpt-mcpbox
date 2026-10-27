# tpt-mcpbox-runtime

The WebAssembly component runtime for [tpt-mcpbox](../../README.md). Every tool
call runs inside a `wasmtime` component instance whose only ambient authority
comes from its configured capabilities.

> **Status: pre-release (0.1.0 in progress).** The API may change before 0.1.0.
> OCI module pulls and signature verification are not built yet. Modules are
> loaded from local paths and pinned by SHA-256.

## Security model

- **No ambient authority.** Filesystem grants become preopened directories.
  A tool that asks for anything else gets an error from the sandbox, whatever
  its code does.
- **Network through the host.** Outbound HTTP goes through a host `wasi:http`
  handler. The handler enforces the tool's domain allowlist, requires HTTPS, and
  injects secret headers.
- **Environment only when granted.** Environment variables are exposed only
  when the configuration grants them.
- **Secrets never enter the guest.** A tool gets the response, not the token
  that was used to make the request.
- **Hard limits.** `memory_limit` caps linear memory through `StoreLimits`.
  `time_limit` bounds execution, and a `CancelToken` lets the host stop a call.
- **Pinned modules.** A module with a `sha256` in the configuration is refused
  if its bytes differ.

## Entry points

| Item | Purpose |
|---|---|
| `Runtime::new` | Builds the `wasmtime` engine, the pooling allocator and the sandboxed WASI and `wasi:http` linker |
| `Runtime::load_tool` | Compiles one tool from its configuration |
| `LoadedTool::call` | Runs one tool with the JSON arguments from `tools/call` |
| `LoadedTool::descriptors` | The tool list the component reports from `describe` |
| `Runtime::self_test` | Runs a probe module at startup to prove the sandbox is in effect |
| `CancelToken` | Cancels a call that is still running |
| `ToolError` | The error type for loading and calling tools |

`self_test` should run at startup. If the sandbox cannot be shown to work, the
server should not start.

## The tool world

Each tool component implements the `tpt:mcpbox/tool` world in
[`wit/tool.wit`](wit/tool.wit):

```wit
world tool {
    export describe: func() -> string;
    export call: func(name: string, arguments: string) -> result<string, string>;
}
```

`describe` returns a JSON array of tools, each with a name, a description and
an input schema. `call` runs one tool. Its arguments are the JSON object from
`tools/call`, and its result is JSON text or an error message. Tools import
only the WASI interfaces they need, and the host links only the ones that
their grants allow.

The SDK for writing tools is [`tpt-mcpbox-sdk`](../tpt-mcpbox-sdk/README.md).

## Pooling

Instances come from `wasmtime`'s pooling allocator. The pool reserves address
space up front, so a warm instance is cheap to reuse. The reservation sizes
are fixed constants in `runtime.rs`: the number of instances, and the largest
linear memory any one instance can use.

## Using the crate

The crate is not yet published to crates.io. Depend on it by path:

```toml
[dependencies]
tpt-mcpbox-runtime = { path = "../tpt-mcpbox-runtime" }
```

The minimum supported Rust version is **1.85**. Building the runtime needs the
dependencies that `wasmtime` 34 requires; the workspace lockfile pins them.

## Testing and benchmarks

```console
cargo test -p tpt-mcpbox-runtime
cargo bench -p tpt-mcpbox-runtime
```

- `tests/sandbox.rs` checks that grants are enforced: an ungranted path or host
  is refused.
- `tests/guest/` is a test-only tool component. The integration tests build it
  for `wasm32-wasip2`. Its own workspace keeps it out of the host build.
- `benches/invocation.rs` measures the cost of one tool invocation.

## Scope

In scope: loading and running tool components, mapping capabilities to WASI
authority, and the outbound HTTP handler.

Out of scope: deciding whether a call is allowed (`tpt-mcpbox-policy`), the
MCP wire format (`tpt-mcpbox-protocol`), and proxying to external servers
(`tpt-mcpbox-proxy`).

## License

Dual licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT), at your option.
