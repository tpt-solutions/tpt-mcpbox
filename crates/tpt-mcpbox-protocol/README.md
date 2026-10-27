# tpt-mcpbox-protocol

Wire-format types and transports for the [Model Context Protocol][mcp] (MCP),
as used by [tpt-mcpbox](../../README.md).

This crate is the protocol boundary of the project. It parses and produces
JSON-RPC 2.0 and MCP messages, moves them over stdio and Streamable HTTP, and
tracks session state. It makes no policy, sandbox or I/O-authority decisions:
those are layered on top by the other `tpt-mcpbox-*` crates.

> **Status: pre-release (0.1.0 in progress).** The API may change before 0.1.0.
> Conformance testing against the MCP JSON Schema and manual interop checks are
> still open; see [todo.md](../../todo.md).

## What it provides

- **JSON-RPC 2.0 envelopes**: requests, responses, notifications and batches,
  with the JSON-RPC and MCP error codes. Unknown error codes pass through
  unchanged.
- **MCP method payloads** for tools, resources (including templates,
  subscriptions and `list_changed`/`updated` notifications), prompts,
  completion, and utilities (progress, cancellation, logging).
- **Capability negotiation** for the server and for the client features that
  are routed back to the agent: `roots`, `sampling/createMessage` and
  `elicitation`.
- **Content types**: text, image, audio, embedded resource and resource links.
- **Protocol versions**: the latest supported revision is `2025-06-18`. The
  crate also accepts `2025-03-26` and `2024-11-05` (see
  `shared::SUPPORTED_PROTOCOL_VERSIONS`).
- **Transports**
  - `transport::stdio`: newline-delimited JSON, a bounded line length,
    single-writer framing, and logs on stderr only.
  - `transport::http`: Streamable HTTP with `POST /mcp`, a `GET` stream and
    `DELETE` to end a session. It uses SSE responses with resumable event ids
    and `Last-Event-ID` replay, `Mcp-Session-Id`, origin validation (loopback
    only by default) and payload caps.
- **Sessions**: a lifecycle state machine that refuses requests before the
  handshake completes.
- **Dispatcher**: routes incoming requests to a `Handler`, shapes JSON-RPC
  errors, and correlates server-to-agent `roots`, `sampling` and `elicitation`
  calls.

## Module map

| Module | Contents |
|---|---|
| `jsonrpc` | Request, response, notification, batch and error envelopes |
| `model` | Capability negotiation and client-feature payloads |
| `tools`, `resources`, `prompts`, `completion`, `utilities` | MCP method payloads |
| `content` | Content blocks returned by tools and prompts |
| `method` | Method name constants |
| `session` | Lifecycle, `SessionId`, `SessionConfig` |
| `server` | `Dispatcher`, `Handler`, `DispatcherOptions` |
| `transport::stdio`, `transport::http` | The two transports |
| `shared` | Protocol version constants and shared helpers |
| `error` | `ProtocolError` and `Result` |

## Example

This example is a doctest, so it is checked by `cargo test`:

```rust
use tpt_mcpbox_protocol::Id;
use tpt_mcpbox_protocol::jsonrpc::Request;
use tpt_mcpbox_protocol::tools::{CallToolRequest, CallToolResult};

let request = Request::new(Id::Number(1), "tools/call")
    .with_params(serde_json::json!({"name": "fs_read", "arguments": {"path": "a.txt"}}));
let call: CallToolRequest = request.parse_params()?;
assert_eq!(call.argument("path").expect("path"), "a.txt");

let result = CallToolResult::text("ok");
assert_eq!(result.is_error, Some(false));
# Ok::<(), tpt_mcpbox_protocol::ProtocolError>(())
```

## Using the crate

The crate is not yet published to crates.io. Depend on it by path from inside
the workspace:

```toml
[dependencies]
tpt-mcpbox-protocol = { path = "../tpt-mcpbox-protocol" }
```

The minimum supported Rust version is **1.85**, the same as the workspace.

## Testing

```console
cargo test -p tpt-mcpbox-protocol
```

The unit tests include round-trip serde tests for every module and tests for
both transports.

## Scope

In scope: wire types, strict validation of incoming messages, transports, and
session state.

Out of scope: deciding whether a call is allowed (`tpt-mcpbox-policy`), running
tool code (`tpt-mcpbox-runtime`), and proxying to upstream servers
(`tpt-mcpbox-proxy`).

## License

Dual licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT), at your option.

[mcp]: https://modelcontextprotocol.io
