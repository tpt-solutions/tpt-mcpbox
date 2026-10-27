# tpt-mcpbox-proxy

A policy-enforcing passthrough for external MCP servers, used by
[tpt-mcpbox](../../README.md). It lets an agent use upstream servers you did not
write, under the same policy that governs local tools.

Upstreams are reached in one of two ways:

- **stdio**: a child process that the proxy spawns and supervises. It speaks
  newline-delimited JSON-RPC.
- **Streamable HTTP**: an endpoint reached over HTTP or HTTPS.

Every forwarded call is checked by the policy engine **before** it leaves the
process. A denied call is never sent upstream.

> **Status: pre-release (0.1.0 in progress).** The API may change before 0.1.0.
> See [todo.md](../../todo.md) for open items.

## Components

| Item | Purpose |
|---|---|
| `Connection` | One upstream, either `Stdio(Client)` or `Http(HttpClient)`. Gives tools, resources and prompts the same interface for both transports. |
| `PolicyGate` | Wraps a `Connection` and asks the policy before each forwarded call. `check_tool_call` is the pure decision step. `call_tool`, `read_resource` and `get_prompt` run the full check. |
| `ProxyError` | `Denied { rule_id, reason }` when policy refuses, or `Upstream` when an allowed call fails. |
| `Client` / `UpstreamOptions` / `UpstreamError` | The stdio upstream: spawning, initialisation and request correlation |
| `HttpClient` | The Streamable HTTP upstream, with session id tracking |
| `ops` | MCP operations shared by both transports, behind the `RpcChannel` trait |

## How a call flows

1. The router asks the gate to forward `tools/call` for an upstream tool.
2. `PolicyGate` builds a `PolicyInput` with the tool name and arguments, and asks
   the policy for a `Decision`.
3. If the decision is a deny, the gate returns `ProxyError::Denied` with the rule
   id and a reason that is safe to show the agent. Nothing is sent upstream.
4. If the decision is an allow, the call goes to the upstream through
   `Connection`. An upstream failure comes back as `ProxyError::Upstream`.

Upstream stderr is passed through the secret `Redactor` before it is logged, so
a secret that an upstream prints does not end up in the logs.

## Using the crate

The crate is not yet published to crates.io. Depend on it by path:

```toml
[dependencies]
tpt-mcpbox-proxy = { path = "../tpt-mcpbox-proxy" }
```

The minimum supported Rust version is **1.85**.

## Testing

```console
cargo test -p tpt-mcpbox-proxy
```

The tests cover the gate's allow and deny paths, both transports, and the
redaction of upstream stderr.

## Scope

In scope: forwarding MCP operations to upstream servers under policy, and
supervising stdio children.

Out of scope: deciding the policy itself (`tpt-mcpbox-policy`), aggregating
local and upstream tools into one view (`tpt-mcpbox-router`), and running Wasm
tools (`tpt-mcpbox-runtime`).

## License

Dual licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT), at your option.
