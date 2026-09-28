# Architecture

This document is the map of the system: what the pieces are, how data flows,
and -- most importantly -- where the trust boundaries are. It is kept current
with the code; see [todo.md](../todo.md) for the implementation phases.

## 1. Component view

```
                    +---------------------------+
   AI agent  <--->  |  tpt-mcpbox-protocol      |   stdio (NDJSON)
  (Claude Code,      |  transports + session +  | <-> MCP Streamable HTTP
   MCP Inspector,    |  dispatch + JSON-RPC      |
   your harness)     +------------+--------------+
                                  |
                          handled messages
                                  v
                    +---------------------------+
                    |  tpt-mcpbox-router        |  aggregation, namespacing,
                    |  namespaced aggregation   |  per-tool/per-client limits
                    +------------+--------------+
                                  |
                    +-------------v--------------+
                    |  tpt-mcpbox-policy        |  deny-by-default decision
                    |  YAML DSL / embedded Rego |  (+ reason + rule id)
                    +------+--------------+------+
                           | allow         | deny -> structured error + audit entry
            +--------------v------+        |
            |  tpt-mcpbox-runtime |        |        +----------------------+
            |  wasmtime pool,    |        +------->| tpt-mcpbox-proxy     |
            |  WASI capability   |  forwarded         | upstream MCP client|
            |  mapper, limits    |  (policy-checked)  | stdio + HTTP       |
            +------+-------------+                     +---------+--------+
                   |                                                 |
                   v                                                 v
        +--------------------+                          +---------------------+
        | Wasm tools (guest) |                          | upstream MCP servers|
        | github, fs, custom |                          | (untrusted)        |
        +--------------------+                          +---------------------+

   cross-cutting: tpt-mcpbox-config (schema, secrets), tpt-mcpbox-audit
   (hash-chained log, metrics, tracing), tpt-mcpbox-cli (binary), tpt-mcpbox-sdk (guest)
```

## 2. Trust boundaries

| # | Boundary | What must never cross it |
|---|----------|--------------------------|
| B1 | Agent -> hub | Anything the policy denies: unlisted hosts, unlisted paths, secret values. Agent-supplied arguments are **untrusted input** everywhere downstream. |
| B2 | Hub -> Wasm guest | Ambient authority: no env vars, no unlisted preopens, no unlisted sockets, no clock/random entropy beyond policy. Only what B3 grants. |
| B3 | Guest -> network | Direct sockets. All egress passes through the host's `wasi:http/outgoing-handler`, which enforces the domain allowlist and injects secret headers. |
| B4 | Hub -> upstream server | Anything the policy denies; upstream responses are untrusted and are re-validated before reaching the agent. |
| B5 | Hub -> logs/metrics/audit | Secret **values**. Names, ids, decisions and hashes only. |
| B6 | Wasm guest -> host process | Memory safety and resource limits: no `unsafe` in our crates, memory/time/fuel caps, trap-to-error conversion. |

`crates/tpt-mcpbox-protocol` deliberately sits *below* B1 enforcement: it frames
and validates messages and owns the session state machine, but never decides
what is allowed. If a parsing bug could grant authority, the layering is wrong.

## 3. Data flow: one `tools/call`

1. **Decode.** A transport reads a frame (NDJSON line or HTTP body with
   `Mcp-Session-Id`), classifies it as request/notification/response, and
   validates `"jsonrpc": "2.0"` (B1).
2. **Session gate.** `Dispatcher` refuses anything but `initialize` until
   `notifications/initialized` arrives; `ping`, `logging/setLevel` and
   `shutdown` are handled in-protocol. Everything else reaches the router.
3. **Resolve.** The router maps the tool name to its origin: local Wasm tool,
   or an upstream behind a prefix/rename.
4. **Policy.** `tpt-mcpbox-policy` evaluates caller identity, tool, method,
   arguments, target host and fs paths, returning allow / deny /
   allow-with-constraints plus a reason and rule id. Deny is the default.
5. **Limit.** Per-tool and per-client rate and concurrency limits are applied;
   rejections are structured overload errors, not silent drops.
6. **Execute.**
   * *Wasm*: the pool checks out a pre-instantiated component; the `Store` is
     built from the policy decision (preopens, `wasi:http` allowlist, memory
     and table caps); an epoch deadline bounds execution; traps become
     structured tool errors.
   * *Upstream*: the proxy issues the forwarded call with only the capabilities
     the policy granted.
7. **Secrets (B3/B5).** For Wasm tools the host injects configured headers at
   the proxy layer. The guest never holds the token. The audit entry records the
   secret *name*.
8. **Audit + metrics.** The decision, duration, outcome and chain hash are
   appended to the tamper-evident log; counters feed `/metrics`.
9. **Respond.** The result travels back over the same transport; notifications
   (progress, list-changed) go to the session's outbound stream, which the
   stdio writer serializes or the HTTP server turns into SSE events.

## 4. Transport notes

### stdio
- One JSON object per line. `serde_json` escapes control characters, so a
  message can never contain a raw newline.
- A single task owns the write half; responses, notifications and
  server-to-agent requests all funnel through one channel, so frames cannot
  interleave.
- Line length is capped by the codec (`LinesCodec::new_with_max_length`), so a
  hostile agent cannot force unbounded buffering.
- Logs go to **stderr**; stdout carries protocol only.

### Streamable HTTP
- `POST /mcp`: JSON in, JSON out (single object, or array for batches); `202`
  for notification-only payloads. The session id is issued with `initialize`.
- `GET /mcp`: SSE stream with monotonic event ids; `Last-Event-ID` replays from
  a bounded ring buffer, so a dropped connection loses nothing recent.
- `DELETE /mcp`: terminates the session (state -> Closed).
- Origin validation defaults to loopback-only (DNS-rebinding protection);
  widen only behind an authenticating proxy.
- Body size is capped; oversized payloads yield `-32801`.

## 5. Session and dispatcher

```
   agent                     dispatcher                       handler (router)
     |  initialize -------------->|  negotiate version + caps        |
     |<-- initialize result -------|                                 |
     |  notifications/initialized->|  state: Initializing -> Ready   |
     |  tools/call --------------->|  ensure_servable --------------->|
     |<-- result ------------------|  error shaping <-- decision -----|
     |  (response to our request) ->|  resolve pending oneshot        |
     |  GET /mcp (SSE) <----------|  notifications + server requests|
```

Server-to-agent calls (`roots/list`, `sampling/createMessage`,
`elicitation/create`) are refused locally when the agent did not advertise the
capability, and are bounded by a timeout, so a silent agent cannot wedge the
proxy.

## 6. Crate dependency direction

```
tpt-mcpbox-protocol
        ^
        |  tpt-mcpbox-config
        |        ^
        |  tpt-mcpbox-policy
        |        ^
        |  tpt-mcpbox-runtime <--- tpt-mcpbox-proxy
        |        ^                     ^
        +--------+---------------------+
                 |
           tpt-mcpbox-router
                 ^
                 |
           tpt-mcpbox-cli   (also: tpt-mcpbox-audit)
```

Dependencies point one way. `tpt-mcpbox-protocol` depends on nothing internal;
guest crates (`tpt-mcpbox-sdk`, `tpt-mcpbox-tool-*`) are outside the workspace
and build for `wasm32-wasip2` with `cargo-component`.

## 7. Invariants worth stating out loud

1. **Deny by default.** An empty or missing policy denies everything.
2. **Schemas are documentation, not authority.** A tool's `inputSchema` is
   written by the tool author; only the policy engine decides.
3. **Annotations are not permissions.** `readOnlyHint: false` grants nothing.
4. **Secrets never enter the guest or the logs.**
5. **A parser bug must not become an authorization bug.** Hence the layering.
6. **Traps are errors, not crashes.** A misbehaving tool degrades one call.
7. **Everything consequential is audited** with a verifiable hash chain.

