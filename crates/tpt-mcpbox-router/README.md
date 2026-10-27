# tpt-mcpbox-router

Request routing for [tpt-mcpbox](../../README.md). The router merges the tools,
resources and prompts from the local Wasm runtime and from every proxied
upstream into one namespaced view. It applies rate limits and drains in-flight
work on shutdown.

> **Status: pre-release (0.1.0 in progress).** The API may change before 0.1.0.
> See [todo.md](../../todo.md) for open items.

## Responsibilities

| Area | Item | What it does |
|---|---|---|
| Routing | `Router` | Holds the local tools (`add_wasm`) and upstream servers (`add_upstream`), and dispatches `call` to the right one |
| Aggregation | `Router::list`, `list_resources`, `list_prompts` | Returns one namespaced view across all sources |
| Limits | `Limiter`, `Limits`, `Permit`, `Rejection` | Per-tool and per-client rate and concurrency limits |
| Shutdown | `Lifecycle`, `InFlight`, `Drain`, `ShuttingDown` | Refuses new calls once shutdown starts, and waits for in-flight calls up to a timeout |
| Metrics | `Metrics` | Counts calls by outcome, for the Prometheus endpoint |
| Errors | `RouterError` | Each error reports an `outcome()` label used by metrics and audit |

A successful call returns a `ToolOutput`.

## Namespacing

Every tool, resource and prompt is exposed under a name that says where it came
from. A call is sent to the owner of that name. Two sources cannot shadow each
other: the router refuses a duplicate name when a source is added. Upstream
registration is all-or-nothing, so a collision adds none of that upstream's tools.

## Limits and shutdown

- `Limiter` enforces both a rate and a concurrency limit. A call that is over a
  limit is refused with a `Rejection` before any work starts.
- `Router::shutdown(timeout)` stops new calls, waits for in-flight calls up to
  `timeout`, and returns a `Drain` value that says whether everything finished.
  The hub stops reading requests as soon as shutdown begins, so a `SIGINT` or
  `SIGTERM` does not cut a call off half-way.

## Auditing

`Router::with_audit` attaches an `AuditLog`. Every call is then recorded in the
hash-chained audit log.

## Using the crate

The crate is not yet published to crates.io. Depend on it by path:

```toml
[dependencies]
tpt-mcpbox-router = { path = "../tpt-mcpbox-router" }
```

The minimum supported Rust version is **1.85**.

## Testing

```console
cargo test -p tpt-mcpbox-router
```

The tests cover dispatch to each source, limiter decisions, and the shutdown
drain.

## Scope

In scope: choosing where a call goes, limiting it, recording it, and shutting
down cleanly.

Out of scope: deciding whether a call is allowed (`tpt-mcpbox-policy`), running
Wasm code (`tpt-mcpbox-runtime`), talking to upstream servers
(`tpt-mcpbox-proxy`), and the wire format (`tpt-mcpbox-protocol`).

## License

Dual licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT), at your option.
