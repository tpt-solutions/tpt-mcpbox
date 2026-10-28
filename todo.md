# tpt-mcpbox — Project Task Checklist

Local-first, zero-trust MCP proxy + WebAssembly tool runtime (Rust). See [spec.txt](spec.txt).

**License:** dual `MIT OR Apache-2.0` — © TPT Solutions.

**Naming:** every crate is `tpt-mcpbox-<name>`; the binary is `tpt-mcpbox`
(so `tpt-mcpbox run`, `tpt-mcpbox audit verify`, ...). Guest crates
(`tpt-mcpbox-sdk`, `tpt-mcpbox-tool-github`, `tpt-mcpbox-tool-fs`) live outside
the host workspace and build for `wasm32-wasip2` with `cargo-component`.

**Last updated:** 2026-10-28 — agent cancellation (`notifications/cancelled`), per-request timeout (`server.request_timeout`), audit finish records for dropped calls, idle client gate sweep, argument-traversal policy tests; workspace tests and clippy pass. Earlier: 2026-10-27 — tracing/logging config, shell completions and man pages, security model and integration docs, fuzz targets and CI jobs added; workspace tests, clippy and fmt pass. Earlier: 2026-10-15 — Phase 0 complete, Phase 1 (protocol core)
implemented with 109 passing tests; Phase 2 (config & secrets) largely
implemented with 73 passing config tests (open: SIGHUP, central redaction
wiring); Phase 3 YAML DSL evaluator landed with 25 passing policy tests (Rego,
constraints and reload wiring open); Phases 4–12 outstanding.

---

## Scope decisions

| Area | Decision |
|---|---|
| Hub scope | Both: local Wasm tool runtime **and** policy-enforcing passthrough proxy to external MCP servers |
| Policy engine | Both a simplified YAML DSL (default) **and** embedded Rego (via `regorus`, pure-Rust) |
| Agent-facing transports | stdio **and** MCP Streamable HTTP |
| Tool SDK | Ship a Rust guest SDK crate **and** build the `github` + `fs` example tools |
| Secrets source | Proxy environment + gitignored `.env` file; config maps secret → outbound header |
| Wasm network model | Standard `wasi:http/outgoing-handler`; host intercepts, enforces domain allowlist, injects secret headers |
| Tool packaging | Local `.wasm` file paths **and** OCI-registry pull, both with hash/signature verification |
| Release platforms | Linux x86_64, macOS arm64 + x86_64, Windows x86_64 |
| MCP surface | Full parity — tools, resources, prompts, completions (Wasm-exposed and proxied) |
| Observability | Structured tracing/logs, tamper-evident hash-chained audit log, Prometheus metrics, criterion benchmark harness |
| Rate limiting | Per-tool **and** per-client (rate + concurrency) |
| Distribution | GitHub Release binaries (per platform + checksums) and crates.io |

### Technical defaults

- Async runtime `tokio`. Wasm via `wasmtime` component model + WASI Preview 2; tools are Wasm **components** with a project-defined WIT world.
- Cargo workspace crates (host): `tpt-mcpbox-cli` (binary `tpt-mcpbox`), `tpt-mcpbox-protocol`, `tpt-mcpbox-config`, `tpt-mcpbox-policy`, `tpt-mcpbox-runtime`, `tpt-mcpbox-proxy`, `tpt-mcpbox-router`, `tpt-mcpbox-audit`. Guest crates (own workspaces, `workspace.exclude`): `crates/tpt-mcpbox-sdk`, `tools/tpt-mcpbox-tool-github`, `tools/tpt-mcpbox-tool-fs`.
- MCP protocol revision: `2025-06-18` (see `tpt-mcpbox-protocol::shared::SUPPORTED_PROTOCOL_VERSIONS`).
- CI: GitHub Actions. Release automation: `cargo-dist` + `release-plz`/`git-cliff`.

---

## Phase 0 — Bootstrap & Governance

- [x] `git init`; add `.gitignore` (Rust, `.env`, `target/`, `*.wasm` build output, OCI cache)
- [x] Create Cargo workspace with member crate skeletons listed above (guest crates deferred to Phases 7/8)
- [x] `rust-toolchain.toml`; set and document MSRV (**1.85**, enforced by the CI `msrv` job)
- [x] Dual licensing: `LICENSE-MIT`, `LICENSE-APACHE`, `license = "MIT OR Apache-2.0"` in every `Cargo.toml`, copyright "TPT Solutions"
- [x] `README.md` (overview, status, quickstart placeholder, license, contribution note)
- [x] `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` (disclosure policy), `CHANGELOG.md`
- [x] `NOTICE` / per-file SPDX headers convention documented
- [x] CI: `fmt`, `clippy -D warnings`, `test`, `cargo-deny` (licenses/advisories/bans), `cargo-audit`
- [x] CI matrix across the 4 target platforms (`cross` job: check on Linux x86_64, macOS arm64/x86_64, Windows x86_64; native test job on Linux/macOS/Windows)
- [x] `.editorconfig`, `rustfmt.toml`, `clippy.toml`
- [x] GitHub issue/PR templates, `CODEOWNERS`
- [x] `docs/architecture.md` — component diagram + data-flow from spec, kept current

## Phase 1 — MCP Protocol Core (`tpt-mcpbox-protocol`)

- [x] JSON-RPC 2.0 types: request / response / notification / batch / error codes (`jsonrpc`)
- [x] MCP message types: `initialize`/`initialized`, capabilities negotiation, `ping`, shutdown (`model`, `session`)
- [x] `tools/list` (+ pagination), `tools/call`, `notifications/tools/list_changed` (`tools`)
- [x] `resources/list`, `resources/read`, `resources/templates/list`, `subscribe`/`unsubscribe`, `list_changed`, `updated` (`resources`)
- [x] `prompts/list`, `prompts/get`, `notifications/prompts/list_changed` (`prompts`)
- [x] `completion/complete` (`completion`)
- [x] Utilities: progress notifications, `notifications/cancelled`, logging (`logging/setLevel`, `notifications/message`) (`utilities`)
- [x] Client-feature passthrough plumbing: `roots`, `sampling/createMessage`, `elicitation` (routed to agent) (`server::Dispatcher`)
- [x] stdio transport (newline-delimited JSON, stderr for logs)
- [x] Streamable HTTP transport: `POST /mcp`, SSE response streams, `Mcp-Session-Id`, resumable event IDs, `GET` stream, `DELETE` session, origin validation
- [x] Content types: text / image / audio / embedded resource / resource links (`content`)
- [x] Round-trip serde tests across every module (110 tests: envelope, model, content, session, dispatcher, both transports)
- [x] Conformance test suite vs. the MCP JSON Schema (fixtures + schema validation) — **done:** `tests/conformance.rs` validates our serialized results and JSON-RPC responses against the vendored 2025-06-18 schema (11 tests, with a negative control).
- [x] Fuzz targets for the JSON-RPC parser (Phase 11) — **done:** `fuzz/fuzz_targets/jsonrpc_parse.rs`.
- [ ] Manual interop check against a real MCP client (Claude Code / MCP Inspector) — **blocked here:** the MCP Inspector CLI could not be run in this environment (the run was denied as an external npm package). Needs a run by hand.

## Phase 2 — Configuration & Secrets (`tpt-mcpbox-config`)

- [x] `tpt-mcpbox.yaml` model (`model`, `units`): `tools[]` (name, source, capabilities, secrets, limits, rate limits), `upstreams[]`, `server` (transports, bind), `policy`, `audit`, `metrics`, `logging`
- [x] Capability schema (`model::Capabilities`): `network` (domain allowlist), `filesystem.read/write` (glob lists), `memory_limit`, `time_limit`, `env` allowlist
- [x] Loader + strict validation + helpful diagnostics; emit JSON Schema for editor support (`load`, `validate`, `schema`)
- [x] Config discovery (`--config`, `$MCPBOX_CONFIG`, CWD, XDG/`%APPDATA%`), layering (`tpt-mcpbox.local.yaml` overlay adds tools/upstreams only), defaults
- [x] Secrets (`secrets::SecretStore`): load from process env + gitignored `.env`; `secret → header` mapping (e.g. `GITHUB_TOKEN` → `Authorization: Bearer …`)
- [x] `SecretString` wrapper: zeroize on drop, `Debug`/`Display` redaction, never serialized
- [~] Central redaction filter applied to logs, error messages, audit entries (`secrets::Redactor` implemented; **done for upstream stderr** in the proxy, and **for every agent-facing reply** (tool output, error text, upstream messages) via `ToolHandler::with_redactor`, verified end to end). **Open:** global `tracing` layer, audit entries (Phase 9).
- [ ] Hot reload: watch config, atomic swap, `SIGHUP` (Unix) / equivalent; reload-safe pool draining (`reload::watch_config` polling watcher + validate-before-swap `ReloadHandle` done; `SIGHUP` and pool draining outstanding, latter needs Phase 4)
- [x] `tpt-mcpbox validate` command (plus `tpt-mcpbox schema`)

## Phase 3 — Policy Engine (`tpt-mcpbox-policy`)

> **Status:** complete except where noted. `tpt-mcpbox-policy` composes the YAML
> DSL and an embedded Rego module (`regorus`, no `std` feature, so no Spectre
> libraries are needed) into one `Policy`. Opinions combine as: any deny wins,
> then any allow admits with the tightest limits, then `policy.default`.
> Still open: wiring `Policy::reload` into the config `ReloadHandle` (needs the
> runtime in Phase 4 to be useful); the runtime enforcement of allow-time limits
> (Phase 4).

- [x] Policy input schema: caller identity (`caller`), tool, method, arguments, host, fs path, resource URIs (`uris`)
- [x] Decision type: allow / deny / allow-with-constraints + reason + rule id (`Decision::constraints` carries memory/time limits and the quota)
- [x] Deny-by-default evaluation; explicit precedence: DSL rules in file order, then Rego; any deny wins; `policy.default` only when no evaluator has an opinion
- [x] YAML DSL evaluator: tool + method + argument predicates, caller globs, host/path/URI globs, per-caller sliding-window quotas
- [x] Rego evaluator via `regorus`: `package tpt.mcpbox`, `allow` query, stable input document (`PolicyInput` as JSON); evaluation errors and undefined `allow` fail closed
- [x] Engine selection per policy; combine YAML + Rego conservatively (most restrictive wins)
- [x] Decision cache keyed on normalized input; quota outcomes are never cached; `Policy::reload` builds a fresh engine and carries quota counters over for surviving rules
- [x] Dry-run / audit-only mode (log what would be denied without blocking) — engine reports `would_be` and reason; writing the audit entry is Phase 9
- [x] Tests: allow/deny matrices, glob edge cases, path traversal, Unicode look-alike hosts, URI normalisation, `regorus` fixtures (allow, deny, undefined, error, input shape), quotas, reload, generated-input property test (57 policy tests; 77 config tests cover the new rule validation)


## Phase 4 — Wasm Runtime (`tpt-mcpbox-runtime`)

> **Status:** built and tested against a real guest component (`tests/guest`,
> built for `wasm32-wasip2` by the test harness). 22 integration tests and 24
> unit tests pass. Open items are marked below and in the summary.

- [x] `wasmtime` engine config: component model on, epoch interruption (10 ms tick), pooling allocator (256 instance slots, 256 MiB max per memory). Fuel: not used.
- [x] Define WIT world for tools (`wit/tool.wit`, `tpt:mcpbox/tool`: exports `describe` and `call`). Imports are the WASI interfaces the host links (`wasi:cli`, filesystem, clocks, random, `wasi:http`), each granted only as far as the tool's capabilities allow.
- [ ] Module source loaders: local path ✓; OCI pull (`oci-client`/`oci-distribution`) with local content-addressed cache — **open**: a tool with `oci_ref` is refused with `ToolError::Unsupported`.
- [x] Integrity: SHA-256 pin per tool, refused on mismatch before compilation (bytes are read once and the same buffer is compiled). Unpinned modules load with a warning that prints the digest.
- [ ] Optional signature verification (`sigstore`/`minisign`) — **open**.
- [x] Warm instance pool: pre-instantiated at load, checkout/checkin, cap = `limits.max_concurrent_calls` (default 4), recycled after 256 calls or on any fault.
- [~] Per-call `Store` with `ResourceLimiter`: deviation — stores are per pooled instance and reused across calls until recycled, with per-call deadline and cancellation reset on each call. Memory, instance, table and memory-count caps are applied via `StoreLimits`. Guest memory can persist between calls within one recycle window; set `recycle_after` lower for stricter isolation (currently fixed at 256, not yet configurable).
- [x] Execution timeout via epoch deadline (`capabilities.time_limit`, default 10 s, interrupted within one tick); cooperative cancellation via `CancelToken` (wiring to `notifications/cancelled` is Phase 5).
- [x] WASI capability mapper: filesystem grants become preopened directories named relative to the grant (no host paths); env exposes only granted, set variables; no stdio, args, raw sockets, or name lookup. **Caveat:** a grant preopens its fixed directory, so `workspace/*.md` exposes all of `workspace/` to the guest. Recorded as a residual risk.
- [~] `wasi:http` outbound handler: host allowlist (normalised, case-insensitive globs), HTTPS only, default port only, userinfo tricks refused, hop-by-hop and `Connection`-named headers stripped, secret headers injected (overwriting any guest value, marked sensitive), connect/first-byte/between-bytes timeouts clamped to the tool's time limit, declared `Content-Length` capped at 16 MiB. **Open:** response body size is not capped (the outbound future does not expose the body stream), DNS-rebinding and private-address (SSRF) checks are not applied yet: `outbound::is_internal_address` classifies internal addresses and is tested, but is not wired to connections, so an allowlisted name that resolves to a private address is still not blocked.
- [x] Deny all other ambient authority (no env beyond grants, no unlisted sockets, no inherited stdio).
- [x] Panic/trap isolation: traps, OOM, timeouts, cancellation and host panics become structured `ToolError`s; the instance is discarded, the runtime keeps serving.
- [x] Startup self-test: `Runtime::self_test(probe_wasm, probe_path)` loads a probe with no grants and asserts the file read, outbound request and environment are all refused. Wiring into `tpt-mcpbox run` is Phase 10.
- [x] Criterion benchmark: `benches/invocation.rs` measures a warm echo call. CI regression threshold (< 5 ms median) is enforced by the `bench` CI job — see the Phase 9 benchmark item.


## Phase 5 — Router & Rate Limiter (`tpt-mcpbox-router`)

- [x] Dispatch `tools/call` to Wasm runtime or an upstream proxy target by tool origin — **done for tools:** `dispatch::Router::call` routes to Wasm (run on a blocking thread, policy-checked there) or to a `PolicyGate`, after the shutdown gate and limiter (7 tests). Resources and prompts route too (see below). Cancellation is wired: `notifications/cancelled` drops the call's future and the router's stop guard signals the guest (see the cancellation item below).
- [~] Namespaced aggregation: merge `tools`/`resources`/`prompts` from Wasm + all upstreams; prefix/rename on conflict; `list_changed` fan-in — **done for tools:** `<prefix><name>` for upstreams, all-or-nothing refusal on conflict (no silent rename). **Resources and prompts aggregated:** resources by URI (duplicate URIs refused), prompts as `<prefix><name>`. **Resource templates done:** `resources/templates/list` is aggregated, and a read that matches no exact URI is routed to the upstream whose `{name}` / `{+name}` template expands to it (matcher tests in `templates.rs`). **Open:** subscriptions, `list_changed` fan-in.
- [~] Per-tool rate limit + max concurrency; per-client (session) rate limit + concurrency; queue vs reject policy — **done:** `limiter::Limiter` (token bucket + semaphore per tool and per client, all-or-nothing admission, 9 tests). Reject-only; queue-and-wait **open**. Idle client gates are swept every 60 s; a gate is dropped only when no call holds a slot and its bucket has refilled, so a sweep never resets a client's budget (3 sweep tests).
- [~] Global request timeout, backpressure, structured overload errors — **timeout done:** `server.request_timeout` caps each `tools/call` end to end; on expiry the tool is cancelled, the agent gets a tool error, and the audit outcome is `timed_out` (2 tests). **Open:** backpressure, structured overload errors.
- [~] Graceful shutdown: stop accepting, drain in-flight, checkpoint audit log — **done:** `lifecycle::Lifecycle` (`begin` gates new calls, `shutdown(timeout)` drains with `Drain::{Completed, TimedOut}`, 5 tests). Audit checkpoint **open** (Phase 9).
- [~] Cancellation + progress propagation across router boundary — **cancellation done:** the stdio read loop no longer waits for a call before reading the next message, so `notifications/cancelled` is applied while the call runs (the cancelled request gets no reply, per the spec). Dropping the call's future signals the runtime, which stops the guest within one epoch tick; the audit log still gets a `finish` record with outcome `cancelled` (3 protocol tests, 1 router guard test, 1 audit test). The guest-level stop is covered by the existing runtime test. **Open:** progress notifications across the router.

## Phase 6 — Passthrough Proxy (`tpt-mcpbox-proxy`)

- [~] MCP client for upstreams: stdio (spawn + supervise child process) and Streamable HTTP — **done:** stdio client `upstream::Client` (spawn with cleared env, kill-on-drop, id-correlated requests, timeouts; 10 tests). Streamable HTTP client `http::HttpClient` (JSON and SSE replies, `Mcp-Session-Id` echo, configured headers; 7 tests against an axum fake). HTTPS via `hyper-rustls` (rustls 0.23, `ring`, `webpki-roots` trust roots); plain `http://` only to loopback addresses. An ignored network test confirms a real TLS handshake. Both share `ops::{initialize, list_tools, call_tool}` via `RpcChannel`. **Cancellation forwarded on stdio:** when a caller stops waiting for an upstream call (dropped, or timed out), the stdio client sends `notifications/cancelled` for that request id (2 tests). The HTTP client does the same with a detached `POST` (1 test). Stdio restart is covered by the lifecycle item below. **Open:** server-initiated requests over HTTP GET stream.
- [~] Upstream lifecycle: launch, `initialize` handshake, health check, restart with backoff — **done:** launch and handshake (version check); restart with exponential backoff (1 s doubling to 60 s) when a stdio peer closes. `proxy::supervise` swaps the new connection into the gate, and the respawn re-runs the handshake and refuses a replacement with a different tool list (3 proxy tests). End to end, the CLI tests run a real child (`examples/fake_upstream.rs`): a crashed child is restarted and serves calls again, and a restart that changes the tool list is refused while the supervisor keeps retrying (2 tests in `serve.rs`). **Health check added (stdio):** an idle stdio upstream is pinged every 30 s; a ping with no reply within 10 s replaces the connection, which kills the hung child. Pings are skipped while calls are outstanding (3 supervisor tests, including a hung-upstream replacement and a busy-upstream exemption). **Open:** HTTP reconnection and HTTP health checks.
- [ ] Capability reconciliation between agent, proxy, and each upstream
- [~] Enforce policy on every proxied call: inspect `tools/call` args, `resources/read` URIs, `prompts/get` args — **done for `tools/call`:** `gate::PolicyGate` denies before anything is sent (3 tests). **Open:** `resources/read` URIs, `prompts/get` args.
- [~] Tool/resource/prompt filtering: allowlist/denylist, rename, description overrides — **done:** tools keep `allow`/`deny` and gain `tools.rename` and `tools.describe`; prompts gain `prompts.allow`/`deny`/`rename`/`describe`; resources gain `resources.allow`/`deny` by URI, which also hides resource templates. Renames and overrides that name an unlisted item fail at startup, and the call still reaches the upstream's own name (router test, config and serve tests). **Open:** description overrides for resources.
- [~] Full-parity forwarding: resources (list/read/templates/subscribe/updated), prompts (list/get), `completion/complete` — **done:** `resources/list`, `resources/read`, `prompts/list`, `prompts/get` through the router and proxy, with policy checks (URI rules and method rules) and audit records; upstreams are asked only for the capabilities they advertise (4 tests in router, 3 in proxy). **Templates done** (see the router item). **Completion done:** `completion/complete` routes a prompt argument to the owning upstream under its own name, and a resource-template variable to the upstream that owns the template; both are policy-checked and audited (2 router tests). **Open:** subscribe/updated.
- [ ] Forward client features to upstream where needed (`roots`, `sampling`) with policy gate
- [ ] Redact/scan upstream responses per policy (optional secret/PII pattern check)

## Phase 7 — Guest Tool SDK (`tpt-mcpbox-sdk`)

- [x] Guest crate targeting the tool WIT world; re-export needed `wasi` bindings
- [~] Tool definition: **done as a `Tool` trait plus `export_tools!` macro_rules** (name, description, schemars schema from the argument type, typed `run`), not a `#[tool]` attribute macro, so no proc-macro crate is needed. Verified: a hello component lists its schema and returns typed results through the hub. **Open:** a `#[tool]` attribute sugar if wanted.
- [~] Ergonomic HTTP helper over `wasi:http` (JSON get/post, error mapping) **Done:** `http::get_json` and `post_json`, with status and JSON error mapping. The denied-without-grant path is verified; a granted successful call is not yet, since it needs a reachable HTTPS endpoint.
- [~] Structured tool errors + result content builders — **done:** text and JSON results, `ToolError` with `isError` reporting. **Open:** resource content blocks.
- [ ] Optional resource/prompt provider traits (full parity)
- [x] `cargo component`-based project template + `tpt-mcpbox init tool` generator — **done:** `init tool <DIR> --sdk-path <PATH>` writes a starter project (path dependency on the SDK, since it is not published); the scaffold builds for wasm32-wasip2 and runs through the hub. Uses a plain cdylib build, not `cargo component`.
- [~] SDK doc page + a "hello world" tool walkthrough **Done:** `crates/tpt-mcpbox-sdk/README.md` and `examples/hello` (greet, add, fetch).

## Phase 8 — Example Tools (`tools/`)

- [~] `tools/tpt-mcpbox-tool-github`: search repos/code via `api.github.com`; relies on proxy-injected `GITHUB_TOKEN` header; no secret in guest **Done:** `search_repos` (percent-encoded query, compact result). Verified: the host injected the token (GitHub answered `401 Bad credentials` for a bogus one) and the token is absent from logs and audit. A search with a real token is not run here. Denied without a network grant.
- [~] `tools/tpt-mcpbox-tool-fs`: read within `./workspace/**`, write within `./workspace/output/**`, enforced by preopens **Done:** `read_file`, `list_dir`, `write_file`. Verified: reads and output writes work; `..`, absolute paths and writes outside the output directory are refused. The guest checks are advisory; the host preopens are what enforce.
- [~] Build both to `.wasm` in CI; publish as release assets — the `guest` CI job builds both (its paths are fixed, but it is still `continue-on-error`). **Open:** uploading the modules as artifacts, and release assets.
- [~] Use both as end-to-end integration fixtures (policy allow + deny paths) — **done for `tools/tpt-mcpbox-tool-fs`:** `crates/tpt-mcpbox-cli/tests/fs_tool.rs` builds the tool for wasm32-wasip2 and drives it through `tools call` with an allow policy (read, in-grant write, traversal refused by the tool) and a read-only policy (write denied by policy), then verifies the audit chain. It skips with a message when the wasm target is not installed. **Open:** the github tool with a real token, and the same automated check for the github tool. Note: a write path is relative to the granted directory, so `write_file` takes `a.md`, not `output/a.md`.
- [x] Sample `tpt-mcpbox.yaml` matching the spec's configuration example **Done:** `examples/tpt-mcpbox.yaml`, with `time_limit`, a hash-pin note, and a test that it passes serve validation.

## Phase 9 — Observability (`tpt-mcpbox-audit` + runtime hooks)

- [x] `tracing` setup: JSON + pretty subscribers, `RUST_LOG`/config level, per-request span with tool, decision, duration — **done:** `run` installs the stderr subscriber from `logging` (`level`, `json`, `spans`), `RUST_LOG` overrides the level. Each `tools/call` runs in a `request` span carrying `kind`, `caller`, `subject`, `outcome`, `rule_id` and `duration_ms`; only names and outcomes go on it, never argument values. Not yet exercised end to end through a live hub.
- [~] Tamper-evident audit log: append-only, per-entry hash chain (prev-hash), entries for every tool call, policy decision, secret injection (name only), upstream spawn, config reload — **done:** `chain::AuditLog` (JSON lines, SHA-256 chain over canonical data, fsync per append, refuses to extend a broken log) and `chain::verify` (7 tests). **Tool calls are recorded:** `Router::with_audit` writes a `start` entry before dispatch (refusing the call if that write fails) and a `finish` entry with outcome and rule id. Argument values are never recorded, only key names. Startup records: `tool_loaded` (with module digest), `upstream_connected` (transport and counts), and `secret_bound` (names only, with scope and owner). Policy decisions are recorded in each call's `finish` entry. **Open:** config reload (`run` has no hot reload yet), and per-request secret injection records. The `tpt-mcpbox audit verify` command now exists.
- [ ] Optional signing of audit segments; log rotation; `tpt-mcpbox audit verify` to check chain integrity — **open:** signing and rotation (the `audit.sign` and `audit.max_segment_bytes` config keys are parsed but not acted on). The verifier and the `audit verify` command exist. Truncation of the newest entries is not detected without an external head checkpoint.
- [~] Prometheus `/metrics`: invocation counts, latency histograms, denial counts, pool utilization, upstream health, rate-limit rejections **Done:** `GET /metrics` on `metrics.bind` (loopback only): `tpt_mcpbox_calls_total{kind,outcome}` and `tpt_mcpbox_call_duration_seconds` histograms (router metrics, 45 router tests). Tool names are never labels. Verified with curl; unknown paths return 404 and a non-loopback bind is refused. **Gauges added:** `tpt_mcpbox_calls_in_flight` (counted for the life of each call, dropped calls included) and `tpt_mcpbox_upstream_up{upstream}` for each supervised stdio upstream (set at startup and flipped by the supervisor; 2 tests). Rate-limit rejections are covered by the `outcome` label only. **Pool gauges added:** `tpt_mcpbox_tool_instances_in_use` and `tpt_mcpbox_tool_instances_capacity`, summed across Wasm tools so no tool name is a label (runtime test `pool_usage_counts_checked_out_instances`). The per-tool breakdown is not exposed, by design. **Open:** the tracing layer and per-request spans.
- [~] Benchmark harness wired to CI with regression thresholds (overhead, cold vs warm) — **done:** the `bench` CI job runs the warm-invocation benchmark and fails if the median is 5 ms or more. It ran locally, but has not yet run on the CI runners. **Open:** a cold-start benchmark.

## Phase 10 — CLI & Developer Experience (`tpt-mcpbox-cli`)

- [~] `tpt-mcpbox run` (start proxy; `--config`, `--transport`, `--dry-run`) — **done:** `run --config` builds the hub (validation, secrets, policy, audit, Wasm tools, stdio and HTTP upstreams with allow/deny globs) and serves stdio; verified end to end with the test guest and a denied call. Ctrl-C and SIGTERM stop the stdio loop and drain in-flight calls (compiled; not exercised interactively). Stdio and Streamable HTTP (`server.http.bind`) both serve; HTTP binds only to loopback and accepts loopback origins by default, or `allowed_origins`. Verified with curl: initialize, a redacted tool call, and a 403 for a disallowed origin. A second writer on the same audit log is refused by an OS file lock (`<log>.lock`), released even when the process is killed. HTTP authentication: `server.http.bearer_env` names a secret whose value clients must send as `Authorization: Bearer <token>`; the check is constant-time and applies to every bind. A non-loopback bind is refused unless a token is configured. Verified with curl on loopback and on `0.0.0.0`. **Done:** `--transport` and `--dry-run` flags. **Open:** token rotation without restart, and OAuth or per-client tokens (only one shared bearer token exists).
- [x] `tpt-mcpbox validate`, `tpt-mcpbox schema` (emit config JSON Schema)
- [x] `tpt-mcpbox policy test <input.json>` (explain a decision; exits 0 on allow, 1 on deny)
- [x] `tpt-mcpbox tools ls` / `tpt-mcpbox tools call` (local invocation for debugging; goes through the same policy, limits and audit as `run`)
- [ ] `tpt-mcpbox pull <oci-ref>` (fetch + verify a tool into cache)
- [x] `tpt-mcpbox audit verify [PATH] [--config CONFIG]` (defaults to `audit.path` from the configuration; a broken chain or missing file exits non-zero)
- [x] `tpt-mcpbox init` (scaffold config; refuses to overwrite without `--force`) / `tpt-mcpbox init tool` (scaffold SDK project)
- [x] Shell completions + generated man pages — **done:** `tpt-mcpbox completions <SHELL>` (clap_complete) and `tpt-mcpbox manpage <DIR>` (clap_mangen, one `.1` per command path, e.g. `tpt-mcpbox-tools-call.1`). Known cosmetic gap: the `.TH` title of a subcommand page shows its short name (`call`), since clap_mangen takes the title from the command name.
- [x] Integration guide: wiring tpt-mcpbox into Claude Code / Claude Desktop `mcpServers` — `docs/integration.md` (stdio and Streamable HTTP with bearer token; verify steps). Written from the config model and not yet tried against a live Claude Code session.

## Phase 11 — Security Hardening & Review

- [x] `docs/security-model.md`: threat model, trust boundaries, non-goals, residual risks — residual risks listed as R1–R11 and tied to the open items in this file.
- [~] `cargo-fuzz` targets: JSON-RPC parser, config parser, YAML DSL, WIT/host-call boundary — **done:** `fuzz/` crate with `jsonrpc_parse`, `config_load` and `policy_input` (the policy target fuzzes the input side of the YAML DSL and Rego evaluation against a fixed policy); all three type-check. A `fuzz` CI job runs each for 60 s, weekly on a schedule and on manual dispatch (not on every change). **Open:** the WIT/host-call boundary target. Not run locally: libFuzzer needs nightly and sanitizers, so the first real run is the CI job.
- [~] Sandbox-escape test suite: attempt fs/net/env access outside grants, path traversal, symlink escape, oversized alloc, infinite loop, deep recursion — **done:** ungranted files and environment, relative traversal, symlink escape (skipped, with a message, where Windows refuses to create the link), outbound hosts, runaway loops, memory limit, guest panics. **Open:** deep recursion (the test guest has no such export yet).
- [~] Secret-safety tests: assert secrets absent from logs, errors, audit payloads, panic messages, `/metrics` — **done for audit payloads** (argument values are never recorded, only key names) and for agent-facing replies, including an upstream error that echoes a credential. **Logs and `/metrics`** are asserted too: a call with a secret argument and a leaking upstream writes no secret to the captured tracing output or the metrics render (`mcp.rs`). **Panic messages:** a guest that panics with its arguments in the message does not leak them: the host receives only the trap (`error while executing at wasm backtrace:`), and a sandbox test pins that (`a_panic_message_does_not_cross_the_boundary`). **Open:** a host-side panic's message is not checked; it is not expected to carry guest data.
- [~] Prompt-injection scenario tests: malicious tool args must not bypass policy — **started:** `arguments_cannot_impersonate_the_caller_or_tool` (router) shows that argument keys claiming a caller or tool do not change the policy's view. **Done for argument predicates:** they are exact JSON matches, so no traversal spelling satisfies one (policy test). **Open:** Rego rules receive raw arguments, so a Rego rule that compares paths must normalise them itself; this is a residual risk until a normalising helper exists for Rego.
- [~] Supply chain: `cargo-deny` gates, `cargo-vet` or `cargo-auditable`, SBOM (CycloneDX) in release — **done:** `cargo-deny` runs in CI; a `sbom` CI job generates a CycloneDX SBOM as an artifact. **Open:** cargo-vet or cargo-auditable, and attaching the SBOM to a release.
- [~] Resource-exhaustion / DoS tests for rate limiter and pool — **done for the limiter:** 10,000 distinct idle clients are swept back to one gate; 1,000 client-rejected calls leak no tool slots; 32 threads never exceed a tool's concurrency cap (3 tests in `limiter.rs`). **Pool:** the existing sandbox `concurrency_cap_is_enforced` covers the instance cap; a flood against the pool itself is **open**.
- [ ] External-style security review pass + checklist sign-off before v0.1.0

## Phase 12 — Documentation & Release

- [x] Docs site (`mdBook`) — **done:** `book.toml` and `docs/book/src`, built by a `docs` CI job. The security, architecture and integration chapters include the files in `docs/` directly. Nothing is deployed. Scope as written: quickstart, config reference, capability & policy guide (YAML + Rego), Wasm tool authoring (SDK), security model, architecture, operations/observability, troubleshooting
- [~] Doc examples tested in CI where feasible — the book builds in CI, but its YAML and Rego snippets are not executed yet.
- [ ] `cargo-dist`: build + package binaries for Linux x86_64, macOS arm64, macOS x86_64, Windows x86_64 with SHA-256 checksums, on tag
- [~] `release-plz`/`git-cliff` changelog + version bump workflow — **done:** `release-plz.toml` (publishing and GitHub release switched off) and `cliff.toml`. **Open:** the release workflow itself.
- [ ] Publish crates to crates.io in dependency order (`--dry-run` first)
- [ ] GitHub Release with binaries, `.wasm` example tools, SBOM, notes
- [ ] Tag `v0.1.0`; announce; update README status → Released

---

## Verification (per phase / at v1)

- [ ] `cargo test --workspace` green on all 4 platforms in CI
- [ ] `cargo clippy --workspace --all-targets -D warnings`, `cargo fmt --check`, `cargo deny check`
- [ ] MCP Inspector / Claude Code connects over stdio and Streamable HTTP; `tools/list`, `resources/list`, `prompts/list` populated from Wasm + an upstream server
- [ ] `tools/call` on `tools/tpt-mcpbox-tool-github` succeeds with proxy-injected token; the same call is **denied** when the policy host allowlist is emptied
- [ ] `tools/call` on `tools/tpt-mcpbox-tool-fs` can write only under `./workspace/output/**`; escape attempts denied
- [ ] Criterion benchmark shows < 5 ms warm-pool invocation overhead on the reference machine
- [ ] `tpt-mcpbox audit verify` passes; tampering with one entry makes it fail
- [ ] `/metrics` exposes invocation, denial, latency, and pool series
- [ ] Secret-scan test suite finds no credential material in logs/audit/metrics/errors
- [ ] `cargo-fuzz` targets run clean for a set duration in CI
