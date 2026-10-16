# tpt-mcpbox — Project Task Checklist

Local-first, zero-trust MCP proxy + WebAssembly tool runtime (Rust). See [spec.txt](spec.txt).

**License:** dual `MIT OR Apache-2.0` — © TPT Solutions.

**Naming:** every crate is `tpt-mcpbox-<name>`; the binary is `tpt-mcpbox`
(so `tpt-mcpbox run`, `tpt-mcpbox audit verify`, ...). Guest crates
(`tpt-mcpbox-sdk`, `tpt-mcpbox-tool-github`, `tpt-mcpbox-tool-fs`) live outside
the host workspace and build for `wasm32-wasip2` with `cargo-component`.

**Last updated:** 2026-10-15 — Phase 0 complete, Phase 1 (protocol core)
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
- [ ] Conformance test suite vs. the MCP JSON Schema (fixtures + schema validation)
- [ ] Fuzz targets for the JSON-RPC parser (Phase 11; `cargo-fuzz` harness stubs to be added there)
- [ ] Manual interop check against a real MCP client (Claude Code / MCP Inspector)

## Phase 2 — Configuration & Secrets (`tpt-mcpbox-config`)

- [x] `tpt-mcpbox.yaml` model (`model`, `units`): `tools[]` (name, source, capabilities, secrets, limits, rate limits), `upstreams[]`, `server` (transports, bind), `policy`, `audit`, `metrics`, `logging`
- [x] Capability schema (`model::Capabilities`): `network` (domain allowlist), `filesystem.read/write` (glob lists), `memory_limit`, `time_limit`, `env` allowlist
- [x] Loader + strict validation + helpful diagnostics; emit JSON Schema for editor support (`load`, `validate`, `schema`)
- [x] Config discovery (`--config`, `$MCPBOX_CONFIG`, CWD, XDG/`%APPDATA%`), layering (`tpt-mcpbox.local.yaml` overlay adds tools/upstreams only), defaults
- [x] Secrets (`secrets::SecretStore`): load from process env + gitignored `.env`; `secret → header` mapping (e.g. `GITHUB_TOKEN` → `Authorization: Bearer …`)
- [x] `SecretString` wrapper: zeroize on drop, `Debug`/`Display` redaction, never serialized
- [ ] Central redaction filter applied to logs, error messages, audit entries (`secrets::Redactor` implemented; wire into `tracing` and audit in Phase 9)
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

- [ ] `wasmtime` engine config: component model on, epoch interruption, pooling allocator, fuel optional
- [ ] Define WIT world for tools (exports: tool descriptors + `call`; imports: `wasi:http`, `wasi:filesystem`, `wasi:cli` subset, clocks, random)
- [ ] Module source loaders: local path; OCI pull (`oci-client`/`oci-distribution`) with local content-addressed cache
- [ ] Integrity: SHA-256 pin per tool; optional signature verification (e.g. `sigstore`/`minisign`); refuse on mismatch
- [ ] Warm instance pool: pre-instantiate per tool, checkout/checkin, max idle, recycle after N calls or on fault
- [ ] Per-call `Store` with `ResourceLimiter`: memory cap from config, table/instance caps
- [ ] Execution timeout via epoch deadline; cooperative cancellation on `notifications/cancelled`
- [ ] WASI capability mapper: build preopen dirs from policy `filesystem` globs (read-only vs read-write), virtualized so host paths never leak
- [ ] `wasi:http` outbound host handler: parse request, enforce policy host allowlist, inject configured secret headers, enforce TLS, cap request/response size + time, strip hop-by-hop headers
- [ ] Deny all other ambient authority (no env, no unlisted sockets, deterministic-ish clocks/random policy)
- [ ] Panic/trap isolation: convert to structured MCP tool error, never crash the proxy
- [ ] Startup self-test: load a fixture component, assert sandbox denies fs/net not granted
- [ ] Criterion benchmark: measure per-invocation overhead; assert < 5 ms p50 on reference hardware; track in CI

## Phase 5 — Router & Rate Limiter (`tpt-mcpbox-router`)

- [ ] Dispatch `tools/call` to Wasm runtime or an upstream proxy target by tool origin
- [ ] Namespaced aggregation: merge `tools`/`resources`/`prompts` from Wasm + all upstreams; prefix/rename on conflict; `list_changed` fan-in
- [ ] Per-tool rate limit + max concurrency; per-client (session) rate limit + concurrency; queue vs reject policy
- [ ] Global request timeout, backpressure, structured overload errors
- [ ] Graceful shutdown: stop accepting, drain in-flight, checkpoint audit log
- [ ] Cancellation + progress propagation across router boundary

## Phase 6 — Passthrough Proxy (`tpt-mcpbox-proxy`)

- [ ] MCP client for upstreams: stdio (spawn + supervise child process) and Streamable HTTP
- [ ] Upstream lifecycle: launch, `initialize` handshake, health check, restart with backoff
- [ ] Capability reconciliation between agent, proxy, and each upstream
- [ ] Enforce policy on every proxied call: inspect `tools/call` args, `resources/read` URIs, `prompts/get` args
- [ ] Tool/resource/prompt filtering: allowlist/denylist, rename, description overrides
- [ ] Full-parity forwarding: resources (list/read/templates/subscribe/updated), prompts (list/get), `completion/complete`
- [ ] Forward client features to upstream where needed (`roots`, `sampling`) with policy gate
- [ ] Redact/scan upstream responses per policy (optional secret/PII pattern check)

## Phase 7 — Guest Tool SDK (`tpt-mcpbox-sdk`)

- [ ] Guest crate targeting the tool WIT world; re-export needed `wasi` bindings
- [ ] `#[tool]` macro: register name, description, JSON-Schema params via `schemars`, typed handler
- [ ] Ergonomic HTTP helper over `wasi:http` (JSON get/post, error mapping)
- [ ] Structured tool errors + result content builders (text/JSON/resource)
- [ ] Optional resource/prompt provider traits (full parity)
- [ ] `cargo component`-based project template + `tpt-mcpbox init tool` generator
- [ ] SDK doc page + a "hello world" tool walkthrough

## Phase 8 — Example Tools (`tools/`)

- [ ] `tools/tpt-mcpbox-tool-github`: search repos/code via `api.github.com`; relies on proxy-injected `GITHUB_TOKEN` header; no secret in guest
- [ ] `tools/tpt-mcpbox-tool-fs`: read within `./workspace/**`, write within `./workspace/output/**`, enforced by preopens
- [ ] Build both to `.wasm` in CI; publish as release assets
- [ ] Use both as end-to-end integration fixtures (policy allow + deny paths)
- [ ] Sample `tpt-mcpbox.yaml` matching the spec's configuration example

## Phase 9 — Observability (`tpt-mcpbox-audit` + runtime hooks)

- [ ] `tracing` setup: JSON + pretty subscribers, `RUST_LOG`/config level, per-request span with tool, decision, duration
- [ ] Tamper-evident audit log: append-only, per-entry hash chain (prev-hash), entries for every tool call, policy decision, secret injection (name only), upstream spawn, config reload
- [ ] Optional signing of audit segments; log rotation; `tpt-mcpbox audit verify` to check chain integrity
- [ ] Prometheus `/metrics`: invocation counts, latency histograms, denial counts, pool utilization, upstream health, rate-limit rejections
- [ ] Benchmark harness wired to CI with regression thresholds (overhead, cold vs warm)

## Phase 10 — CLI & Developer Experience (`tpt-mcpbox-cli`)

- [ ] `tpt-mcpbox run` (start proxy; `--config`, `--transport`, `--dry-run`)
- [ ] `tpt-mcpbox validate`, `tpt-mcpbox schema` (emit config JSON Schema)
- [ ] `tpt-mcpbox policy test <input.json>` (explain a decision)
- [ ] `tpt-mcpbox tools ls` / `tpt-mcpbox tools call` (local invocation for debugging)
- [ ] `tpt-mcpbox pull <oci-ref>` (fetch + verify a tool into cache)
- [ ] `tpt-mcpbox audit verify`
- [ ] `tpt-mcpbox init` (scaffold config) / `tpt-mcpbox init tool` (scaffold SDK project)
- [ ] Shell completions + generated man pages
- [ ] Integration guide: wiring tpt-mcpbox into Claude Code / Claude Desktop `mcpServers`

## Phase 11 — Security Hardening & Review

- [ ] `docs/security-model.md`: threat model, trust boundaries, non-goals, residual risks
- [ ] `cargo-fuzz` targets: JSON-RPC parser, config parser, YAML DSL, WIT/host-call boundary
- [ ] Sandbox-escape test suite: attempt fs/net/env access outside grants, path traversal, symlink escape, oversized alloc, infinite loop, deep recursion
- [ ] Secret-safety tests: assert secrets absent from logs, errors, audit payloads, panic messages, `/metrics`
- [ ] Prompt-injection scenario tests: malicious tool args must not bypass policy
- [ ] Supply chain: `cargo-deny` gates, `cargo-vet` or `cargo-auditable`, SBOM (CycloneDX) in release
- [ ] Resource-exhaustion / DoS tests for rate limiter and pool
- [ ] External-style security review pass + checklist sign-off before v0.1.0

## Phase 12 — Documentation & Release

- [ ] Docs site (`mdBook`): quickstart, config reference, capability & policy guide (YAML + Rego), Wasm tool authoring (SDK), security model, architecture, operations/observability, troubleshooting
- [ ] Doc examples tested in CI where feasible
- [ ] `cargo-dist`: build + package binaries for Linux x86_64, macOS arm64, macOS x86_64, Windows x86_64 with SHA-256 checksums, on tag
- [ ] `release-plz`/`git-cliff` changelog + version bump workflow
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
