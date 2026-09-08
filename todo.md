# tpt-mcpbox — Project Task Checklist

Local-first, zero-trust MCP proxy + WebAssembly tool runtime (Rust). See [spec.txt](spec.txt).

**License:** dual `MIT OR Apache-2.0` — © TPT Solutions.

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
- Cargo workspace crates: `mcpbox-cli` (binary), `mcpbox-protocol`, `mcpbox-config`, `mcpbox-policy`, `mcpbox-runtime`, `mcpbox-proxy`, `mcpbox-router`, `mcpbox-audit`, `mcpbox-sdk` (guest); plus `tools/github`, `tools/fs`.
- MCP protocol revision: latest stable (`2025-06-18`) at implementation time.
- CI: GitHub Actions. Release automation: `cargo-dist` + `release-plz`/`git-cliff`.

---

## Phase 0 — Bootstrap & Governance

- [ ] `git init`; add `.gitignore` (Rust, `.env`, `target/`, `*.wasm` build output, OCI cache)
- [ ] Create Cargo workspace with member crate skeletons listed above
- [ ] `rust-toolchain.toml`; set and document MSRV
- [ ] Dual licensing: `LICENSE-MIT`, `LICENSE-APACHE`, `license = "MIT OR Apache-2.0"` in every `Cargo.toml`, copyright "TPT Solutions"
- [ ] `README.md` (overview, status, quickstart placeholder, license, contribution note)
- [ ] `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` (disclosure policy), `CHANGELOG.md`
- [ ] `NOTICE` / per-file SPDX headers convention documented
- [ ] CI: `fmt`, `clippy -D warnings`, `test`, `cargo-deny` (licenses/advisories/bans), `cargo-audit`
- [ ] CI matrix across the 4 target platforms
- [ ] `.editorconfig`, `rustfmt.toml`, `clippy.toml`
- [ ] GitHub issue/PR templates, `CODEOWNERS`
- [ ] `docs/architecture.md` — component diagram + data-flow from spec, kept current

## Phase 1 — MCP Protocol Core (`mcpbox-protocol`)

- [ ] JSON-RPC 2.0 types: request / response / notification / batch / error codes
- [ ] MCP message types: `initialize`/`initialized`, capabilities negotiation, `ping`, shutdown
- [ ] `tools/list` (+ pagination), `tools/call`, `notifications/tools/list_changed`
- [ ] `resources/list`, `resources/read`, `resources/templates/list`, `subscribe`/`unsubscribe`, `list_changed`, `updated`
- [ ] `prompts/list`, `prompts/get`, `notifications/prompts/list_changed`
- [ ] `completion/complete`
- [ ] Utilities: progress notifications, `notifications/cancelled`, logging (`logging/setLevel`, `notifications/message`)
- [ ] Client-feature passthrough plumbing: `roots`, `sampling/createMessage`, `elicitation` (routed to agent)
- [ ] stdio transport (newline-delimited JSON, stderr for logs)
- [ ] Streamable HTTP transport: `POST /mcp`, SSE response streams, `Mcp-Session-Id`, resumable event IDs, `GET` stream, `DELETE` session, origin validation
- [ ] Content types: text / image / audio / embedded resource / resource links
- [ ] Conformance test suite vs. the MCP schema; round-trip serde tests; fuzz the parser
- [ ] Manual interop check against a real MCP client (Claude Code / MCP Inspector)

## Phase 2 — Configuration & Secrets (`mcpbox-config`)

- [ ] `tpt-mcpbox.yaml` model: `tools[]` (name, source, capabilities, secrets, limits, rate limits), `upstreams[]`, `server` (transports, bind), `policy`, `audit`, `metrics`, `logging`
- [ ] Capability schema: `network` (domain allowlist), `filesystem.read/write` (glob lists), `memory_limit`, `time_limit`, `env` allowlist
- [ ] Loader + strict validation + helpful diagnostics; emit JSON Schema for editor support
- [ ] Config discovery (CWD, `--config`, XDG/`%APPDATA%`), layering, defaults
- [ ] Secrets: load from process env + gitignored `.env`; `secret → header` mapping (e.g. `GITHUB_TOKEN` → `Authorization: Bearer …`)
- [ ] `SecretString` wrapper: zeroize on drop, `Debug`/`Display` redaction, never serialized
- [ ] Central redaction filter applied to logs, error messages, audit entries
- [ ] Hot reload: watch config, atomic swap, `SIGHUP` (Unix) / equivalent; reload-safe pool draining
- [ ] `mcpbox validate` command

## Phase 3 — Policy Engine (`mcpbox-policy`)

- [ ] Policy input schema: caller identity/session, tool name, method, arguments, requested resource URIs, target host, fs path
- [ ] Decision type: allow / deny / allow-with-constraints + reason + rule id (for audit)
- [ ] Deny-by-default evaluation; explicit precedence and merge rules for multiple policies
- [ ] YAML DSL evaluator: match tool + method + arg predicates, host/path glob checks, quotas
- [ ] Rego evaluator via `regorus`: load `.rego` modules, stable input document, decision logging
- [ ] Engine selection per policy; combine YAML + Rego results conservatively (most restrictive wins)
- [ ] Decision cache keyed on normalized input; invalidate on config reload
- [ ] Dry-run / audit-only mode (log what would be denied without blocking)
- [ ] Tests: allow/deny matrices, glob edge cases, path traversal, Unicode/host-normalization, `regorus` policy fixtures; property tests

## Phase 4 — Wasm Runtime (`mcpbox-runtime`)

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

## Phase 5 — Router & Rate Limiter (`mcpbox-router`)

- [ ] Dispatch `tools/call` to Wasm runtime or an upstream proxy target by tool origin
- [ ] Namespaced aggregation: merge `tools`/`resources`/`prompts` from Wasm + all upstreams; prefix/rename on conflict; `list_changed` fan-in
- [ ] Per-tool rate limit + max concurrency; per-client (session) rate limit + concurrency; queue vs reject policy
- [ ] Global request timeout, backpressure, structured overload errors
- [ ] Graceful shutdown: stop accepting, drain in-flight, checkpoint audit log
- [ ] Cancellation + progress propagation across router boundary

## Phase 6 — Passthrough Proxy (`mcpbox-proxy`)

- [ ] MCP client for upstreams: stdio (spawn + supervise child process) and Streamable HTTP
- [ ] Upstream lifecycle: launch, `initialize` handshake, health check, restart with backoff
- [ ] Capability reconciliation between agent, proxy, and each upstream
- [ ] Enforce policy on every proxied call: inspect `tools/call` args, `resources/read` URIs, `prompts/get` args
- [ ] Tool/resource/prompt filtering: allowlist/denylist, rename, description overrides
- [ ] Full-parity forwarding: resources (list/read/templates/subscribe/updated), prompts (list/get), `completion/complete`
- [ ] Forward client features to upstream where needed (`roots`, `sampling`) with policy gate
- [ ] Redact/scan upstream responses per policy (optional secret/PII pattern check)

## Phase 7 — Guest Tool SDK (`mcpbox-sdk`)

- [ ] Guest crate targeting the tool WIT world; re-export needed `wasi` bindings
- [ ] `#[tool]` macro: register name, description, JSON-Schema params via `schemars`, typed handler
- [ ] Ergonomic HTTP helper over `wasi:http` (JSON get/post, error mapping)
- [ ] Structured tool errors + result content builders (text/JSON/resource)
- [ ] Optional resource/prompt provider traits (full parity)
- [ ] `cargo component`-based project template + `mcpbox init tool` generator
- [ ] SDK doc page + a "hello world" tool walkthrough

## Phase 8 — Example Tools (`tools/`)

- [ ] `tools/github`: search repos/code via `api.github.com`; relies on proxy-injected `GITHUB_TOKEN` header; no secret in guest
- [ ] `tools/fs`: read within `./workspace/**`, write within `./workspace/output/**`, enforced by preopens
- [ ] Build both to `.wasm` in CI; publish as release assets
- [ ] Use both as end-to-end integration fixtures (policy allow + deny paths)
- [ ] Sample `tpt-mcpbox.yaml` matching the spec's configuration example

## Phase 9 — Observability (`mcpbox-audit` + runtime hooks)

- [ ] `tracing` setup: JSON + pretty subscribers, `RUST_LOG`/config level, per-request span with tool, decision, duration
- [ ] Tamper-evident audit log: append-only, per-entry hash chain (prev-hash), entries for every tool call, policy decision, secret injection (name only), upstream spawn, config reload
- [ ] Optional signing of audit segments; log rotation; `mcpbox audit verify` to check chain integrity
- [ ] Prometheus `/metrics`: invocation counts, latency histograms, denial counts, pool utilization, upstream health, rate-limit rejections
- [ ] Benchmark harness wired to CI with regression thresholds (overhead, cold vs warm)

## Phase 10 — CLI & Developer Experience (`mcpbox-cli`)

- [ ] `mcpbox run` (start proxy; `--config`, `--transport`, `--dry-run`)
- [ ] `mcpbox validate`, `mcpbox schema` (emit config JSON Schema)
- [ ] `mcpbox policy test <input.json>` (explain a decision)
- [ ] `mcpbox tools ls` / `mcpbox tools call` (local invocation for debugging)
- [ ] `mcpbox pull <oci-ref>` (fetch + verify a tool into cache)
- [ ] `mcpbox audit verify`
- [ ] `mcpbox init` (scaffold config) / `mcpbox init tool` (scaffold SDK project)
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
- [ ] `tools/call` on `tools/github` succeeds with proxy-injected token; the same call is **denied** when the policy host allowlist is emptied
- [ ] `tools/call` on `tools/fs` can write only under `./workspace/output/**`; escape attempts denied
- [ ] Criterion benchmark shows < 5 ms warm-pool invocation overhead on the reference machine
- [ ] `mcpbox audit verify` passes; tampering with one entry makes it fail
- [ ] `/metrics` exposes invocation, denial, latency, and pool series
- [ ] Secret-scan test suite finds no credential material in logs/audit/metrics/errors
- [ ] `cargo-fuzz` targets run clean for a set duration in CI
