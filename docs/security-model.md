# Security model

This document states what tpt-mcpbox defends against, where the trust
boundaries sit, what it deliberately does not do, and what risk is still open.
The boundaries themselves are listed in [architecture.md](architecture.md#2-trust-boundaries);
this document explains the reasoning behind them and the gaps.

Status: pre-release (v0.1.0 not yet tagged). Items marked **residual** are known
gaps, not hypotheticals.

## 1. Assets

| Asset | Why it matters |
|-------|----------------|
| Secret values (API tokens in the proxy environment or `.env`) | Grant access to third-party services under the user's identity. |
| Host filesystem outside the granted paths | Source code, credentials files, SSH keys, shell history. |
| Host network reachable from the machine | Internal services, cloud metadata endpoints, LAN devices. |
| The audit log | Evidence of what an agent did. Must not be silently rewritten. |
| Host availability | A runaway tool or agent loop must not exhaust CPU, memory or file descriptors. |

## 2. Adversaries and attack paths

The primary adversary is **an agent acting on untrusted input**: a prompt
injected into a web page, file, issue or tool result that steers the model into
calling tools with hostile arguments. The agent is therefore treated as an
untrusted principal, even though it runs on the user's machine.

Secondary adversaries:

- **A malicious or compromised tool module** (`.wasm` file, or an upstream MCP
  server). Its code is untrusted; its output is untrusted input to the agent.
- **A malicious upstream response** that tries to smuggle content past policy.
- **Another local user or process** that can reach the loopback HTTP listener
  or the audit log.
- **A network attacker** against the Streamable HTTP transport, if it is bound
  beyond loopback.

Out of scope as adversaries: a user who already has write access to the config
file and the policy. The policy is trusted; if the operator writes an allow rule
for `rm -rf /`, the hub will honour it.

## 3. Controls

### 3.1 Deny by default

- Policy evaluation returns `deny` unless a rule explicitly allows the call.
  `policy.default: allow` is rejected by serve-mode validation.
- Opinions from the YAML DSL and the embedded Rego module combine conservatively:
  any deny wins, then any allow admits with the tightest limits, then
  `policy.default` applies.
- Rego evaluation errors and an undefined `allow` both fail closed.
- Policy inputs are normalised before matching, for the DSL and for Rego alike:
  host names are lower-cased and checked for Unicode look-alikes, paths are
  checked for traversal, and URIs are normalised before comparison. A value
  that cannot be normalised is matched by every deny rule that names its field
  and by no allow rule, and Rego refuses the request outright.
- **Gap:** the hub does not yet fill in the host or path of a call, so `hosts`
  and `paths` rules do not fire (SR-01 in [security-review.md](security-review.md)).

### 3.2 Wasm sandbox

Tools run as WebAssembly components under wasmtime with WASI Preview 2.

- **No ambient authority.** A guest gets no environment variables beyond those
  named in its `env` grant, no inherited stdio, no arguments, no raw sockets and
  no name resolution.
- **Filesystem** is granted by preopening directories. The guest sees the
  preopened name, never the host path. Writes outside a preopened, writable
  directory fail in the host, whatever the guest checks.
- **Network** goes only through `wasi:http/outgoing-handler`, which the host
  implements. The host enforces the domain allowlist, HTTPS only, the default
  port only, and refuses userinfo tricks. Hop-by-hop headers are stripped.
- **Limits.** Memory, table and instance counts are capped through `StoreLimits`.
  The memory cap applies to each linear memory, not the instance (SR-09).
  Execution time is bounded by an epoch deadline (10 ms tick) while guest code
  runs; time spent blocked in a host call is not covered yet (SR-05). Traps, out-of-
  memory, timeouts and cancellation all become structured errors, and the
  instance is discarded.
- **Pooling.** Instances are reused until recycled (after 256 calls or on any
  fault). Guest memory can therefore persist between calls within one recycle
  window. See residual risk R3.
- **Self-test.** `Runtime::self_test` loads a probe module with no grants and
  asserts that file reads, outbound requests and environment access are
  refused. The test suite runs it; the hub does not run it at startup yet
  (SR-10).

### 3.3 Secrets

- Secret values are loaded from the process environment or a gitignored `.env`
  file, and are wrapped in `SecretString`: zeroised on drop, redacted in
  `Debug` and `Display`, and never serialised.
- Secrets are **injected by the host** into outbound HTTP headers for the
  configured tool or upstream. The guest never receives the value. An injected
  header overwrites any value the guest supplied, and is marked sensitive.
- Agent-facing replies (tool output, error text, upstream messages) pass through
  the `Redactor` before they leave the hub.
- Audit records carry secret **names** and scopes only (`secret_bound`), never
  values.

### 3.4 Audit

- Every `tools/call` writes a `start` record before dispatch and a `finish`
  record with outcome, duration and rule id. If the `start` record cannot be
  written, the call is refused.
- Records are JSON lines. Each entry carries the hash of its predecessor, so
  editing or deleting an entry breaks the chain. With `audit.key_env` set the hash
  is HMAC-SHA256 under that secret, so rebuilding the chain needs the key.
  Without it, the hash is plain SHA-256 and anyone who can write the file can
  rebuild the chain. `tpt-mcpbox audit verify` reports the first break and exits
  non-zero.
- Argument **values** are never recorded, only argument key names.
- A second writer on the same log is refused by an OS file lock.

### 3.5 Transports

- **stdio:** the trust relationship is the parent process that launched the hub.
- **Streamable HTTP:** bound to loopback by default. Origins are validated, so a
  browser page on another origin cannot drive the hub through DNS rebinding
  tricks. A non-loopback bind is refused unless a bearer token is configured,
  and the token check is constant-time.
- The metrics listener is loopback-only and refuses non-loopback binds.

### 3.6 Resource limits

- Per-tool and per-client rate limits (token bucket) and concurrency limits
  (semaphore). Concurrency permits are all-or-nothing; a tool's rate token is
  not returned when the client gate refuses (SR-19). Per-client limits exist
  in the limiter but have no configuration yet, so they are off (SR-14).
- Upstream spawn uses a cleared environment and kill-on-drop.

## 4. Non-goals

- **Not a host sandbox for native code.** Only Wasm tools and the hub itself run
  here. Upstream MCP servers are separate processes that the hub spawns; they are
  not isolated beyond a cleared environment. Use an OS-level sandbox for those if
  they are not trusted.
- **Not a prompt-injection detector.** The policy decides on structured inputs
  (tool, method, arguments, host, path). It does not classify natural language.
- **Not a multi-tenant service.** The threat model assumes one user on one
  machine. There are no per-user accounts, and the bearer token is one shared
  secret.
- **Not a secret manager.** Secrets come from the environment and `.env`. There
  is no vault integration or rotation without a restart.
- **Not a content filter** for upstream responses (see residual risk R7).

## 5. Residual risks

These are known and open. Each should be closed or explicitly accepted before
v0.1.0.

| ID | Risk | Status |
|----|------|--------|
| R1 | Response bodies from `wasi:http` are not size-capped; the outbound future does not expose the body stream. A tool can make the host buffer an arbitrarily large response. | Open |
| R2 | DNS rebinding and private-address (SSRF) checks are not done. An allowlisted name that resolves to a private or link-local address is not blocked. | Open |
| R3 | Guest memory persists across calls within one recycle window. `recycle_after` is fixed at 256 and not yet configurable. | Partly mitigated |
| R4 | A filesystem grant preopens its fixed directory. A grant of `workspace/*.md` exposes all of `workspace/` to the guest, and a write grant of `workspace/*.log` makes all of `workspace/` writable. | Accepted, documented |
| R5 | Signature verification is opt-in with minisign (`minisign_key`); `sigstore` is not implemented. Without a key, SHA-256 pinning is the only integrity check, and unpinned modules load with a warning. | Open (minisign opt-in) |
| R6 | OCI pulls are refused (`ToolError::Unsupported`), so there is no supply-chain path to audit yet. | Open (feature gap) |
| R7 | Upstream responses are scanned only against the per-upstream `scan` rules an operator writes, and prompts are not scanned. Known secret values are redacted. | Partly mitigated |
| R8 | Client-side rate-limit state is never evicted, so memory grows with the number of distinct session ids. | Open |
| R9 | Truncation of the newest audit entries is not detected without an external head checkpoint. Without `audit.key_env` the chain hash is unkeyed, so someone who can write the file can also recompute the whole chain. | Open (keying is opt-in) |
| R10 | Only one shared bearer token exists. There is no per-client token and no rotation without restart. | Open |
| R11 | Fuzz targets cover the JSON-RPC parser, config parser and policy input, and run weekly in CI. The WIT boundary has no target yet. | Partly mitigated |

The internal review in [security-review.md](security-review.md) lists further
findings (SR-01 to SR-26) with severity and status.

## 6. How to check these claims

- Unit and integration tests: `cargo test --workspace`. The sandbox escape and
  secret-safety tests live in `crates/tpt-mcpbox-runtime/tests/sandbox.rs` and
  the router and audit crates.
- Audit integrity: `tpt-mcpbox audit verify`, then edit one line of the log and
  run it again. It must fail.
- Secret handling: run a tool call with a bogus token and grep the logs, the
  audit log and `/metrics` for the value. It must not appear.
- Policy: `tpt-mcpbox policy test <input.json>` shows the decision and rule id
  for a request, without making the call.

## 7. Reporting a vulnerability

See [SECURITY.md](../SECURITY.md) for the disclosure policy. Please do not open a
public issue for a suspected sandbox escape, secret leak or policy bypass.
