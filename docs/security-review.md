# Security review (internal pass, pre-v0.1.0)

This is an internal review of the code against the claims in
[security-model.md](security-model.md). It is not the external review that the
v0.1.0 checklist asks for. It exists so that the external reviewer starts from a
list of known findings instead of rediscovering them.

- **Date:** 2026-10-29
- **Code reviewed:** `master` at `6a184f2`, plus the fixes listed below as
  *Fixed*.
- **Method:** each control in sections 3.1 to 3.6 of the security model was
  traced to the code that implements it, then checked for inputs that bypass
  it. The sandbox (`tpt-mcpbox-runtime`), transports and proxy
  (`tpt-mcpbox-protocol`, `tpt-mcpbox-proxy`, `tpt-mcpbox-cli`), router and
  limiter (`tpt-mcpbox-router`), audit (`tpt-mcpbox-audit`), and policy and
  configuration (`tpt-mcpbox-policy`, `tpt-mcpbox-config`) were covered. No
  dynamic testing beyond the existing test suite was done, and the fuzz
  targets were not run locally.
- **Out of scope:** wasmtime, regorus and other dependencies, except where the
  code relies on a specific behaviour of theirs. The guest SDK and the example
  tools.

Severity follows the usual scale: **critical** means a documented protection
does not work at all; **high** means it can be bypassed by an agent or tool
with moderate effort; **medium** means it is weaker than documented or needs an
unusual configuration to exploit; **low** and **info** are hardening and
accuracy.

## Summary

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| SR-01 | `hosts` and `paths` policy rules never fire: no caller fills in `host` or `fs_path` | Critical | Open |
| SR-02 | A host or path that fails normalisation skipped deny rules | High | Fixed |
| SR-03 | Upstream tools are checked under their upstream name, not the exposed name | High | Open |
| SR-04 | Quotas are per session id, and a new session gets a new budget | High | Open |
| SR-05 | Time limit and cancellation do not apply while a guest is blocked in a host call | High | Open |
| SR-06 | Rego saw un-normalised hosts, paths and URIs | Medium | Fixed |
| SR-07 | A relative `policy.rego` was resolved against the working directory | Medium | Fixed |
| SR-08 | Secret headers are injected into requests to every allowlisted host of the tool | Medium | Open |
| SR-09 | The memory limit applies per linear memory, and four are allowed | Medium | Open |
| SR-10 | `Runtime::self_test` is never run at startup | Medium | Open (doc corrected) |
| SR-11 | A write grant with a glob makes the whole directory writable (R4 for writes) | Medium | Open (doc corrected) |
| SR-12 | Rego can allow a call the DSL has no rule for; the policy guide said it could only tighten | Medium | Doc corrected; behaviour accepted |
| SR-13 | Per-tool limits are registered under the config name but looked up by exposed name | Medium | Open |
| SR-14 | Per-client limits are never configured | Medium | Open (doc corrected) |
| SR-15 | HTTP upstream response bodies and SSE buffers are not size-capped | Medium | Open |
| SR-16 | `deny` rules on `args` use exact JSON equality and are easy to step around | Medium | Open |
| SR-17 | Userinfo in an outbound URL was accepted and judged on the host alone | Low | Fixed |
| SR-18 | IPv6 loopback Origins with a port were refused | Low | Fixed |
| SR-19 | A tool's rate token is spent even when the client gate then refuses the call | Low | Open |
| SR-20 | A failed audit append can leave a partial line that blocks the next start | Low | Open |
| SR-21 | Epoch ticker spawn failure is ignored, which would disable timeouts | Low | Open |
| SR-22 | Numeric IPv4 forms (`2130706433`, `127.1`) pass host normalisation | Low | Open |
| SR-23 | The local overlay can add an HTTP listener | Low | Open |
| SR-24 | The audit hash chain is unkeyed: anyone who can write the file can rebuild it | Info | Open (doc corrected) |
| SR-25 | Prompt names are not part of the policy input | Info | Open |
| SR-26 | Upstream secret headers are not marked sensitive; secret copies are not zeroised | Info | Open |
| SR-27 | Non-goals, transports, bearer check, body cap, origin check, audit-before-dispatch | — | Hold |

## Findings

### SR-01: `hosts` and `paths` rules never fire (critical, open)

`dispatch.rs` (Wasm route) and `gate.rs` (upstream route) build a
`PolicyInput` with `host` and `fs_path` left empty. A rule that names `hosts` or
`paths` therefore never matches. For allow rules that fails closed. For deny
rules it does not: the policy guide's `deny-secrets` example (`paths:
["**/.env"]`) never applies, and an allow on `tool` or `args` then admits a
read of `.env`. The sandbox grants still bound what a Wasm tool can touch, so
the impact is on upstream tools and on deny rules written as a second line of
defence.

**Fix:** the runtime and proxy must supply the host and path for each call
(from the tool's declared argument schema, or from the host call at the point
it is made). Until then, validation should warn that `hosts` and `paths` on a
deny rule are not enforced. Not a small change.

### SR-02: unnormalisable host or path skipped deny rules (high, fixed)

`normalize_host` and `normalize_path` return `None` for values such as
`evil.test:443` or `../x`. The DSL treated that like an absent field, so a deny
rule naming the field did not match and a later allow could admit the call.
Unnormalisable URIs were already handled correctly.

**Fixed:** `dsl.rs` keeps "absent" and "present but invalid" apart. An invalid
value is covered by every deny rule that names the field and by no allow rule.
Tests: `an_unnormalisable_path_is_caught_by_a_deny_rule`,
`an_unnormalisable_host_is_caught_by_a_deny_rule`.

### SR-03: upstream tools are checked under their upstream name (high, open)

`dispatch.rs` passes the upstream's own tool name to `UpstreamGate::call_tool`,
not the prefixed name the agent sees. Two upstreams that both expose
`read_file` look identical to the policy, so an allow written for one admits
the other, and an overlay can add an upstream that reuses an allowed name.

**Fix:** pass the exposed name. Rules written against raw names need migrating,
so this should land before v0.1.0 rather than after.

### SR-04: quotas reset with a new session (high, open)

The caller is the session id, a random UUID per `initialize`. A client that
re-initialises gets a fresh quota bucket, and a `caller: "agent-*"` glob, as in
the policy guide, can never match.

**Fix:** key quotas on an authenticated principal, or offer a global bucket per
rule. Design change.

### SR-05: time limit does not cover host calls (high, open)

Epoch interruption only fires while Wasm code runs. A guest blocked on a
`wasi:clocks` pollable or a slow allowlisted server holds its thread and
concurrency slot past `time_limit`, and cancellation has no effect during the
wait. Each outbound request also gets a fresh `time_limit`, not the time left on
the call.

**Fix:** async wasmtime (`async_support`, async linkers, `call_async`) wrapped in
`tokio::time::timeout`. A partial fix is to clamp outbound timeouts to the time
left on the call.

### SR-06: Rego saw un-normalised input (medium, fixed)

`rego.rs` serialised the raw input, so a Rego check on `api.github.com` or on a
`secret/` prefix could be sidestepped with `API.GitHub.com.` or
`x/../secret/`.

**Fixed:** the module now receives the normalised host, path and URIs, and a
request whose host, path or URI cannot be normalised is refused before the
module runs. The refusal reason does not echo the value. Tests:
`rego_sees_normalised_hosts_and_paths`,
`rego_refuses_a_request_it_cannot_normalise`.

### SR-07: relative Rego path resolved against the working directory (medium, fixed)

`policy.rego: ./policy.rego` was opened relative to wherever the hub started,
unlike `audit.path`. When the configuration comes from `$MCPBOX_CONFIG` or the
user configuration directory, a `policy.rego` planted in the working directory
replaced the real module, and a Rego allow can admit unmatched calls (SR-12).

**Fixed:** `load_file` resolves a relative `policy.rego` against the directory
of the configuration file. Test:
`a_relative_rego_path_resolves_against_the_config_file`.

### SR-08: secret headers go to every allowlisted host (medium, open)

`outbound.rs` injects every secret binding into every admitted request. A tool
allowed `api.github.com` and a host whose content an attacker controls sends the
GitHub token to both.

**Fix:** an optional `hosts` list on `SecretBinding`, injected only on a match.

### SR-09: memory limit is per linear memory (medium, open)

`StoreLimits::memory_size` caps each memory and `memories(4)` is allowed, so a
guest can reach about four times `memory_limit`. Host-side buffers (resource
table, `wasi:http` bodies, see R1) are not counted.

**Fix:** `memories(1)` if the components allow it, or divide the budget.

### SR-10: the startup self-test is not run (medium, open)

`Runtime::self_test` is only called from `tests/sandbox.rs`. The security model
said it runs at startup. **Doc corrected.** Fix: embed the probe module and run
it in `build_router`.

### SR-11: write grants widen to the whole directory (medium, open)

R4 also applies to writes: a write grant of `workspace/*.log` makes all of
`workspace/` writable, and a write glob that maps to the same directory as a
read grant upgrades that preopen to writable. **Doc corrected** in R4. Fix:
refuse write grants whose last segment is a wildcard, or document the rule in
the configuration reference.

### SR-12: Rego can loosen the policy (medium, doc corrected)

When the DSL has no matching rule, a Rego allow admits the call, even with
`policy.default: deny`. That is the documented combination order, but the
policy guide also says Rego "can only make a decision stricter than the DSL".
Only "a DSL deny wins" holds. **Doc corrected** in `docs/book/src/policy.md`;
the behaviour itself is the documented combination order and is kept.

### SR-13: per-tool limits keyed by the wrong name (medium, open)

`serve.rs` registers rate limits under each tool's configuration name, while
the router looks them up by the name the tool exposes. A component that
exposes `read_file` from a tool configured as `local_files` gets no limit.
Upstream tools have no per-tool limit at all. Fix: register limits under each
exposed name while loading descriptors.

### SR-14: per-client limits never configured (medium, open)

`serve.rs` passes `Limits::default()` (unlimited) for clients, and there is no
configuration field for them. Combined with SR-04, per-client limits would be
easy to bypass even if set. **Doc corrected** in section 3.6.

### SR-15: HTTP upstream responses are not size-capped (medium, open)

`proxy/src/http.rs` reads a JSON reply whole, and the SSE reader's buffers grow
without bound. A hostile upstream can exhaust memory within the request
timeout. `max_line_bytes` only applies to stdio. Fix: wrap the body in a
length-limited reader and bound the SSE buffers.

### SR-16: `args` deny rules are exact JSON equality (medium, open)

`"Write"` does not equal `"write"`, `1.0` does not equal `1`, and missing keys or
non-object arguments never match. A deny keyed only on `args` is easy to step
around. Fix: document it in the policy guide; warn on deny rules that only use
`args`.

### SR-17: userinfo in outbound URLs (low, fixed)

`https://user@api.github.com/` passed the allowlist because `Uri::host` drops
the userinfo. It was harmless in practice (the connection fails), but the
security model says userinfo tricks are refused. **Fixed** in `outbound.rs`.
Test: `userinfo_in_front_of_an_allowed_host_is_refused`.

### SR-18: IPv6 loopback Origin (low, fixed)

`is_loopback_origin` split at the first `:`, so `http://[::1]:8080` gave the
host `[` and was refused. That failed closed, but broke browsers on IPv6
loopback. **Fixed** in `protocol/src/transport/http.rs`, with cases in
`origin_policy_defaults_to_loopback_only`.

### SR-19 to SR-26 (low and info, open)

- **SR-19:** `Limiter::acquire_at` takes the tool's rate token before the
  client gate. When the client gate refuses, the token is not returned, so a
  client over its own limit can drain a shared tool's budget. Only reachable
  once SR-14 is fixed. Fix: check the client gate first, or refund.
- **SR-20:** a partial `write_all` or `sync_data` failure in `chain.rs` leaves
  a torn line; later appends follow it and the next `open` refuses the log
  (fails closed, but takes the hub down). Fix: truncate back to the previous
  length on error.
- **SR-21:** `runtime.rs` ignores an error spawning the epoch ticker, which
  would leave no timeouts at all. Fix: return the error from `Runtime::new`.
- **SR-22:** `normalize_host` accepts digit-and-dot hosts, so `127.1` or
  `2130706433` evade a deny on `127.0.0.1`. Fix: refuse hosts that parse as a
  number or an IP literal, or normalise them to dotted quads.
- **SR-23:** the `tpt-mcpbox.local.yaml` overlay can add transports and set
  `server.http` when the primary file has none. A non-loopback bind still needs
  a bearer token. Fix: take only `tools` and `upstreams` from the overlay.
- **SR-24:** the audit chain uses an unkeyed SHA-256, so it detects edits by
  someone who does not recompute the chain, not by someone who can rewrite the
  whole file. **Doc corrected** in R9.
- **SR-25:** `prompts/get` has no name in the policy input, so a rule cannot
  allow one prompt and not another.
- **SR-26:** secret headers sent to HTTP upstreams are not marked sensitive,
  and `headers_for` returns plain `String` copies that are not zeroised.

### SR-27: claims that hold

- No ambient environment, stdio, arguments, sockets or name lookup for guests.
- Preopens hide host paths; writes outside a writable preopen fail in the host.
- HTTPS only, default port only, allowlist case-insensitive, no redirects,
  hop-by-hop headers stripped, guest cannot set `Host`.
- A trap, timeout, cancellation or panic discards the instance.
- SHA-256 pins are compared case-insensitively over the bytes that are compiled.
- `policy.default: allow` is refused in serve mode; `--dry-run` relaxes it by
  design. Rego compile and evaluation errors fail closed.
- The audit `start` record is written before dispatch and its failure refuses
  the call. Argument values are not recorded (resource URIs are, in full).
- The audit log is locked against a second writer.
- Origin is checked on every HTTP method; a non-loopback bind requires a bearer
  token; the token comparison is constant-time apart from length; the metrics
  listener refuses non-loopback binds; request bodies are capped at 4 MiB.
- Stdio upstreams are spawned with a cleared environment and kill-on-drop.
- No panics on untrusted input were found on the reviewed paths.

## Sign-off

The v0.1.0 checklist item "External-style security review pass + checklist
sign-off" needs an external reviewer. This internal pass does not satisfy it.

- [ ] External reviewer has reviewed this document and the code, and agrees
      with the severities and the open items accepted for v0.1.0.
      Reviewer: ____________ Date: ____________
