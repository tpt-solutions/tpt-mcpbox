# Contributing to tpt-mcpbox

Thanks for helping harden the MCP trust boundary. This project is
security-sensitive: a bug in the policy engine or sandbox is a remote code
execution for every user, so the bar for changes is "obviously correct, and
covered by a test that fails without it".

## Getting set up

```console
git clone https://github.com/tpt-solutions/tpt-mcpbox
cd tpt-mcpbox
cargo build
cargo test --workspace
```

Requirements: a current stable Rust toolchain (pinned in `rust-toolchain.toml`)
and the `wasm32-wasip2` target plus `cargo-component` for guest crates.

## Before you open a pull request

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs the same commands, plus `cargo deny check` and `cargo audit`. Fixing
lints is part of the change, not a follow-up.

## Repository conventions

- **SPDX headers.** Every Rust file starts with:
  ```rust
  // SPDX-License-Identifier: MIT OR Apache-2.0
  // Copyright (c) TPT Solutions
  ```
- **Crates are `tpt-mcpbox-<name>`.** The binary is `tpt-mcpbox`.
- **`#![forbid(unsafe_code)]`** in every crate. If you genuinely need `unsafe`,
  expect a design discussion first.
- **Public items are documented** (`missing_docs` is a warning and is treated as
  an error in review).
- **ASCII in source.** Avoid smart quotes and em dashes in `.rs` files; they
  survive copy/paste badly.
- **Errors must not leak secrets.** Error messages returned to an agent are
  shown to users; keep values out of them.

## Where to put code

| Concern | Crate |
|---|---|
| Wire format, transports, sessions | `tpt-mcpbox-protocol` |
| Config parsing, discovery, secrets | `tpt-mcpbox-config` |
| Allow/deny decisions | `tpt-mcpbox-policy` |
| Wasm execution, capability mapping | `tpt-mcpbox-runtime` |
| Talking to upstream servers | `tpt-mcpbox-proxy` |
| Aggregation, limits, shutdown | `tpt-mcpbox-router` |
| Audit chain, metrics, tracing | `tpt-mcpbox-audit` |
| Command line | `tpt-mcpbox-cli` |

The dependency direction is one-way: `protocol <- config <- policy <- runtime
<- proxy <- router <- cli`. `tpt-mcpbox-protocol` must never depend on the
policy engine: transports that could make policy decisions would make every
transport bug a privilege-escalation bug.

## Tests

- Unit tests live next to the code in `#[cfg(test)] mod tests`.
- Anything security-relevant needs a test that asserts the **deny** path, not
  just the allow path.
- Transport tests use in-memory duplexes; do not bind ports or spawn shells in
  unit tests.
- Property and fuzz targets arrive in Phase 11; when you touch the JSON-RPC or
  config parsers, add cases to those corpora.

## Commit and PR style

- One logical change per PR; explain *why* in the description.
- Reference the phase and checklist item from `todo.md` you are advancing, and
  tick it.
- Draft PRs are welcome for design discussions on policy semantics.

## Reporting security issues

Do **not** open a public issue. Follow [SECURITY.md](SECURITY.md).
