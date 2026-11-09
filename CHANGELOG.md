# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes are generated from conventional commits by `release-plz` /
`git-cliff` from Phase 12 onward.

## [Unreleased]

### Added

- Workspace bootstrap: `tpt-mcpbox-{protocol,config,policy,runtime,proxy,router,audit,cli}`
  crates, dual MIT/Apache-2.0 licensing, tooling config (`rustfmt`, `clippy`,
  `cargo-deny`, `editorconfig`) and governance docs.
- `tpt-mcpbox-protocol`: JSON-RPC 2.0 envelopes (request / response /
  notification / batch, error codes incl. unknown-code passthrough), MCP tool,
  resource, prompt, completion, logging, progress and cancellation payloads,
  capability negotiation for server and client features.
- `tpt-mcpbox-protocol`: stdio transport (newline-delimited JSON, bounded line
  length, single-writer framing, stderr for logs).
- `tpt-mcpbox-protocol`: Streamable HTTP transport (`POST`/`GET`/`DELETE`,
  `Mcp-Session-Id`, SSE with resumable event ids, `Last-Event-ID` replay,
  origin validation defaulting to loopback-only, payload caps).
- `tpt-mcpbox-protocol`: session lifecycle state machine (requests refused
  before the handshake completes) and a dispatcher that shapes JSON-RPC errors
  and correlates server-to-agent `roots` / `sampling` / `elicitation` calls.

- `tpt-mcpbox-cli`: `completions <SHELL>` and `manpage <DIR>` commands.
- `tpt-mcpbox-router`: each `tools/call` runs in a `request` tracing span with
  outcome, rule id and duration; `run` honours the `logging` configuration.
- `docs/security-model.md` and `docs/integration.md`.
- `fuzz/`: cargo-fuzz targets for the JSON-RPC parser, config loader and policy
  input, run for 60 s each in CI.
- `tpt-mcpbox pull <REF>` fetches a tool module from an OCI registry into the
  cache, loads it to confirm it is a tool component, and prints its digest for
  pinning.
- OCI module sources (`oci_ref`): anonymous pulls with bearer challenges,
  redirects that never carry credentials, a content-addressed cache, digest and
  size checks, and image index selection.
- Private registry credentials through `oci_auth`, read from a secret.
- Typed tool results: a tool can declare `result: envelope-v1` and return MCP
  content blocks (text, image, embedded resource, resource link).
- The SDK returns images, embedded resources and multi-block replies.
- CI checks the licence policy in every workspace. The fuzz suite gains a
  descriptor target and a Rego target.

### Changed

- TLS uses `rustls-rustcrypto`, a pure-Rust provider, in place of `ring`.
- Outbound requests of Wasm tools are decided by the whole policy, using the
  request's host and URI.
- `paths` on a policy rule is refused when the configuration loads, because a
  tool call never carries a path.
- Rego is an in-crate interpreter for a documented subset of Rego v1, replacing
  `regorus`. Unsupported forms are refused when the module loads.
- `wasmtime` is 48.0.8. It was 34 at the start of this cycle, and the update
  clears five advisories.
- Embedded resources in MCP content follow the specification (the body sits
  under `resource`).
- The SDK's `ToolResult` holds content blocks. `ToolResult::as_text` returns
  `String`; `text` and `json` are unchanged.

### Removed

- The `regorus` and `ring` dependencies, and the bare `Apache-2.0` licence
  allowance.

### Security

- SR-01 is closed. The policy decides every outbound request of a Wasm tool, and
  an allow rule's `hosts` constrain the tool to those hosts.
- Tool network requests must resolve only to public addresses, and the
  connection goes to the address that was checked.
- Tool response bodies are capped at 16 MiB.
- Registry credentials are sent only to the token endpoint, never to a redirect
  target, and are never printed.
- Guest tool descriptors are parsed strictly: unknown fields, empty names and
  non-object schemas are refused.
- Advisories against the `rustls-rustcrypto` alpha are accepted with reasons in
  `deny.toml`, to be re-decided by 2027-02-09.

### Notes

- Crate naming convention fixed at `tpt-mcpbox-<name>`; the binary is
  `tpt-mcpbox`.
- Guest crates (`tpt-mcpbox-sdk`, `tpt-mcpbox-tool-*`) are excluded from the
  host workspace and build for `wasm32-wasip2` via `cargo-component`.
