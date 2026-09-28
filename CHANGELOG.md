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

### Notes

- Crate naming convention fixed at `tpt-mcpbox-<name>`; the binary is
  `tpt-mcpbox`.
- Guest crates (`tpt-mcpbox-sdk`, `tpt-mcpbox-tool-*`) are excluded from the
  host workspace and build for `wasm32-wasip2` via `cargo-component`.
