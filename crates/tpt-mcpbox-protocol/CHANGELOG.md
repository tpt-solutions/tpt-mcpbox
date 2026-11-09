# Changelog

All notable changes to `tpt-mcpbox-protocol` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- JSON-RPC 2.0 envelopes (request, response, notification, batch) with JSON-RPC
  and MCP error codes, including passthrough of unknown error codes.
- MCP payloads for tools, resources, prompts, completion and utilities
  (progress, cancellation, logging).
- Capability negotiation for server features and for the client features
  `roots`, `sampling` and `elicitation`, which are routed back to the agent.
- Content types: text, image, audio, embedded resource and resource links.
- stdio transport: newline-delimited JSON, a bounded line length, single-writer
  framing, and logs on stderr.
- Streamable HTTP transport: `POST`, `GET` and `DELETE`, `Mcp-Session-Id`, SSE
  responses with resumable event ids and `Last-Event-ID` replay, origin
  validation (loopback only by default) and payload caps.
- Session lifecycle state machine. Requests are refused before the handshake
  completes.
- Dispatcher that shapes JSON-RPC errors and correlates server-to-agent
  requests.
- Protocol versions `2025-06-18` (latest), `2025-03-26` and `2024-11-05`.
- `tools::parse_descriptors` reads a component's descriptors strictly, returning
  `GuestTool` values that carry their `ResultFormat`.
- `tools::decode_result` decodes a call result: plain text, or a `envelope-v1`
  envelope of content blocks. A malformed envelope is refused without echoing
  its contents.

### Changed

- `Content::Resource` carries `EmbeddedResource { resource }`, the shape the
  specification uses. Code that matched the flat shape must change.

### Fixed

- Embedded resource blocks from MCP servers, which nest the body under
  `resource`, now parse.

