# tpt-mcpbox-http

The HTTP/1.1 server surface used by the MCP transports: exact-path routing by
method, request and response bodies, JSON and server-sent-event responses, and
a graceful serve loop. It is built on `hyper` and `tower`, and it replaces the
`axum` subset this workspace used, so that no Apache-2.0-only crate is pulled
in through the server stack.

It is deliberately small. It has no extractors beyond `State`, no middleware
layers, and no multipart or WebSocket support. Body limits are enforced by the
handler with [`to_bytes`], as the transports already do.
