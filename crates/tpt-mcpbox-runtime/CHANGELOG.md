# Changelog

All notable changes to `tpt-mcpbox-runtime` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Wasm component runtime on `wasmtime` 34 with the component model and WASI
  Preview 2 (`Runtime`, `LoadedTool`).
- Pooling allocator for warm instance reuse.
- Sandbox: filesystem grants as preopened directories, and no ambient
  environment access.
- Outbound `wasi:http` handler that enforces the domain allowlist and HTTPS,
  and injects secret headers.
- Memory limits through `StoreLimits`, time limits, and `CancelToken`.
- SHA-256 pinning of tool modules.
- `Runtime::self_test` to prove the sandbox at startup.
- The `tpt:mcpbox/tool` WIT world (`wit/tool.wit`).
- OCI module pulls (`oci` module): reference parsing, anonymous bearer-token
  pulls, redirects, digest and size checks, image index selection, and a
  content-addressed cache.
- `Runtime::load_tool_async` loads `oci_ref` tools, with credentials resolved
  from the secret store.
- `ToolError::ModuleFetch` for modules that cannot be fetched or do not pass
  their pins.
- An outbound send path (`send`) in place of wasmtime's default one, so the
  crate has no `ring`. Tool connections refuse non-public addresses and connect
  to the address that was checked.
- Tool response bodies are capped at 16 MiB.

### Changed

- `wasmtime` is 48.0.8 (it was 34 at the start of this cycle). `wasmtime-wasi-
  http` is built without its default send path.
- `HostCheck` receives the request URI as well as the host.

### Security

- Tool connections are refused for host-internal addresses (SSRF), including
  cloud metadata addresses.
- Registry credentials are sent only to the token endpoint.

