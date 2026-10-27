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
