# Changelog

All notable changes to `tpt-mcpbox-router` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Router` with `add_wasm` and `add_upstream`, dispatching `call` to the owning
  source.
- Namespaced aggregation of tools, resources and prompts from every source.
- `Limiter` with per-tool and per-client rate and concurrency limits.
- `Lifecycle` with graceful shutdown: new calls are refused, and in-flight calls
  drain up to a timeout.
- `Metrics` with per-outcome call counts, exposed on a loopback Prometheus
  listener.
- Audit recording of every call through `Router::with_audit`.
- Resource and prompt routing, with policy checks on every read.
