# Changelog

All notable changes to `tpt-mcpbox-policy` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- YAML DSL policy evaluator (`Engine`) with host and path normalisation.
- Embedded Rego evaluation, composed with the DSL into a single `Policy`. The
  evaluator is an in-crate interpreter for a documented subset of Rego v1; it
  replaces the earlier `regorus` engine, so the crate has no third-party Rego
  implementation.
- `PolicyInput` with caller and URI inputs, and quota checks.
- `Decision` with a reason and a rule id, plus dry-run reporting through
  `would_be`.
- Input normalisation for hosts, paths and URIs (`normalize`).
- `Policy::reload` to build a new policy from a changed configuration.
- `Policy::evaluate_recheck` decides an outbound request with the whole engine
  (DSL, Rego and default), using the request's host and URI, without spending
  quota.
- A Rego subset interpreter with load-time refusal of unsupported forms, a step
  budget, and builtins for string, type and normalisation checks.

### Changed

- Rego evaluation is an in-crate interpreter, replacing `regorus`.
- `Policy::outbound_denial` is replaced by `evaluate_recheck`.

### Removed

- The `regorus` dependency.

### Security

- An allow rule's `hosts` constrain a tool's outbound requests (SR-01).

