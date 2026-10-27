# Changelog

All notable changes to `tpt-mcpbox-policy` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- YAML DSL policy evaluator (`Engine`) with host and path normalisation.
- Embedded Rego evaluation through `regorus`, composed with the DSL into a
  single `Policy`.
- `PolicyInput` with caller and URI inputs, and quota checks.
- `Decision` with a reason and a rule id, plus dry-run reporting through
  `would_be`.
- Input normalisation for hosts, paths and URIs (`normalize`).
- `Policy::reload` to build a new policy from a changed configuration.
