# Changelog

All notable changes to `tpt-mcpbox-audit` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Hash-chained, append-only audit log (`AuditLog`) with `GENESIS` as the first
  link.
- `verify` and `VerifyReport` to check a log and report its length and head hash.
- Startup events recorded in the log.
- Recording of every tool call in the log.
- Prometheus metrics and structured tracing setup.

### Changed

- The log is locked with an OS file lock instead of a separate lock file, so a
  crash cannot leave a stale lock behind.

### Security

- A second writer on the same log is refused.
- Entries record secret names only, never values.
