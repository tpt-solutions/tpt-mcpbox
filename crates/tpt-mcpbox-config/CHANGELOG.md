# Changelog

All notable changes to `tpt-mcpbox-config` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Configuration model (`model`) with unknown fields rejected at parse time.
- Human-friendly units (`units`): byte sizes and durations, with formatters.
- Discovery, layering and parsing (`load`).
- Semantic validation (`validate`) with `ValidationMode`. `Serve` mode refuses
  `policy.default: allow`.
- Secret handling (`secrets`): `SecretString`, environment and `.env` sources,
  outbound header injection, and the central `Redactor`.
- JSON Schema emission (`schema`) for editor completion and CI checks.
- Polling hot-reload watcher and atomic swap handle (`reload`).
- Bearer-token requirement for non-loopback HTTP listeners.
- `ToolConfig::oci_auth` (`OciAuth { secret }`): credentials for a private OCI
  registry, read from a secret whose value is `username:password`.

### Changed

- Validation refuses `paths` on any policy rule, because the policy never sees a
  tool call's path.
- `hosts` on a deny rule is enforced on outbound requests, so it no longer draws
  a warning.
- Validation refuses `oci_auth` on a tool that has no `oci_ref`.
- The JSON Schema gains `oci_auth`.

