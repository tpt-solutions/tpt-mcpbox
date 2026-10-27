# Changelog

All notable changes to `tpt-mcpbox-cli` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `tpt-mcpbox run` serves the hub over stdio, and over Streamable HTTP when
  configured.
- `tpt-mcpbox validate` and `tpt-mcpbox schema`.
- `tpt-mcpbox audit verify`, which exits non-zero on a broken chain.
- `tpt-mcpbox policy test`, which prints the decision for one input and exits 0
  when allowed and 1 when denied.
- `tpt-mcpbox init` writes a starter configuration. `tpt-mcpbox init tool`
  scaffolds a tool component project.
- `tpt-mcpbox tools ls` and `tools call`, for listing and calling tools while
  debugging.
- `tpt-mcpbox version`.
- Prometheus metrics on a loopback listener.

### Security

- Non-loopback HTTP requires a bearer token.
- Every reply is scrubbed of secret values, and the server stops cleanly on
  Ctrl-C or SIGTERM.
- Upstream stderr is redacted before it is logged.
