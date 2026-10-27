# Changelog

All notable changes to `tpt-mcpbox-proxy` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Upstream clients for stdio (spawned and supervised child processes) and
  Streamable HTTP, with HTTPS support.
- `Connection`, so policy gates work the same way over stdio and HTTP.
- `PolicyGate`, which checks every forwarded call against the policy before it
  is sent upstream. A denied call returns `ProxyError::Denied` with the rule id.
- Forwarding of upstream resources and prompts, with the same policy checks as
  tools.
- Scrubbing of upstream stderr through the secret `Redactor` before logging.
