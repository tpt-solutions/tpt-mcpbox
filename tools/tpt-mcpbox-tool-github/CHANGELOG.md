# Changelog

All notable changes to `tpt-mcpbox-tool-github` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The crate is an example and is not published (`publish = false`).

## [Unreleased]

### Added

- `search_repos` tool that queries the GitHub repository search API.
- The GitHub token is injected by the host as the `Authorization` header and is
  never visible to the tool.
- Percent-encoding of query text for the search URL.
