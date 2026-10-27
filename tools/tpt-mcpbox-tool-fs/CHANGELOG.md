# Changelog

All notable changes to `tpt-mcpbox-tool-fs` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The crate is an example and is not published (`publish = false`).

## [Unreleased]

### Added

- `read_file`, `list_dir` and `write_file` tools over a read root and a write
  root that the host preopens.
- Path checks that refuse absolute paths and `..` segments before the sandbox
  is reached.
