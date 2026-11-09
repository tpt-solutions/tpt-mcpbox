# Changelog

All notable changes to `tpt-mcpbox-sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The crate is not published (`publish = false`) and is excluded from the host
workspace.

## [Unreleased]

### Added

- Guest SDK for tool components: the `Tool` trait, `ToolResult`, `ToolError`
  and the `export_tools!` macro.
- `http` helpers (`get_json`, `post_json`, `get_json_with_headers`) that go
  through the host's outbound `wasi:http` handler.
- `examples/hello`, a worked example with `greet`, `add` and `fetch`.
- `ToolResult::image`, `ToolResult::resource_text` and `ToolResult::with_block`.
- The SDK declares `result: envelope-v1` in `describe`, and replies are MCP
  content blocks.

### Changed

- `ToolResult` holds content blocks. `ToolResult::as_text` now returns `String`
  and joins the text blocks. `ToolResult::text` and `ToolResult::json` are
  unchanged.

