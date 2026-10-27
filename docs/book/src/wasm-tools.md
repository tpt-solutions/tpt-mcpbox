# Writing Wasm tools

A tool is a `wasm32-wasip2` component that exports the tpt-mcpbox tool world.
The guest SDK, `tpt-mcpbox-sdk`, provides the `Tool` trait, a macro that exports
a set of tools, JSON results and an HTTP helper that goes through the host.

The SDK's own guide follows. It is the same file as in the repository.

{{#include ../../../crates/tpt-mcpbox-sdk/README.md}}

## Building and granting

```sh
cd tools/tpt-mcpbox-tool-fs
cargo build --release --target wasm32-wasip2
sha256sum target/wasm32-wasip2/release/tpt_mcpbox_tool_fs.wasm
```

Then point a `tools` entry at the file and grant only what it needs. The
example configuration in `examples/tpt-mcpbox.yaml` shows both example tools.

Remember that a grant is what the tool can reach, not what it should reach. The
guest's own checks are advisory; the host's preopens and allowlists are what
enforce the grant.
