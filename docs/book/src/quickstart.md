# Quickstart

```sh
# 1. Build the binary.
cargo install --path crates/tpt-mcpbox-cli

# 2. Write a starter configuration and check it.
tpt-mcpbox init
tpt-mcpbox validate

# 3. See what the agent would be offered, and why a call would be refused.
tpt-mcpbox tools ls
tpt-mcpbox policy test input.json

# 4. Serve the configured tools on stdio.
tpt-mcpbox run
```

`init` writes `tpt-mcpbox.yaml` with deny-by-default policy and audit logging
on. `validate` reports every problem at once, and warns about secrets that are
referenced but not set. `run` refuses to start when validation finds an error.

To debug one tool without an agent, call it through the same policy, limits and
audit log:

```sh
tpt-mcpbox tools call local_files --args '{"path":"notes.md"}'
```

Next, connect a client: see [Integrating with Claude Code and Claude Desktop](integration.md).
