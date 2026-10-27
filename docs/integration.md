# Integration guide: Claude Code and Claude Desktop

This guide shows how to register tpt-mcpbox as an MCP server in Claude Code or
Claude Desktop, so that the agent reaches its tools only through the hub's
policy, limits and audit log.

It assumes you have a working configuration. Create a starter one with
`tpt-mcpbox init`, then check it with `tpt-mcpbox validate`.

## 1. Build or install the binary

```sh
cargo install --path crates/tpt-mcpbox-cli
tpt-mcpbox version
```

Use the absolute path to the binary in the client configuration below. Client
applications do not always inherit your shell `PATH`.

## 2. Check the configuration before wiring it in

```sh
tpt-mcpbox validate --config /absolute/path/to/tpt-mcpbox.yaml
tpt-mcpbox tools ls --config /absolute/path/to/tpt-mcpbox.yaml
```

`tools ls` shows exactly what the agent will see. If a tool is missing there, it
is not reachable by the agent either. To see why a call would be refused without
making it:

```sh
tpt-mcpbox policy test input.json --config /absolute/path/to/tpt-mcpbox.yaml
```

## 3. Stdio (recommended)

Claude Code runs the hub as a child process and talks to it over stdin and
stdout. Nothing listens on the network.

Add it to a project-scoped `.mcp.json`, or to the user configuration with
`claude mcp add`:

```json
{
  "mcpServers": {
    "tpt-mcpbox": {
      "command": "C:/tools/tpt-mcpbox.exe",
      "args": ["run", "--config", "C:/work/project/tpt-mcpbox.yaml"]
    }
  }
}
```

Claude Desktop uses the same shape under `mcpServers` in
`claude_desktop_config.json`.

Secrets are read by the hub, not by the client. Keep them in the environment of
the hub process, or in a gitignored `.env` file next to the configuration. Do
not put them in the client configuration file, which is often committed.

Logs go to stderr, which the client shows in its MCP log. Stdout carries the
protocol and must stay clean.

## 4. Streamable HTTP (optional)

Use HTTP when the client cannot launch a child process, or when several clients
share one hub. Enable the transport in the configuration:

```yaml
server:
  transports: [stdio, http]
  http:
    bind: 127.0.0.1:8899
    allowed_origins: []
    bearer_env: MCPBOX_TOKEN
```

Loopback is the default and the safe choice. A non-loopback bind is refused
unless `bearer_env` names a secret, and the hub then requires that token on every
request. Set the token in the environment, never in the configuration file:

```sh
export MCPBOX_TOKEN="$(openssl rand -hex 32)"
tpt-mcpbox run --config /absolute/path/to/tpt-mcpbox.yaml
```

Register the endpoint in the client. Claude Code reads the token from the
environment through `${VAR}` expansion, so the file itself holds no secret:

```json
{
  "mcpServers": {
    "tpt-mcpbox": {
      "type": "http",
      "url": "http://127.0.0.1:8899/mcp",
      "headers": {
        "Authorization": "Bearer ${MCPBOX_TOKEN}"
      }
    }
  }
}
```

Requests carrying an `Origin` header are accepted only from loopback origins,
or from the origins listed in `allowed_origins`. Anything else gets a 403.

## 5. Verify the connection

1. Start the client and open its MCP server list. `tpt-mcpbox` should show as
   connected, with the tools from `tools ls`.
2. Ask the agent to call an allowed tool. Then check the audit log:

   ```sh
   tpt-mcpbox audit verify --config /absolute/path/to/tpt-mcpbox.yaml
   ```

   The log should show a `start` and a `finish` record for the call, with the
   argument key names and no values.
3. Ask the agent to call a tool the policy does not allow. The call should fail
   with a denial that names the reason and the rule id.

## 6. Things to know

- **One writer per audit log.** A second hub, or `tools call`, against the same
  audit log is refused while the first one is running. Stop the hub, or point
  the second command at another configuration.
- **Reloading.** Configuration is read at start. Restart the hub after editing
  `tpt-mcpbox.yaml`; hot reload is not yet wired to the running hub.
- **Tool names.** Tools are exposed under their configured names. Two
  upstreams that export the same tool name cause a refusal at startup rather
  than a silent rename, so rename one in its upstream configuration.
- **Debugging a tool.** `tpt-mcpbox tools call <NAME> --args '{"path":"notes.md"}'`
  runs one call through the same policy, limits and audit log as the hub.

See [security-model.md](security-model.md) for what the hub does and does not
protect against.
