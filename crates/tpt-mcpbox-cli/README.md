# tpt-mcpbox-cli

The `tpt-mcpbox` command-line tool. It is the front end for the
[tpt-mcpbox](../../README.md) hub: it starts the server, checks configuration,
explains policy decisions, verifies the audit log, and scaffolds new tools.

The binary is named `tpt-mcpbox`. The crate is `tpt-mcpbox-cli`.

> **Status: pre-release (0.1.0 in progress).** Commands and flags may change
> before 0.1.0. Run `tpt-mcpbox <command> --help` for the current options.

## Commands

| Command | What it does |
|---|---|
| `run` | Serves the configured tools and upstreams over stdio, and over Streamable HTTP when configured. Stdout carries the protocol, so logs go to stderr only. |
| `validate` | Loads a configuration and reports every problem with it. `--warn-only` reports without failing. `--offline` skips checks that need the host, such as secrets and files on disk. |
| `schema` | Prints the JSON Schema for `tpt-mcpbox.yaml`. `-o`/`--output` also writes it to a file. |
| `init` | Writes a starter `tpt-mcpbox.yaml`. `-o`/`--output` chooses the path, and `--force` overwrites an existing file. |
| `init tool <DIR>` | Scaffolds a tool component project in `DIR`. `--sdk-path` points at the `tpt-mcpbox-sdk` crate, which is written as a path dependency because the SDK is not published yet. |
| `tools ls` | Lists the tools the configuration exposes |
| `tools call <NAME>` | Calls one tool and prints its result. `-a`/`--args` takes a JSON object. It goes through the same policy, limits and audit log as `run`, so it is refused while a hub is running against the same audit log. |
| `policy test <INPUT>` | Evaluates one policy input, read from a JSON file, and prints the decision. The file has `method`, `tool`, `arguments` and, optionally, `caller`, `host`, `fs_path` and `uris`. Exits 0 when allowed and 1 when denied. |
| `audit verify <PATH>` | Checks the hash chain and reports the first break. A break is an error, so the exit code is non-zero. |
| `completion <SHELL>` | Prints a shell completion script to stdout |
| `man <DIR>` | Writes man pages for the command and its subcommands into `DIR` |
| `version` | Prints the version and exits |

Most commands take `-c`/`--config` to name a configuration file. When it is
omitted, the file is discovered from the working directory.

## Quickstart

```console
tpt-mcpbox init                       # write a starter tpt-mcpbox.yaml
tpt-mcpbox validate                   # check it
tpt-mcpbox policy test input.json     # explain the decision for one input
tpt-mcpbox run                        # serve over stdio
```

`input.json` is a policy input, for example:

```json
{ "method": "tools/call", "tool": "read_file", "arguments": { "path": "notes.md" } }
```

Build the example tools first. The sample configuration in
[`examples/tpt-mcpbox.yaml`](../../examples/tpt-mcpbox.yaml) expects them. Set
the secrets it names, such as `GITHUB_TOKEN`, in the environment or in a `.env`
file next to the configuration. Never put a token in the configuration itself.

## Connecting an MCP client

Once the hub is built, point an MCP client at it. For Claude Code or Claude
Desktop, use the stdio form:

```json
{
  "mcpServers": {
    "tpt-mcpbox": {
      "command": "tpt-mcpbox",
      "args": ["run", "--config", "./tpt-mcpbox.yaml"]
    }
  }
}
```

## HTTP serving

`run` serves Streamable HTTP when `server.transports` includes `http`. A
listener that is not on loopback needs a bearer token. The token is read from the
environment variable named by `server.http.bearer_env`, and it is never written
in the configuration.

Prometheus metrics are served on a loopback listener when `metrics` is enabled.

## Exit codes

- `validate`, `audit verify` and `policy test` set the exit code, so a script can
  gate on them.
- `run` stops on Ctrl-C or SIGTERM. It drains in-flight calls before it exits.

## Using the crate

The crate is not yet published to crates.io. Build the binary from the workspace:

```console
cargo build --release -p tpt-mcpbox-cli
./target/release/tpt-mcpbox --version
```

The minimum supported Rust version is **1.85**.

## Testing

```console
cargo test -p tpt-mcpbox-cli
```

## License

Dual licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT), at your option.
