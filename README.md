# tpt-mcpbox

**A local-first, zero-trust MCP proxy and WebAssembly tool runtime.**

`tpt-mcpbox` sits between an AI agent and the tools it wants to use. It speaks
[MCP](https://modelcontextprotocol.io) to the agent, enforces capability-based
policy on every call, executes tool logic inside WebAssembly sandboxes with no
ambient authority, and proxies — under the same policy — to external MCP servers
you did not write.

```
[ AI agent ] --MCP (stdio | Streamable HTTP)--> [ tpt-mcpbox ] -- policy --> [ Wasm tools ]
                                                                    \-- policy --> [ upstream MCP servers ]
```

## Why

An agent that can call tools can call *anything* the process can reach. Host-OS
permissions are too coarse: once a tool process runs, it has your filesystem,
your network and your credentials. Prompt injection turns that into remote code
execution. `tpt-mcpbox` makes the blast radius explicit and small:

- **No ambient authority.** A tool gets exactly the filesystem paths and network
  hosts its policy grants, and nothing else.
- **Secrets never enter the guest.** The proxy intercepts outbound HTTP and
  injects `Authorization` headers at the proxy layer, so a compromised tool
  cannot read the token it was issued.
- **Hard resource limits.** Memory, execution time and rate limits are enforced
  per tool and per client, so a runaway call cannot take the host with it.
- **Tamper-evident audit trail.** Every call, policy decision and secret
  injection is hash-chained; `tpt-mcpbox audit verify` detects tampering.

## Status

**Pre-release (v0.1.0 in progress).** See [todo.md](todo.md) for the phased
plan and current state.

| Phase | Scope | State |
|---|---|---|
| 0 | Bootstrap & governance | in progress |
| 1 | MCP protocol core (`tpt-mcpbox-protocol`) | in progress |
| 2-12 | config, policy, runtime, proxy, SDK, audit, CLI, hardening, release | not started |

## Layout

All crates carry the `tpt-mcpbox-` prefix. Crates that run on the host are
workspace members; guest (Wasm) crates are excluded because they do not build
for the host target.

| Crate | Kind | Purpose |
|---|---|---|
| `tpt-mcpbox-protocol` | lib | JSON-RPC 2.0 / MCP types, stdio + Streamable HTTP transports, session and dispatch |
| `tpt-mcpbox-config` | lib | `tpt-mcpbox.yaml` model, validation, discovery, secrets |
| `tpt-mcpbox-policy` | lib | Deny-by-default policy engine (YAML DSL + embedded Rego) |
| `tpt-mcpbox-runtime` | lib | `wasmtime` component runtime, warm pool, WASI capability mapper |
| `tpt-mcpbox-proxy` | lib | Policy-enforcing passthrough to upstream MCP servers |
| `tpt-mcpbox-router` | lib | Namespaced aggregation, rate limiting, graceful shutdown |
| `tpt-mcpbox-audit` | lib | Hash-chained audit log, tracing setup, Prometheus metrics |
| `tpt-mcpbox-cli` | bin | The `tpt-mcpbox` binary |
| `tpt-mcpbox-sdk` | guest | SDK for authoring tools (excluded from the workspace) |
| `tpt-mcpbox-tool-github`, `tpt-mcpbox-tool-fs` | guest | Example tools (excluded) |

## Quickstart

```console
git clone https://github.com/tpt-solutions/tpt-mcpbox
cd tpt-mcpbox
cargo build --release
./target/release/tpt-mcpbox --version
```

Wire it into an MCP client (Claude Code / Claude Desktop) once the CLI lands:

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

A minimal configuration mirrors the design spec:

```yaml
tools:
  - name: github_search
    wasm_path: ./tools/tpt-mcpbox-tool-github.wasm
    capabilities:
      network: ["api.github.com"]
      memory_limit: "64MB"
    secrets:
      - GITHUB_TOKEN
  - name: local_files
    wasm_path: ./tools/tpt-mcpbox-tool-fs.wasm
    capabilities:
      filesystem:
        read: ["./workspace/**"]
        write: ["./workspace/output/**"]
```

## Development

```console
cargo build                 # build the workspace
cargo test --workspace      # unit + integration tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Requires a current stable toolchain (see `rust-toolchain.toml`); the MSRV is
**1.85** and is enforced in CI.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: see
[SECURITY.md](SECURITY.md).

## License

Dual licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option. See [NOTICE](NOTICE).
