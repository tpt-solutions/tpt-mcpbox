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
- **Verified tool modules.** Each `.wasm` can be pinned by SHA-256 and, when a
  minisign key is configured, must carry a valid signature before it runs.
- **Scanned upstream responses.** Tool results and text resources from upstream
  servers can be checked against regex rules that redact or refuse them before
  they reach the agent.
- **Tamper-evident audit trail.** Every call, policy decision and secret
  injection is hash-chained, and the log rolls into numbered segments that stay
  in one chain. `tpt-mcpbox audit verify` detects tampering.

## Status

**Pre-release.** Nothing is published yet; `v0.1.0` is in progress. The core
pieces are built and tested: protocol, configuration, policy, Wasm runtime,
router, upstream proxy, guest SDK, observability and the CLI. Security review
fixes are in progress. See [todo.md](todo.md) for the full checklist.

| Phase | Scope | State |
|---|---|---|
| 0 | Bootstrap & governance | done |
| 1 | MCP protocol core (`tpt-mcpbox-protocol`) | done |
| 2 | Configuration & secrets (`tpt-mcpbox-config`) | largely done; hot reload open |
| 3 | Policy engine (`tpt-mcpbox-policy`) | largely done; reload wiring open |
| 4 | Wasm runtime (`tpt-mcpbox-runtime`) | largely done; OCI module pull open |
| 5 | Router & rate limiter (`tpt-mcpbox-router`) | largely done |
| 6 | Passthrough proxy (`tpt-mcpbox-proxy`) | largely done |
| 7 | Guest tool SDK (`tpt-mcpbox-sdk`) | largely done |
| 8 | Example tools (`tools/`) | largely done; release assets open |
| 9 | Observability (`tpt-mcpbox-audit`) | largely done |
| 10 | CLI (`tpt-mcpbox-cli`) | largely done; `pull` open |
| 11 | Security hardening & review | in progress |
| 12 | Documentation & release | in progress; crates.io and tagged release open |

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
| `tpt-mcpbox-proxy` | lib | Policy-enforcing passthrough to supervised upstream MCP servers |
| `tpt-mcpbox-router` | lib | Namespaced aggregation, rate limiting, cancellation, graceful shutdown |
| `tpt-mcpbox-audit` | lib | Hash-chained, segmented audit log and tracing setup |
| `tpt-mcpbox-cli` | bin | The `tpt-mcpbox` binary |
| `tpt-mcpbox-sdk` | guest | SDK for authoring tools (excluded from the workspace) |
| `tools/tpt-mcpbox-tool-github`, `tools/tpt-mcpbox-tool-fs` | guest | Example tools (excluded) |

## Quickstart

```console
git clone https://github.com/tpt-solutions/tpt-mcpbox
cd tpt-mcpbox
cargo build --release
./target/release/tpt-mcpbox version
```

Write a starter configuration, check it, then serve it:

```console
tpt-mcpbox init                              # writes tpt-mcpbox.yaml
tpt-mcpbox validate --config tpt-mcpbox.yaml
tpt-mcpbox run --config tpt-mcpbox.yaml
```

Other commands:

- `tpt-mcpbox tools ls` lists the tools a configuration exposes.
- `tpt-mcpbox tools call <NAME> --args '<JSON>'` calls one tool through the same
  policy, limits and audit log as `run`.
- `tpt-mcpbox policy test <input.json>` explains a decision and exits 1 on deny.
- `tpt-mcpbox audit verify` checks the audit chain.
- `tpt-mcpbox init tool <DIR> --sdk-path <PATH>` scaffolds a new tool project.

Wire it into an MCP client (Claude Code / Claude Desktop):

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

A minimal configuration, trimmed from [examples/tpt-mcpbox.yaml](examples/tpt-mcpbox.yaml):

```yaml
version: 1

server:
  transports: [stdio]

tools:
  - name: github_search
    wasm_path: ./tools/tpt-mcpbox-tool-github.wasm
    capabilities:
      network: ["api.github.com"]
      memory_limit: "64MB"
      time_limit: "30s"   # required for any tool with network access
    secrets:
      - env: GITHUB_TOKEN          # read from the environment or ./.env
        header: Authorization      # injected by the host, never seen by the tool
        prefix: Bearer
  - name: local_files
    wasm_path: ./tools/tpt-mcpbox-tool-fs.wasm
    capabilities:
      filesystem:
        read: ["./workspace/**"]
        write: ["./workspace/output/**"]
      memory_limit: "64MB"
      time_limit: "10s"

policy:
  default: deny                    # anything not named below is refused
  rules:
    - id: allow-search
      effect: allow
      tool: search_repos
    - id: allow-read
      effect: allow
      tool: read_file
    - id: allow-list
      effect: allow
      tool: list_dir
    - id: allow-write
      effect: allow
      tool: write_file

audit:
  enabled: true
  path: .mcpbox/audit.log
```

Build the example tools with `cargo build --release --target wasm32-wasip2` in
each `tools/` crate first. The paths in the sample configuration assume that.

Documentation:

- [docs/integration.md](docs/integration.md) — wiring into MCP clients, HTTP
  transport and bearer tokens.
- [docs/architecture.md](docs/architecture.md) — components and data flow.
- [docs/security-model.md](docs/security-model.md) — threat model, trust
  boundaries and residual risks.

## Development

```console
cargo build                 # build the workspace
cargo test --workspace      # unit + integration tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Requires a current stable toolchain (see `rust-toolchain.toml`). The MSRV is
**1.95** (`rust-version` in the workspace `Cargo.toml`) and is enforced in CI.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: see
[SECURITY.md](SECURITY.md).

## License

Dual licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option. See [NOTICE](NOTICE).
