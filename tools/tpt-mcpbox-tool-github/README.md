# tpt-mcpbox-tool-github

An example tool component for [tpt-mcpbox](../../README.md) that searches GitHub
repositories. It shows how a tool can call an authenticated API without ever
holding the credential.

It provides one tool:

| Tool | Arguments | Result |
|---|---|---|
| `search_repos` | `query` | Matching repositories from the GitHub search API |

## How the token stays out of the guest

The tool sends only the headers that identify it. It never reads `GITHUB_TOKEN`.
The configuration binds the secret to an outbound header for one host, and the
host adds the header on the way out:

```yaml
tools:
  - name: github_search
    wasm_path: ../tools/tpt-mcpbox-tool-github/target/wasm32-wasip2/release/tpt_mcpbox_tool_github.wasm
    capabilities:
      network: ["api.github.com"]
      memory_limit: "64MB"
      time_limit: "30s"
    secrets:
      - env: GITHUB_TOKEN
        header: Authorization
        prefix: Bearer
```

The token comes from the environment or a gitignored `.env` file. It is never
written in the configuration. A compromised tool can call `api.github.com`, but
it cannot read the token.

## Build

```sh
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

The output is `target/wasm32-wasip2/release/tpt_mcpbox_tool_github.wasm`.

## License

Dual licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT), at your option.
