# Configuration reference

The configuration is one YAML file, `tpt-mcpbox.yaml`. It is found by
`--config`, then `$MCPBOX_CONFIG`, then the working directory, then the user
configuration directory. A `tpt-mcpbox.local.yaml` next to it can add tools and
upstreams, and nothing else.

Unknown keys are errors, so a misspelt key cannot silently switch a protection
off. The machine-readable schema is printed by `tpt-mcpbox schema`, which most
editors can use for completion.

## Top level

| Key | Purpose |
|-----|---------|
| `version` | Must be `1`. |
| `tools` | Wasm tools the hub runs. |
| `upstreams` | External MCP servers the hub forwards to. |
| `server` | Agent-facing transports. |
| `policy` | Rules and the default decision. |
| `audit` | The hash-chained audit log. |
| `metrics` | The Prometheus listener. |
| `logging` | Log level and format. |

## `tools`

```yaml
tools:
  - name: github_search
    description: Search GitHub repositories
    wasm_path: ./tools/github.wasm
    sha256: "9f2c…"          # refuse the module unless its bytes hash to this
    enabled: true
    capabilities:
      network: ["api.github.com"]   # host allowlist; empty means no network
      filesystem:
        read: ["./workspace/**"]
        write: ["./workspace/output/**"]
      memory_limit: "64MB"
      time_limit: "30s"             # required for any tool with network access
      env: []                       # environment variables the guest may read
    secrets:
      - env: GITHUB_TOKEN           # name of the variable the hub reads
        header: Authorization       # outbound header it is injected into
        prefix: Bearer              # optional prefix on the header value
    limits:
      max_concurrent_calls: 4
      max_argument_bytes: 65536
```

Set `sha256` once the module is built (`sha256sum file.wasm`). An unpinned
module still loads, with a warning that prints its digest.

## `upstreams`

Each upstream is either a stdio child process or a Streamable HTTP endpoint,
with an optional name prefix. Names exposed by an upstream are prefixed so they
cannot shadow a Wasm tool. A duplicate name across all sources is an error at
startup, not a silent rename. The exact fields are in the schema.

What an upstream exposes can be narrowed and reshaped. Keys always name the
upstream's own tool, prompt or resource, and a rename or override that names
something the upstream does not list is refused at startup.

```yaml
upstreams:
  - name: kb
    transport:
      stdio: { command: kb-server }
    prefix: kb__
    allow: ["search*", "get_*"]    # tools: globs; empty means all
    deny: ["get_secret"]           # tools: hidden even if allowed
    tools:
      rename: { search_docs: find }      # agents see kb__find
      describe: { find: "Search the knowledge base" }
    prompts:
      allow: ["summar*"]
      rename: { summarise: summary }
    resources:
      deny: ["secret://*"]         # by URI; also hides resource templates
```

Renames apply before the prefix. Policy rules match the upstream's own name,
and so does the upstream, so a rename does not change what a rule must allow.
Resource templates are hidden whenever `resources` is set, because a template
can reach URIs the filter would refuse. Resource descriptions cannot be
overridden.

## `server`

```yaml
server:
  transports: [stdio, http]
  http:
    bind: 127.0.0.1:8899
    allowed_origins: []        # extra Origin values to accept
    bearer_env: MCPBOX_TOKEN   # name of the variable holding the bearer token
```

Loopback is the default bind. A non-loopback bind is refused unless
`bearer_env` is set. `run --transport` overrides this list for one run.

## `policy`

```yaml
policy:
  default: deny     # keep this; `allow` is refused unless dry_run is on
  dry_run: false    # log would-be denials without refusing
  rules: []         # see the policy guide
  rego: ./policy.rego
```

## `audit`

```yaml
audit:
  enabled: true
  path: .mcpbox/audit.log   # relative paths resolve against the config file
```

`sign` and `max_segment_bytes` are accepted by the schema but not acted on yet.
See [Operations](operations.md).

## `metrics` and `logging`

```yaml
metrics:
  enabled: true
  bind: 127.0.0.1:9464       # must be loopback

logging:
  level: info                # debug, info, warn or error
  json: true                 # JSON lines on stderr; false for a terminal
  spans: true                # include the request span in JSON output
```

`RUST_LOG` overrides `logging.level` for one run.
