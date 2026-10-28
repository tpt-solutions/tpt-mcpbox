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
    minisign_key: "RWQ…"     # optional: refuse unless `<wasm_path>.minisig` verifies under this key
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
        hosts: ["api.github.com"]   # hosts it may be sent to; set this for credentials
    limits:
      max_concurrent_calls: 4
      max_argument_bytes: 65536
```

A write grant must name a directory, or a directory tree ending in `/**`; a
wildcard anywhere else, such as `workspace/*.log`, is refused at load.

Set `sha256` once the module is built (`sha256sum file.wasm`). An unpinned
module still loads, with a warning that prints its digest.

To require a signature, set `minisign_key` to the public key from `minisign -G`,
and sign the module with `minisign -Sm file.wasm`. The signature must sit beside
the module as `file.wasm.minisig`. A module that does not verify under the key is
refused before it is compiled.

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
      describe: { "docs://guide": "The onboarding guide" }
```

Renames apply before the prefix. Policy rules match the name the agent calls,
so an allow for the upstream's tool is written as `kb__find`, not `search_docs`.
The upstream itself is still called by its own name, and two upstreams that
expose the same tool name can be allowed separately.
Resource templates are hidden whenever `resources` is set, because a template
can reach URIs the filter would refuse. A resource's description can be replaced
under `resources.describe`, keyed by its URI, and an override for a URI the
upstream does not list is refused at startup.

Responses can be scanned on the way back to the agent. Each rule is a regular
expression, run in order over tool text, text resources and every string in
`structuredContent`:

```yaml
upstreams:
  - name: kb
    transport:
      stdio: { command: kb-server }
    scan:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"   # default action: redact
      - name: card_number
        pattern: "\\b(?:\\d[ -]?){13,16}\\b"
        action: refuse                # the agent gets no part of the response
```

A `redact` match becomes `[redacted:<name>]`. A `refuse` match fails the call
with an error that names the rule, and the audit record carries the same rule
id. The matched text is never logged or returned. Binary resources and
prompts are not scanned yet.

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
  key_env: MCPBOX_AUDIT_KEY # secret that keys the chain (HMAC-SHA256)
```

Set `key_env` to the name of a secret, in the environment or the `.env` file. The
chain is then keyed, and `tpt-mcpbox audit verify --config` needs the same secret.
Without a key, anyone who can write the log can rebuild its whole chain, and the
loader warns. A log written with a key cannot be opened without it, and the
reverse holds too.

`max_segment_bytes` (default 64 MB) rolls the log into numbered segments,
`audit.log.1`, `audit.log.2` and so on. The chain runs across them, and
`tpt-mcpbox audit verify` checks every segment. `sign` is accepted by the schema
but not acted on yet.
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
