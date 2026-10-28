# Policy guide

Every `tools/call`, resource read and prompt fetch is evaluated against the
policy before anything runs. The request is described by a policy input:

| Field | Meaning |
|-------|---------|
| `method` | The MCP method, e.g. `tools/call`. |
| `tool` | The exposed tool name. |
| `caller` | The session that made the call. |
| `arguments` | The call's arguments. Used for matching, never recorded. |
| `host` | The network host the call would reach, if any. |
| `fs_path` | The filesystem path the call would touch, if any. |
| `uris` | Resource URIs. |

Arguments are untrusted. A rule decides on the fields above, and the agent
cannot change the caller or the tool by putting keys in `arguments`.

## YAML DSL

Rules are checked in file order. A rule matches when every field it names
matches. The first matching rule decides.

```yaml
policy:
  default: deny
  rules:
    - id: allow-search
      effect: allow
      tool: github_search
      hosts: ["api.github.com"]

    - id: allow-read-workspace
      effect: allow
      tool: local_files
      method: tools/call
      args:
        operation: read
      paths: ["./workspace/**"]
      caller: "agent-*"
      constraints:
        quota:
          max_calls: 30
          window: 1m

    - id: deny-secrets
      effect: deny
      paths: ["**/.env", "**/*.pem"]
```

Matching rules:

- `tool`, `method`, `caller`: exact or glob.
- `hosts`: glob, case-insensitive, after normalisation. Look-alike Unicode
  hosts are normalised before matching.
- `paths`: glob, applied to the normalised path. Traversal such as `..` does not
  escape a match.
- `uris`: glob, applied to normalised URIs.
- `args`: each key must equal the given value.

Constraints on an allow apply to the call: `quota` (sliding window), and the
memory and time limits. When several rules allow a call, the tightest limits win.

## Rego

Set `policy.rego` to a module that declares `package tpt.mcpbox` and defines
`allow`. It reads the policy input from `input`:

```rego
package tpt.mcpbox

default allow := false

allow if {
    input.method == "tools/call"
    input.tool == "github_search"
    input.host == "api.github.com"
}
```

The module sees the same normalised host, path and URIs as the DSL, and a
request whose host, path or URI cannot be normalised is refused before the
module runs. A relative `policy.rego` path is resolved against the directory of
the configuration file.

A DSL deny always wins over Rego. An error in the module, or an undefined
`allow`, counts as a refusal. Rego is not only a filter, though: when no DSL
rule matches, a Rego allow admits the call even with `default: deny`.

## Testing a decision

```sh
tpt-mcpbox policy test input.json --config tpt-mcpbox.yaml
```

Prints the decision, the rule id and the reason. Exits 0 when allowed and 1 when
denied, so it can gate a script.

## Dry run

`policy.dry_run: true` (or `run --dry-run`) logs and audits would-be denials
without refusing the calls. It exists for migrating an existing setup. Keep it
off in production.
