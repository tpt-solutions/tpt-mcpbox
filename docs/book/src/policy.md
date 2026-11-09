# Policy guide

Every `tools/call`, resource read and prompt fetch is evaluated against the
policy before anything runs. The request is described by a policy input:

| Field | Meaning |
|-------|---------|
| `method` | The MCP method, e.g. `tools/call`. |
| `tool` | The exposed tool name. |
| `prompt` | The prompt name for `prompts/get`, as the agent sees it. |
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
      caller: "agent-*"
      constraints:
        quota:
          max_calls: 30
          window: 1m

    - id: deny-evil-hosts
      effect: deny
      tool: github_search
      hosts: ["*.evil.test"]
```

Matching rules:

- `tool`, `prompt`, `method`, `caller`: exact or glob. A `prompt` rule never
  matches a tool call, and a `tool` rule never matches a prompt.
- `hosts` applies to each outbound request a Wasm tool makes, as well as to the
  call itself. The whole policy is consulted for each request, so an allow rule
  that names hosts admits the tool only for those hosts, and a deny rule refuses
  the hosts it names. A request that no rule admits is refused by the default.
  Upstream calls are not host-checked, because their destination is the
  configured upstream.
- `paths` is refused by the loader. A tool call never carries a filesystem path
  for the policy to match, so the rule would never apply. Limit filesystem
  access with the tool's `capabilities.filesystem` grants instead. See the
  security review, SR-01.
- `hosts`: glob, case-insensitive, after normalisation. Look-alike Unicode
  hosts are normalised before matching.
- `uris`: glob, applied to normalised URIs.
- `args`: each key must equal the given value, by exact JSON equality. `"Write"`
  is not `"write"`, `1.0` is not `1`, and a missing key never matches. A deny that
  matches only on `args` is easy to step around, so name the tool too; the loader
  warns about such a rule.

Constraints on an allow apply to the call: `quota` (sliding window), and the
memory and time limits. When several rules allow a call, the tightest limits win.

A quota has one budget per caller by default. Set `shared: true` for one budget
that every caller of the rule draws on. A client that starts a new session gets
a fresh per-caller budget, so use `shared` for a limit that must hold.

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

Arguments are raw, so a rule that compares one normalises it first with a
builtin: `tpt.normalize_host(x)`, `tpt.normalize_path(x)` or `tpt.normalize_uri(x)`.
A value that cannot be normalised is undefined, so `==` on it is false and an
allow built on it does not fire. For example:

```rego
package tpt.mcpbox

default allow := false

allow if {
    input.tool == "read_file"
    tpt.normalize_path(input.arguments.path) == "/srv/workspace/notes.txt"
}
```

The evaluator is an in-house interpreter for a subset of Rego v1, not a full
Rego engine. The subset:

- `package tpt.mcpbox`; `import rego.v1` and `import future.keywords...` are
  accepted and ignored;
- `default allow := true|false`, and boolean rules written `NAME if { ... }`,
  `NAME if EXPR` or `NAME { ... }`, with several definitions allowed;
- statements that run in the order written, separated by newlines or `;`:
  `not`, comparisons (`==`, `!=`, `<`, `<=`, `>`, `>=`), `=` and `:=` (which bind
  an unbound variable), `in`, and `some NAME in COLLECTION`;
- values: strings, numbers, `true`, `false`, `null`, arrays, `input`,
  `data.tpt.mcpbox.RULE` (another rule of this module), variables, `_`, and
  bracket indexing such as `input.uris[_]`;
- builtins: `startswith`, `endswith`, `contains`, `lower`, `upper`, `count`,
  `is_string`, `is_number`, `is_boolean`, `is_array`, `is_object`, `is_null`,
  and the `tpt.normalize_host`, `tpt.normalize_path` and `tpt.normalize_uri`
  normalisers.

Anything else is refused when the module loads, with the line that caused it:
arithmetic, `else`, `with`, functions with arguments, comprehensions, regular
expressions, and most of the standard library. A variable must be bound by an
earlier statement, so write `x := input.tool` before `x == "read"`. Rules may not
refer to each other in a cycle. A comparison of different types is false, a
type error in a builtin is an error (a refusal), and the evaluation has a step
budget, so a module cannot run unbounded.

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
