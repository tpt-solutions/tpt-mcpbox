# tpt-mcpbox-policy

The capability-based policy engine for [tpt-mcpbox](../../README.md). It decides
whether a tool call, upstream call or resource read is allowed.

Evaluation is **deny-by-default**. Every decision carries a human-readable
reason and the id of the rule that made it. The audit log can therefore record
*why* a call was blocked, not only that it was.

> **Status: pre-release (0.1.0 in progress).** The API may change before 0.1.0.
> See [todo.md](../../todo.md) for open items.

## How it works

Two evaluators compose into one `Policy`:

1. **YAML DSL** (`Engine`). This is the default. Rules are declarative and
   reviewed alongside the configuration. Each rule has an `id`, an `effect`
   (`allow` or `deny`) and matchers such as the tool name.
2. **Embedded Rego** (through [`regorus`](https://crates.io/crates/regorus), a
   pure-Rust engine). Use this when a rule needs more logic than the DSL offers.

`Policy::from_config` builds the DSL-only policy. `Policy::from_config_with_rego`
adds a Rego module. `Policy::reload` builds a new policy from a changed
configuration, and it can be swapped in atomically.

Inputs are normalised before they are matched (`normalize`). Hosts, paths and
URIs are lowercased, dot segments are resolved and malformed values are
rejected. This stops `..` tricks and mixed-case hosts from slipping past a
rule.

## The sample policy

From [`examples/tpt-mcpbox.yaml`](../../examples/tpt-mcpbox.yaml):

```yaml
policy:
  # Anything not named below is refused.
  default: deny
  rules:
    - id: allow-search
      effect: allow
      tool: search_repos
    - id: allow-read
      effect: allow
      tool: read_file
```

## Decisions

`Engine::evaluate` and `Policy::evaluate` take a `PolicyInput` and return a
`Decision`.

| Method | Meaning |
|---|---|
| `Decision::is_allowed` | `true` only for an allow decision that is in force |
| `Decision::is_dry_run_override` | `true` when a dry run reports `allow` for a call that would be denied |

In dry-run mode the decision is reported as `effect: allow` with a `would_be`
of `deny`. The CLI prints that as-is, so a dry run is never mistaken for a
live allow.

## Errors

`PolicyError` covers rules that fail to compile, unknown effects, and Rego
modules that fail to load. A configuration that fails to build a policy is
rejected at startup, so the server never runs with a half-built policy.

## Using the crate

The crate is not yet published to crates.io. Depend on it by path:

```toml
[dependencies]
tpt-mcpbox-policy = { path = "../tpt-mcpbox-policy" }
```

The minimum supported Rust version is **1.85**.

## Testing

```console
cargo test -p tpt-mcpbox-policy
```

The test suite covers the DSL evaluator, the Rego integration and the
composition of the two. The `tpt-mcpbox policy test` command runs one input
through the same engine, so you can see the decision a rule produces.

## Scope

In scope: deciding allow or deny, explaining the decision, and normalising
inputs.

Out of scope: enforcing the decision. The router and proxy call the policy and
act on the result. The policy itself does not sandbox anything.

## License

Dual licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT), at your option.
