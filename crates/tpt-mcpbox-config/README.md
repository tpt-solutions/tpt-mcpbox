# tpt-mcpbox-config

The configuration model for [tpt-mcpbox](../../README.md): the `tpt-mcpbox.yaml`
schema, loading and layering, semantic validation, secret handling, unit
parsing, JSON Schema generation and hot reload.

The crate is split so that **parsing never implies trust**. A value that parses
is not yet a value that is allowed. For example, a capability grant that
contains a typo fails to parse instead of silently widening access.

> **Status: pre-release (0.1.0 in progress).** The API may change before 0.1.0.
> Reload is polling-based. Open items, such as SIGHUP reload, are tracked in
> [todo.md](../../todo.md).

## What it provides

| Module | Responsibility |
|---|---|
| `model` | The `Config` data model. Unknown fields are rejected. |
| `units` | Human-friendly byte sizes (`"64MB"`) and durations (`"500ms"`), with formatters |
| `load` | Discovery, layering and parsing into `model::Config` |
| `validate` | Semantic checks with actionable diagnostics, and `ValidationMode` |
| `secrets` | `SecretString` (zeroized and redacted), env and `.env` sources, header injection, `Redactor` |
| `schema` | JSON Schema for `tpt-mcpbox.yaml`, for editor completion and CI |
| `reload` | A polling watcher and an atomic swap handle |

### Validation modes

`validate` takes a `ValidationMode`. The `Serve` mode refuses
`policy.default: allow`, which is only permitted in dry-run runs, so a
permissive default cannot reach a live server by accident. Other modes can
skip checks that need the host, such as whether referenced secrets are set or
whether module paths exist on disk. The CLI's `tpt-mcpbox validate --offline`
selects this mode.

### Secrets

- Secrets are read from the environment or from a gitignored `.env` file.
- A `SecretString` zeroes its memory on drop and never prints its value.
- Each tool secret is bound to an outbound HTTP header (for example,
  `Authorization` with a `Bearer` prefix). The host injects that header, so
  the tool never sees the value.
- `Redactor` scrubs known secret values from any text before it is logged or
  returned.

## Example

This example is a doctest, so it is checked by `cargo test`:

```rust
use tpt_mcpbox_config::{load_str, validate, ValidationMode};

let yaml = r#"
tools:
  - name: fs_read
    wasm_path: ./tools/fs.wasm
    capabilities:
      filesystem:
        read: ["./workspace/**"]
"#;

let config = load_str(yaml, "tpt-mcpbox.yaml").expect("parses");
let report = validate(&config, ValidationMode::Serve);
assert!(report.is_ok(), "unexpected diagnostics: {report:?}");
assert_eq!(
    config.tools[0].capabilities.filesystem.read,
    vec!["./workspace/**"]
);
```

A complete sample configuration is in [`examples/tpt-mcpbox.yaml`](../../examples/tpt-mcpbox.yaml).

## Configuration shape

The top level has these sections. Each one maps to a field of `model::Config`:

| Key | Purpose |
|---|---|
| `version` | Configuration schema version (currently `1`) |
| `server` | Transports (`stdio`, `http`) and the HTTP bind address, origins and bearer token environment variable |
| `tools` | Wasm tools: `name`, `wasm_path` or `oci_ref`, `sha256`, `capabilities`, `secrets`, `limits` |
| `upstreams` | External MCP servers to proxy, over stdio or Streamable HTTP |
| `policy` | `default` (`deny`) and an ordered list of rules with `id`, `effect` and `tool` |
| `audit` | Whether the audit log is enabled and where it is written |
| `metrics` | Prometheus listener settings |
| `logging` | Log level and format |

Discovery and layering are handled by `load`. The loader searches for the
file from the working directory when no path is given.

## Using the crate

The crate is not yet published to crates.io. Depend on it by path:

```toml
[dependencies]
tpt-mcpbox-config = { path = "../tpt-mcpbox-config" }
```

The minimum supported Rust version is **1.85**.

## Testing

```console
cargo test -p tpt-mcpbox-config
```

## Scope

In scope: describing, parsing, validating and reloading configuration, and
keeping secret values out of logs and replies.

Out of scope: evaluating policy decisions (`tpt-mcpbox-policy`), and the
runtime behaviour of the limits configured here (`tpt-mcpbox-runtime`).

## License

Dual licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT), at your option.
