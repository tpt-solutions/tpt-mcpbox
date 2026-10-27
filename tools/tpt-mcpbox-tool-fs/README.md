# tpt-mcpbox-tool-fs

An example tool component for [tpt-mcpbox](../../README.md) that reads and writes
files in a workspace. It shows how a tool gets filesystem access that is limited
by configuration, not by the code.

It provides three tools:

| Tool | Arguments | Access |
|---|---|---|
| `read_file` | `path` | Reads a UTF-8 text file under the read root |
| `list_dir` | `path` | Lists a directory under the read root. Directories end with a slash. |
| `write_file` | `path`, `content` | Writes a text file under the output root, replacing any existing file |

Every `path` is relative to the root it applies to. For `write_file` that root is
the granted output directory itself, so `a.md` writes `workspace/output/a.md`.
Passing `output/a.md` writes `workspace/output/output/a.md`.

## Access model

The configuration grants two directories:

```yaml
capabilities:
  filesystem:
    read: ["./workspace/**"]
    write: ["./workspace/output/**"]
```

The host preopens those directories for the guest under the names `/workspace`
(read) and `/workspace_output` (write). The sandbox refuses any access outside
them, whatever this code does.

The tool also checks paths itself. It accepts only relative paths with no `..`
segment, so a bad path gets a clear error before the host sees it. That check is
for the agent's benefit. The sandbox is the enforcement.

## Build

```sh
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

The output is `target/wasm32-wasip2/release/tpt_mcpbox_tool_fs.wasm`, which the
sample configuration in [`examples/`](../../examples/tpt-mcpbox.yaml) expects.

## Tests

This is a guest crate with its own workspace, so build it for the guest target
and exercise it through the hub. The crate has no host-side tests.

To check it by hand against the sample configuration, with `workspace/notes.md`
present next to the configuration:

```sh
tpt-mcpbox tools call read_file --args '{"path":"notes.md"}' --config tpt-mcpbox.yaml
tpt-mcpbox tools call write_file --args '{"path":"a.md","content":"hi"}' --config tpt-mcpbox.yaml
tpt-mcpbox tools call write_file --args '{"path":"../escape.md","content":"x"}' --config tpt-mcpbox.yaml   # refused
```

The last call is refused by the tool's own path check, before the sandbox is asked.

## License

Dual licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT), at your option.
