# tpt-mcpbox-audit

The audit log for [tpt-mcpbox](../../README.md): a tamper-evident, hash-chained
record of every call, policy decision and secret injection, together with the
structured tracing setup and Prometheus metrics.

Each entry embeds the hash of the entry before it. Changing any past entry, or
removing one from the middle, breaks the chain. `tpt-mcpbox audit verify`
finds the first place where it breaks.

> **Status: pre-release (0.1.0 in progress).** The API may change before 0.1.0.
> See [todo.md](../../todo.md) for open items.

## What is recorded

- Every tool call and its outcome.
- Every policy decision, with the rule id and the reason.
- Startup events.
- Secret injections. Entries record the **name** of a secret, never its value.

## Components

| Item | Purpose |
|---|---|
| `AuditLog::open` | Opens or creates a log file. Takes an OS file lock, so a second writer is refused. |
| `AuditLog::append` | Appends one entry with a kind and a JSON payload, and returns the new `Entry` |
| `AuditLog::path` | The path of the log file |
| `Entry` | One record, with its hash and the hash of its predecessor |
| `GENESIS` | The hash that the first entry chains from |
| `verify` | Checks the whole chain and returns a `VerifyReport` (entry count and head hash) |
| `AuditError` | Errors from opening, appending or verifying |

## Verifying a log

```console
tpt-mcpbox audit verify .mcpbox/audit.log
```

The command prints the number of entries and the head hash. A broken chain is an
error, so the exit code is non-zero and scripts can depend on it.

## Concurrency

The log is locked with an OS file lock, not with a lock file. The lock is
released when the process exits, so a crash cannot leave a stale lock behind.
A second process that tries to write to the same log is refused.

## Using the crate

The crate is not yet published to crates.io. Depend on it by path:

```toml
[dependencies]
tpt-mcpbox-audit = { path = "../tpt-mcpbox-audit" }
```

The minimum supported Rust version is **1.85**.

## Testing

```console
cargo test -p tpt-mcpbox-audit
```

The tests cover appending, verifying an intact chain, detecting modification
and deletion, and refusing a second writer.

## Limits of the guarantee

The hash chain makes tampering **detectable**. It does not stop someone who can
write to the file from rewriting the whole chain. To close that gap, keep a copy
of the head hash somewhere the log writer cannot change it.

## License

Dual licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT), at your option.
