# Operations

## Logging

Logs go to stderr, because stdout carries the protocol on the stdio transport.
With `logging.json: true` each line is a JSON object. Each tool call runs in a
`request` span, so its lines carry the kind, caller, subject (tool name),
outcome, rule id and duration. Argument values never appear in a span.

```sh
RUST_LOG=debug tpt-mcpbox run --config tpt-mcpbox.yaml
```

## Metrics

With `metrics.enabled: true`, `GET /metrics` on `metrics.bind` serves:

- `tpt_mcpbox_calls_total{kind,outcome}`: calls served, by kind (`tool`,
  `resource_read`, `prompt_get`) and outcome (`ok`, `denied`, `rate_limited`,
  ...).
- `tpt_mcpbox_call_duration_seconds{kind}`: a histogram of call durations.

Tool names are never label values, so the number of series does not grow with
what an agent asks for. Pool-utilisation and upstream-health gauges are not
exported yet.

## Audit log

Every call writes a `start` record and a `finish` record. Each record carries
the hash of the record before it.

```sh
tpt-mcpbox audit verify --config tpt-mcpbox.yaml
```

Exits non-zero, and names the first broken entry, if the chain was edited. A
truncated tail is not detected without an external head checkpoint.

## Shell completions and man pages

```sh
tpt-mcpbox completions bash > ~/.local/share/bash-completion/completions/tpt-mcpbox
tpt-mcpbox manpage ./man
```

## Running the hub

- Stop it with Ctrl-C or SIGTERM. In-flight calls get a short drain period.
- The `policy` section is re-read while the hub runs. The file is checked every
  two seconds. A valid edit takes effect on the next call, and an invalid one is
  logged and ignored, so the previous rules stay in force. `run --dry-run` and
  `run --transport` still apply after an edit.
- Every other section is read at start. Restart the hub after changing it; the
  hub logs a warning when such an edit is seen.
- Only one hub can write a given audit log at a time.
