# Troubleshooting

## `validate` or `run` reports errors

`validate` prints every problem with its location. `run` refuses to start while
any error remains, so fix them all and run `validate` again. Serve-mode
validation is stricter than `--warn-only`; in particular `policy.default: allow`
is an error unless `dry_run` is on.

## `warning: secret ... is referenced but not set`

The variable named in `secrets[].env` is not in the environment, nor in the
`.env` file next to the configuration. Values are never printed, only names.

## A call is refused

Ask the policy why:

```sh
tpt-mcpbox policy test input.json --config tpt-mcpbox.yaml
```

Denials name the rule id and the reason. If the call was refused before reaching
the policy, it was an unknown tool name, or the hub was shutting down.

## A tool's module is refused

The `sha256` pin does not match the file. Rebuild the module, or update the pin
to the digest of the file you have reviewed.

## HTTP clients get 403

The request carried an `Origin` that is not loopback and not in
`server.http.allowed_origins`. Add the origin, or connect from a non-browser
client that sends no `Origin`.

## The hub refuses a non-loopback bind

Set `server.http.bearer_env` and export the token it names. The hub never binds
beyond loopback without one.

## `no audit log at ...`

`audit verify` found no file. Check `audit.path`; relative paths resolve against
the configuration file, not the working directory.

## Upstream tool names conflict

Two sources expose the same name. Rename one with its prefix. The hub refuses
the whole configuration rather than renaming silently.
