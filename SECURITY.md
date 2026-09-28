# Security Policy

## Scope

`tpt-mcpbox` is a security boundary: it decides which files, hosts and secrets
an AI agent's tool calls may reach. Please treat vulnerabilities here as
high-severity by default.

In scope:

- Policy bypass: reaching a host, path or secret that configuration forbids.
- Sandbox escape: gaining filesystem, network or environment authority that the
  policy did not grant.
- Secret exposure: credentials appearing in logs, audit entries, metrics, error
  messages or `/metrics` output.
- Integrity: forging or mutating the audit log without detection.
- Denial of service through resource exhaustion that a tool or agent can drive.

Out of scope:

- Vulnerabilities in the host operating system or in Rust dependencies that are
  already covered by a published advisory (report those upstream; we track them
  with `cargo audit`).
- A malicious *configuration author*: if someone writes a policy that grants the
  agent everything, that is their decision.
- Denial of service by a client that is already fully trusted on the host.

## Reporting a vulnerability

**Do not open a public issue, discussion or PR.**

1. Email **security@tpt-solutions.com** with a subject of
   `VULN: <short summary>`.
2. Include: affected version or commit, reproduction steps, impact, and any
   proof-of-concept. Encrypt sensitive material with our published key and ask
   for ours if you need to send a weaponised exploit.
3. We acknowledge within 3 business days, provide a remediation plan within 10,
   and coordinate a 90-day disclosure window by default.

## Supported versions

Security fixes are provided for the latest released minor version and the
`main` branch until the next release. `main` is pre-release today, so prefer
`main` until `v0.1.0` ships.

## Hardening expectations for contributions

Any change that touches `tpt-mcpbox-policy`, `tpt-mcpbox-runtime`,
`tpt-mcpbox-config` or secret handling should:

1. Preserve deny-by-default semantics; "allow when unsure" is a bug.
2. Add a test for the denied path, including hostile inputs (path traversal,
   Unicode host normalization, symlink escape, oversized payloads).
3. Keep secrets out of every `tracing` field, error string, audit entry and
   metric label.
4. Keep `tpt-mcpbox-protocol` free of policy logic so a parsing bug cannot
   become an authorization bug.
