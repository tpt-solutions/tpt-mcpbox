## Summary

<!-- What does this PR change, and why? Reference the phase/checklist item from todo.md. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Security hardening
- [ ] Documentation / build / CI
- [ ] Refactor with no behaviour change

## Security impact

<!--
Does this change alter what a tool, an agent or an upstream server can reach?
If yes, describe the before/after authority and the deny-path test you added.
-->

- [ ] No change to authority boundaries
- [ ] Changes policy enforcement (explain, and include the deny-path test)
- [ ] Changes sandbox capabilities (explain)
- [ ] Touches secret handling, logging, audit or metrics

## Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace` green
- [ ] Tests cover the denied path for any new/changed enforcement
- [ ] `todo.md` updated (checklist item ticked, scope decisions recorded)
- [ ] SPDX headers present in new files
- [ ] No secrets, tokens or host paths added to fixtures or snapshots
