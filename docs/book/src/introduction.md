# Introduction

tpt-mcpbox sits between an AI agent and the tools it uses. The agent speaks
the Model Context Protocol (MCP) to the hub; the hub decides, for each call,
whether it may run, runs it in a sandbox or forwards it to an upstream server,
and records what happened in a tamper-evident log.

It has three parts:

- **A policy engine** that denies by default. Rules are written in a small YAML
  DSL, an embedded Rego module, or both.
- **A WebAssembly tool runtime.** Tools are `wasm32-wasip2` components. They get
  only the filesystem paths, network hosts, environment variables and memory
  their configuration grants. Secrets are added to outbound requests by the host,
  so a tool never holds them.
- **An upstream proxy** for existing MCP servers, whose calls go through the
  same policy, limits and audit log.

Agent-facing transports are stdio and Streamable HTTP. Everything is a single
binary, `tpt-mcpbox`.

The project is pre-release. The [configuration reference](configuration.md)
and the [security model](security-model.md) say which parts are finished.
