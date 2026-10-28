// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Semantic validation with actionable diagnostics.
//!
//! Parsing proves the document *matches the schema*; validation proves it is
//! *safe to run*. The checks here are the ones an attacker would otherwise
//! exploit by editing a config file:
//!
//! * a tool with no `wasm_path` or `oci_ref` (no origin to verify),
//! * both origins set (ambiguous provenance),
//! * duplicate tool or upstream names,
//! * a tool that grants network without a memory/time limit,
//! * a filesystem grant that is not under a relative, non-`..` prefix,
//! * `policy.default: allow` outside dry-run,
//! * a rule set where a `deny` rule is unreachable behind an earlier
//!   catch-all `allow`.
//!
//! Every finding carries a [`Diagnostic`] with a path, a message and, where
//! possible, a hint -- `tpt-mcpbox validate` prints them verbatim.

use std::collections::HashSet;
use std::fmt;

use crate::model::{Config, Effect, ToolConfig, UpstreamConfig, UpstreamTransport};

/// How severe a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Worth telling the operator about; the config still runs.
    Warning,
    /// The config is unsafe or unusable; refuse to start.
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning => f.write_str("warning"),
            Self::Error => f.write_str("error"),
        }
    }
}

/// One validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// How severe.
    pub severity: Severity,
    /// Dotted path to the offending field, e.g. `tools[0].capabilities.network`.
    pub path: String,
    /// What is wrong.
    pub message: String,
    /// How to fix it.
    pub hint: Option<String>,
}

impl Diagnostic {
    /// An error with no hint.
    pub fn error(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            path: path.into(),
            message: message.into(),
            hint: None,
        }
    }

    /// An error with a remediation hint.
    pub fn error_with_hint(
        path: impl Into<String>,
        message: impl Into<String>,
        hint: impl Into<String>,
    ) -> Self {
        Self {
            severity: Severity::Error,
            path: path.into(),
            message: message.into(),
            hint: Some(hint.into()),
        }
    }

    /// A warning.
    pub fn warning(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            path: path.into(),
            message: message.into(),
            hint: None,
        }
    }

    /// Render as a single human-readable line.
    #[must_use]
    pub fn render(&self) -> String {
        match &self.hint {
            Some(hint) => format!(
                "{}: {}: {} (hint: {hint})",
                self.severity, self.path, self.message
            ),
            None => format!("{}: {}: {}", self.severity, self.path, self.message),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Context in which a configuration is validated.
///
/// The mode matters: a `policy.default: allow` configuration is a legitimate
/// migration aid under [`ValidationMode::DryRun`] and a footgun in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    /// The hub is about to serve traffic.
    Serve,
    /// The hub only logs what it would deny.
    DryRun,
    /// `tpt-mcpbox validate`: advisory, but still checks for hard errors.
    Audit,
}

/// The outcome of validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// Findings, errors first.
    pub diagnostics: Vec<Diagnostic>,
}

impl ValidationReport {
    /// `true` when nothing blocks startup.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        !self.has_errors()
    }

    /// `true` when at least one finding is an error.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
    }

    /// Findings of a given severity.
    #[must_use]
    pub fn of_severity(&self, severity: Severity) -> Vec<&Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == severity)
            .collect()
    }

    /// Merge another report's findings into this one.
    pub fn extend(&mut self, other: ValidationReport) {
        self.diagnostics.extend(other.diagnostics);
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.diagnostics.is_empty() {
            return f.write_str("configuration is valid");
        }
        for diagnostic in &self.diagnostics {
            writeln!(f, "  {}", diagnostic.render())?;
        }
        let errors = self
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
            .count();
        write!(
            f,
            "{} finding(s): {errors} error(s), {} warning(s)",
            self.diagnostics.len(),
            self.diagnostics.len() - errors
        )
    }
}

/// Validate a configuration for the given mode.
///
/// The function is total: it never panics and never returns early, so one run
/// reports every problem the operator has to fix.
#[must_use]
pub fn validate(config: &Config, mode: ValidationMode) -> ValidationReport {
    let mut report = ValidationReport::default();

    validate_server(config, &mut report);
    validate_tools(config, mode, &mut report);
    validate_upstreams(config, &mut report);
    validate_policy(config, mode, &mut report);
    validate_audit(config, &mut report);

    report
        .diagnostics
        .sort_by_key(|diagnostic| std::cmp::Reverse(diagnostic.severity));
    report
}

fn validate_server(config: &Config, report: &mut ValidationReport) {
    if config.server.has_http() && config.server.http.is_none() {
        report.diagnostics.push(Diagnostic::error_with_hint(
            "server.http",
            "the http transport is enabled but no bind address is configured",
            "add `server.http.bind: 127.0.0.1:8899`",
        ));
    }
    if let Some(http) = &config.server.http {
        if !http.bind.contains(':') {
            report.diagnostics.push(Diagnostic::error_with_hint(
                "server.http.bind",
                format!("`{}` is not a host:port pair", http.bind),
                "use an address such as `127.0.0.1:8899`",
            ));
        }
        if http.bind.starts_with("0.0.0.0") || http.bind.starts_with("::") {
            report.diagnostics.push(Diagnostic::warning(
                "server.http.bind",
                format!("binding {} exposes the hub beyond loopback", http.bind),
            ));
        }
    }
    if !config.server.has_stdio() && !config.server.has_http() {
        report.diagnostics.push(Diagnostic::error(
            "server.transports",
            "no transport is enabled, so no agent can connect",
        ));
    }
}

fn validate_tools(config: &Config, mode: ValidationMode, report: &mut ValidationReport) {
    let mut seen: HashSet<&str> = HashSet::new();

    for (index, tool) in config.tools.iter().enumerate() {
        let path = format!("tools[{index}]");

        if !seen.insert(tool.name.as_str()) {
            report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.name"),
                format!("duplicate tool name `{}`", tool.name),
                "tool names are the namespace agents call; rename one",
            ));
        }
        if tool.name.trim().is_empty() {
            report.diagnostics.push(Diagnostic::error(
                format!("{path}.name"),
                "tool name must not be empty",
            ));
        }

        match (&tool.wasm_path, &tool.oci_ref) {
            (None, None) => report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.wasm_path"),
                format!("tool `{}` has no origin to verify", tool.name),
                "set `wasm_path` (local file) or `oci_ref` (registry reference)",
            )),
            (Some(_), Some(_)) => report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.wasm_path"),
                format!("tool `{}` sets both wasm_path and oci_ref", tool.name),
                "keep exactly one origin so the provenance check is unambiguous",
            )),
            (Some(local), None) => {
                if local.extension().and_then(|ext| ext.to_str()) != Some("wasm") {
                    report.diagnostics.push(Diagnostic::warning(
                        format!("{path}.wasm_path"),
                        format!("{} does not end in `.wasm`", local.display()),
                    ));
                }
                if tool.sha256.is_none() && mode != ValidationMode::Audit {
                    report.diagnostics.push(Diagnostic::warning(
                        format!("{path}.sha256"),
                        format!(
                            "tool `{}` has no sha256 pin; a replaced .wasm file would be trusted",
                            tool.name
                        ),
                    ));
                }
            }
            (None, Some(reference)) => {
                if tool.sha256.is_none() && mode != ValidationMode::Audit {
                    report.diagnostics.push(Diagnostic::warning(
                        format!("{path}.sha256"),
                        format!(
                            "tool `{}` pulls `{reference}` without a sha256 pin",
                            tool.name
                        ),
                    ));
                }
            }
        }

        validate_capabilities(tool, &path, report);
    }
}

fn validate_capabilities(tool: &ToolConfig, path: &str, report: &mut ValidationReport) {
    let capabilities = &tool.capabilities;

    for (kind, patterns) in [
        ("read", &capabilities.filesystem.read),
        ("write", &capabilities.filesystem.write),
    ] {
        for (index, pattern) in patterns.iter().enumerate() {
            let field = format!("{path}.capabilities.filesystem.{kind}[{index}]");
            if pattern.contains("..") {
                report.diagnostics.push(Diagnostic::error_with_hint(
                    field.clone(),
                    format!("`{pattern}` contains `..` and could escape the working directory"),
                    "use paths relative to the workspace root",
                ));
            }
            if is_absolute_path(pattern) {
                report.diagnostics.push(Diagnostic::warning(
                    field,
                    format!("`{pattern}` is an absolute path; prefer workspace-relative globs"),
                ));
            }
        }
    }

    for (index, host) in capabilities.network.iter().enumerate() {
        let field = format!("{path}.capabilities.network[{index}]");
        if host.trim().is_empty() {
            report
                .diagnostics
                .push(Diagnostic::error(field.clone(), "empty host entry"));
        }
        if host.contains("://") {
            report.diagnostics.push(Diagnostic::error_with_hint(
                field.clone(),
                format!("`{host}` looks like a URL; the allowlist takes bare hosts"),
                "write `api.github.com`, not `https://api.github.com`",
            ));
        }
        if host == "*" {
            report.diagnostics.push(Diagnostic::warning(
                field,
                "`*` grants network access to every host; prefer an explicit list",
            ));
        }
    }

    if !capabilities.network.is_empty() {
        if capabilities.memory_limit.is_none() {
            report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.capabilities.memory_limit"),
                format!(
                    "tool `{}` can reach the network without a memory limit",
                    tool.name
                ),
                "set `capabilities.memory_limit` (e.g. `64MB`) so a runaway call is bounded",
            ));
        }
        if capabilities.time_limit.is_none() {
            report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.capabilities.time_limit"),
                format!(
                    "tool `{}` can reach the network without a time limit",
                    tool.name
                ),
                "set `capabilities.time_limit` (e.g. `30s`)",
            ));
        }
    }

    for (index, name) in capabilities.env.iter().enumerate() {
        if looks_like_a_secret_variable(name) {
            report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.capabilities.env[{index}]"),
                format!("`{name}` looks like a credential"),
                "use `secrets` so the value is injected at the proxy layer and never enters the guest",
            ));
        }
    }

    for (index, secret) in tool.secrets.iter().enumerate() {
        let field = format!("{path}.secrets[{index}]");
        if secret.header.trim().is_empty() {
            report.diagnostics.push(Diagnostic::error(
                format!("{field}.header"),
                "secret binding has an empty header name",
            ));
        } else if !secret
            .header
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        {
            report.diagnostics.push(Diagnostic::error(
                format!("{field}.header"),
                format!("`{}` is not a valid HTTP header name", secret.header),
            ));
        }
        if tool.capabilities.network.is_empty() {
            report.diagnostics.push(Diagnostic::warning(
                field,
                format!(
                    "tool `{}` binds secret `{}` but grants no network access",
                    tool.name, secret.env
                ),
            ));
        }
    }

    if tool.limits.max_argument_bytes.unwrap_or(u64::MAX) > 32 * 1024 * 1024 {
        report.diagnostics.push(Diagnostic::warning(
            format!("{path}.limits.max_argument_bytes"),
            "argument cap above 32MB invites denial of service",
        ));
    }
}

/// `true` for POSIX- and Windows-style absolute paths.
fn is_absolute_path(pattern: &str) -> bool {
    pattern.starts_with('/') || pattern.starts_with('\\') || {
        let bytes = pattern.as_bytes();
        bytes.len() > 2 && bytes[1] == b':' && bytes[2] == b'\\'
    }
}

/// Heuristic: variable names that look like they hold credentials.
fn looks_like_a_secret_variable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "APIKEY",
        "API_KEY",
        "PRIVATE_KEY",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

fn validate_upstreams(config: &Config, report: &mut ValidationReport) {
    let mut seen: HashSet<&str> = HashSet::new();

    for (index, upstream) in config.upstreams.iter().enumerate() {
        let path = format!("upstreams[{index}]");
        if !seen.insert(upstream.name.as_str()) {
            report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.name"),
                format!("duplicate upstream name `{}`", upstream.name),
                "upstream names appear in diagnostics and audit entries",
            ));
        }

        match &upstream.transport {
            UpstreamTransport {
                stdio: Some(stdio),
                http: None,
            } => {
                if stdio.command.trim().is_empty() {
                    report.diagnostics.push(Diagnostic::error(
                        format!("{path}.transport.stdio.command"),
                        "empty command",
                    ));
                }
                for (env_index, value) in stdio.env.iter().enumerate() {
                    if looks_like_a_secret_variable(value.0.as_str()) {
                        report.diagnostics.push(Diagnostic::error_with_hint(
                            format!("{path}.transport.stdio.env.{env_index}"),
                            format!("`{}` looks like a credential in plaintext config", value.0),
                            "move it to a `secrets` binding so it is injected at runtime",
                        ));
                    }
                }
            }
            UpstreamTransport {
                stdio: None,
                http: Some(http),
            } => {
                if http.url.starts_with("http://") {
                    report.diagnostics.push(Diagnostic::warning(
                        format!("{path}.transport.http.url"),
                        "plain http upstream: credentials would travel in the clear",
                    ));
                } else if !http.url.starts_with("https://") {
                    report.diagnostics.push(Diagnostic::error_with_hint(
                        format!("{path}.transport.http.url"),
                        format!("`{}` is not an absolute https URL", http.url),
                        "include the scheme, e.g. `https://mcp.example/api`",
                    ));
                }
            }
            _ => report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.transport"),
                format!(
                    "upstream `{}` does not declare exactly one transport",
                    upstream.name
                ),
                "set exactly one of `transport.stdio` or `transport.http`",
            )),
        }

        if let Some(prefix) = &upstream.prefix
            && !prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.prefix"),
                format!("`{prefix}` must match [A-Za-z0-9_-]"),
                "use a tool-name-safe prefix such as `gh__`",
            ));
        }

        for pattern in upstream.allow.iter().chain(upstream.deny.iter()) {
            if pattern.trim().is_empty() {
                report.diagnostics.push(Diagnostic::error(
                    format!("{path}.allow/deny"),
                    "empty tool filter entry",
                ));
            }
        }
        validate_upstream_names(upstream, &path, report);
    }
}

/// Filter entries must be non-empty, and renames must give non-empty, distinct
/// names. Whether a rename's source exists is checked when the upstream is
/// listed, since the config cannot know the upstream's tools.
fn validate_upstream_names(upstream: &UpstreamConfig, path: &str, report: &mut ValidationReport) {
    let filters = [
        ("prompts.allow", &upstream.prompts.allow),
        ("prompts.deny", &upstream.prompts.deny),
        ("resources.allow", &upstream.resources.allow),
        ("resources.deny", &upstream.resources.deny),
    ];
    for (field, patterns) in filters {
        if patterns.iter().any(|pattern| pattern.trim().is_empty()) {
            report.diagnostics.push(Diagnostic::error(
                format!("{path}.{field}"),
                "empty filter entry",
            ));
        }
    }

    let renames = [
        ("tools.rename", &upstream.tools.rename),
        ("prompts.rename", &upstream.prompts.rename),
    ];
    for (field, rename) in renames {
        let mut targets = HashSet::new();
        for (from, to) in rename {
            if from.trim().is_empty() || to.trim().is_empty() {
                report.diagnostics.push(Diagnostic::error(
                    format!("{path}.{field}"),
                    "rename entries need a non-empty name on both sides",
                ));
            } else if !targets.insert(to.as_str()) {
                report.diagnostics.push(Diagnostic::error_with_hint(
                    format!("{path}.{field}"),
                    format!("two renames both become `{to}`"),
                    "give each exposed name one source",
                ));
            }
        }
    }

    let mut names = HashSet::new();
    for rule in &upstream.scan {
        if rule.name.trim().is_empty() {
            report.diagnostics.push(Diagnostic::error(
                format!("{path}.scan"),
                "scan rules need a non-empty name",
            ));
        } else if !names.insert(rule.name.as_str()) {
            report.diagnostics.push(Diagnostic::error(
                format!("{path}.scan"),
                format!("two scan rules are named `{}`", rule.name),
            ));
        }
        if let Err(error) = regex::Regex::new(&rule.pattern) {
            report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.scan"),
                format!("scan rule `{}`: {error}", rule.name),
                "use a regular expression; `regex` syntax applies",
            ));
        }
    }
}

/// Audit settings: an unkeyed chain can be rebuilt by whoever can write the file.
fn validate_audit(config: &Config, report: &mut ValidationReport) {
    if !config.audit.enabled {
        return;
    }
    if config.audit.max_segment_bytes == 0 {
        report.diagnostics.push(Diagnostic::error(
            "audit.max_segment_bytes",
            "a segment must hold at least one byte",
        ));
    }
    match config.audit.key_env.as_deref() {
        None => report.diagnostics.push(Diagnostic::warning(
            "audit.key_env",
            "the audit chain is plain SHA-256, so anyone who can write the log can rebuild it; set `key_env` to a secret to key it (SR-24)",
        )),
        Some(name) if name.trim().is_empty() => report.diagnostics.push(Diagnostic::error(
            "audit.key_env",
            "the audit key's secret name must not be empty",
        )),
        Some(_) => {}
    }
}

fn validate_policy(config: &Config, mode: ValidationMode, report: &mut ValidationReport) {
    if config.policy.default == Effect::Allow {
        if mode == ValidationMode::Serve && !config.policy.dry_run {
            report.diagnostics.push(Diagnostic::error_with_hint(
                "policy.default",
                "`allow` means every unmatched call is permitted",
                "set `policy.default: deny`, or enable `policy.dry_run` while migrating",
            ));
        } else {
            report.diagnostics.push(Diagnostic::warning(
                "policy.default",
                "unmatched calls are allowed; this is deny-by-default only in dry-run mode",
            ));
        }
    }

    let mut rule_ids: HashSet<&str> = HashSet::new();
    let mut allow_catch_all: Option<&str> = None;

    for (index, rule) in config.policy.rules.iter().enumerate() {
        let path = format!("policy.rules[{index}]");
        if !rule_ids.insert(rule.id.as_str()) {
            report.diagnostics.push(Diagnostic::error_with_hint(
                format!("{path}.id"),
                format!("duplicate rule id `{}`", rule.id),
                "rule ids are recorded in audit entries and must be unique",
            ));
        }
        // The policy is not given a call's filesystem path, so a deny rule on
        // `paths` never matches (SR-01). Say so rather than let an operator rely
        // on it. `hosts` on a deny rule is checked only on the outbound requests
        // of Wasm tools, not on upstream calls.
        // A deny that matches only on arguments is compared by exact JSON
        // equality, so `"Write"` or `1.0` steps around it (SR-16).
        let only_args = !rule.args.is_empty()
            && rule.tool.is_none()
            && rule.method.is_none()
            && rule.prompt.is_none()
            && rule.caller.is_none()
            && rule.hosts.is_empty()
            && rule.paths.is_empty()
            && rule.uris.is_empty();
        if rule.effect == Effect::Deny && only_args {
            report.diagnostics.push(Diagnostic::warning(
                &path,
                "a deny rule that matches only on `args` compares values exactly; spellings such as `Write` for `write` pass it. Also name the tool",
            ));
        }
        if rule.effect == Effect::Deny && !rule.paths.is_empty() {
            report.diagnostics.push(Diagnostic::warning(
                &path,
                "`paths` on a deny rule is not enforced yet; the policy is not given the call's path",
            ));
        }
        if rule.effect == Effect::Deny && !rule.hosts.is_empty() {
            report.diagnostics.push(Diagnostic::warning(
                &path,
                "`hosts` on a deny rule applies only to outbound requests of Wasm tools; upstream calls are not host-checked",
            ));
        }
        if let Some(constraints) = &rule.constraints {
            if rule.effect == Effect::Deny {
                report.diagnostics.push(Diagnostic::error_with_hint(
                    format!("{path}.constraints"),
                    "constraints only apply to `allow` rules",
                    "remove `constraints`, or change the rule to `effect: allow`",
                ));
            }
            if let Some(quota) = &constraints.quota {
                if quota.max_calls == 0 {
                    report.diagnostics.push(Diagnostic::error(
                        format!("{path}.constraints.quota.max_calls"),
                        "a quota must allow at least one call",
                    ));
                }
                if quota.window.is_zero() {
                    report.diagnostics.push(Diagnostic::error(
                        format!("{path}.constraints.quota.window"),
                        "a quota window must be longer than zero",
                    ));
                }
            }
        }
        if rule.effect == Effect::Allow && rule.tool.is_none() && rule.method.is_none() {
            allow_catch_all = allow_catch_all.or(Some(rule.id.as_str()));
        }
        if rule
            .tool
            .as_deref()
            .is_some_and(|tool| tool.contains("://"))
        {
            report.diagnostics.push(Diagnostic::error(
                format!("{path}.tool"),
                "tool globs match tool names, not URLs",
            ));
        }
    }

    // First match wins, so a later deny rule behind a catch-all allow is dead
    // configuration an operator may still believe is protecting them.
    if let Some(catch_all) = allow_catch_all {
        let unreachable: Vec<&str> = config
            .policy
            .rules
            .iter()
            .skip_while(|rule| rule.id != catch_all)
            .skip(1)
            .filter(|rule| rule.effect == Effect::Deny)
            .map(|rule| rule.id.as_str())
            .collect();
        if !unreachable.is_empty() {
            report.diagnostics.push(Diagnostic::error_with_hint(
                "policy.rules",
                format!(
                    "rule `{catch_all}` matches every tool, so later deny rule(s) {} can never apply",
                    unreachable.join(", ")
                ),
                "rules are evaluated in order and the first match wins; move deny rules above the catch-all",
            ));
        }
    }

    if let Some(rego) = &config.policy.rego
        && !rego.exists()
    {
        report.diagnostics.push(Diagnostic::error_with_hint(
            "policy.rego",
            format!("{} does not exist", rego.display()),
            "point `policy.rego` at the module or remove it",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::load_str;

    fn parse(yaml: &str) -> Config {
        load_str(yaml, "test.yaml").expect("parses")
    }

    fn errors(config: &Config) -> Vec<String> {
        validate(config, ValidationMode::Serve)
            .diagnostics
            .into_iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
            .map(|diagnostic| diagnostic.render())
            .collect()
    }

    fn paths(config: &Config) -> Vec<String> {
        validate(config, ValidationMode::Serve)
            .diagnostics
            .into_iter()
            .map(|diagnostic| diagnostic.path)
            .collect()
    }

    #[test]
    fn the_default_configuration_validates() {
        let report = validate(&Config::default(), ValidationMode::Serve);
        assert!(report.is_ok(), "{report}");
    }

    #[test]
    fn upstream_scan_rules_are_checked() {
        let config = parse(
            r#"
upstreams:
  - name: kb
    transport:
      stdio:
        command: "true"
    scan:
      - name: card
        pattern: "(unclosed"
      - name: card
        pattern: "\\d{4}"
        action: refuse
"#,
        );
        let found = errors(&config);
        assert!(
            found.iter().any(|e| e.contains("scan rule `card`")),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|e| e.contains("two scan rules are named `card`")),
            "{found:?}"
        );
    }

    #[test]
    fn upstream_renames_and_filters_are_checked() {
        let config = parse(
            r#"
upstreams:
  - name: kb
    transport:
      stdio:
        command: "true"
    tools:
      rename:
        a: same
        b: same
    resources:
      deny: [""]
"#,
        );
        let found = errors(&config);
        assert!(
            found
                .iter()
                .any(|e| e.contains("two renames both become `same`")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|e| e.contains("empty filter entry")),
            "{found:?}"
        );
    }

    #[test]
    fn the_spec_example_validates_cleanly() {
        let config = parse(
            r#"
tools:
  - name: github_search
    wasm_path: ./tools/github.wasm
    sha256: "0000000000000000000000000000000000000000000000000000000000000000"
    capabilities:
      network: ["api.github.com"]
      memory_limit: "64MB"
      time_limit: "30s"
    secrets:
      - env: GITHUB_TOKEN
        header: Authorization
        prefix: Bearer
  - name: local_files
    wasm_path: ./tools/fs.wasm
    sha256: "0000000000000000000000000000000000000000000000000000000000000000"
    capabilities:
      filesystem:
        read: ["./workspace/**"]
        write: ["./workspace/output/**"]
policy:
  default: deny
  rules:
    - id: allow-github
      effect: allow
      tool: github_*
"#,
        );
        let report = validate(&config, ValidationMode::Serve);
        assert!(report.is_ok(), "{report}");
    }

    #[test]
    fn a_tool_without_an_origin_is_an_error() {
        let config = parse("tools:\n  - name: mystery\n");
        let messages = errors(&config);
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(messages[0].contains("no origin to verify"), "{messages:?}");
    }

    #[test]
    fn two_origins_are_ambiguous_and_refused() {
        let config = parse(
            "tools:\n  - name: both\n    wasm_path: a.wasm\n    oci_ref: oci://example/fs:1\n",
        );
        assert!(errors(&config)[0].contains("both wasm_path and oci_ref"));
    }

    #[test]
    fn duplicate_tool_names_are_refused() {
        let config = parse(
            "tools:\n  - name: dup\n    wasm_path: a.wasm\n  - name: dup\n    wasm_path: b.wasm\n",
        );
        assert!(errors(&config)[0].contains("duplicate tool name"));
    }

    #[test]
    fn network_without_resource_limits_is_refused() {
        let config = parse(
            "tools:\n  - name: net\n    wasm_path: a.wasm\n    capabilities:\n      network: [\"api.github.com\"]\n",
        );
        let found = paths(&config);
        assert!(
            found.contains(&"tools[0].capabilities.memory_limit".to_owned()),
            "{found:?}"
        );
        assert!(
            found.contains(&"tools[0].capabilities.time_limit".to_owned()),
            "{found:?}"
        );
    }

    #[test]
    fn path_traversal_in_a_grant_is_refused() {
        let config = parse(
            "tools:\n  - name: fs\n    wasm_path: a.wasm\n    capabilities:\n      filesystem:\n        read: [\"../../etc/**\"]\n",
        );
        assert!(errors(&config)[0].contains("could escape the working directory"));
    }

    #[test]
    fn urls_in_the_host_allowlist_are_refused_with_a_hint() {
        let config = parse(
            "tools:\n  - name: net\n    wasm_path: a.wasm\n    capabilities:\n      network: [\"https://api.github.com\"]\n      memory_limit: 64MB\n      time_limit: 30s\n",
        );
        let messages = errors(&config);
        assert!(messages[0].contains("looks like a URL"), "{messages:?}");
    }

    #[test]
    fn secrets_in_the_env_allowlist_are_refused() {
        let config = parse(
            "tools:\n  - name: leaky\n    wasm_path: a.wasm\n    capabilities:\n      env: [\"GITHUB_TOKEN\"]\n",
        );
        assert!(errors(&config)[0].contains("looks like a credential"));
    }

    #[test]
    fn allow_by_default_is_refused_when_serving() {
        let config = parse("policy:\n  default: allow\n");
        assert!(errors(&config)[0].contains("every unmatched call is permitted"));
    }

    #[test]
    fn an_audit_log_without_a_key_draws_a_warning() {
        let report = validate(
            &parse(
                "version: 1
",
            ),
            ValidationMode::Serve,
        );
        let warnings: Vec<_> = report
            .of_severity(Severity::Warning)
            .into_iter()
            .filter(|d| d.path == "audit.key_env")
            .collect();
        assert_eq!(warnings.len(), 1, "{report}");

        let keyed = parse(
            "version: 1
audit:
  key_env: MCPBOX_AUDIT_KEY
",
        );
        assert!(validate(&keyed, ValidationMode::Serve).is_ok());
    }

    #[test]
    fn an_empty_audit_key_name_is_an_error() {
        let config = parse(
            "version: 1
audit:
  key_env: \"  \"
",
        );
        assert!(
            errors(&config)
                .iter()
                .any(|e| e.contains("must not be empty"))
        );
    }

    /// Warnings about the policy section. Other sections may warn too, for
    /// example about the audit key, and these tests are about policy only.
    fn policy_warnings(report: &ValidationReport) -> Vec<&Diagnostic> {
        report
            .of_severity(Severity::Warning)
            .into_iter()
            .filter(|d| d.path.starts_with("policy"))
            .collect()
    }

    #[test]
    fn deny_rules_on_paths_draw_a_warning() {
        let config = parse(
            "policy:
  rules:
    - id: deny-env
      effect: deny
      paths: [\"**/.env\"]
",
        );
        let report = validate(&config, ValidationMode::Serve);
        let warnings = policy_warnings(&report);
        assert_eq!(warnings.len(), 1, "{report}");
        assert_eq!(warnings[0].path, "policy.rules[0]");
    }

    #[test]
    fn a_deny_on_args_alone_draws_a_warning() {
        let config = parse(
            "policy:
  rules:
    - id: deny-write
      effect: deny
      args: {mode: write}
",
        );
        let report = validate(&config, ValidationMode::Serve);
        let warnings = policy_warnings(&report);
        assert_eq!(warnings.len(), 1, "{report}");
        assert!(warnings[0].message.contains("exactly"));
    }

    #[test]
    fn deny_rules_on_hosts_say_where_they_apply() {
        let config = parse(
            "policy:
  rules:
    - id: deny-evil
      effect: deny
      hosts: [\"*.evil.test\"]
",
        );
        let report = validate(&config, ValidationMode::Serve);
        let warnings = policy_warnings(&report);
        assert_eq!(warnings.len(), 1, "{report}");
        assert!(warnings[0].message.contains("Wasm tools"));
    }

    #[test]
    fn allow_by_default_is_tolerated_in_dry_run() {
        let config = parse("policy:\n  default: allow\n  dry_run: true\n");
        let report = validate(&config, ValidationMode::DryRun);
        assert!(report.is_ok(), "{report}");
        assert_eq!(policy_warnings(&report).len(), 1);
    }

    #[test]
    fn a_deny_rule_behind_a_catch_all_allow_is_dead_config() {
        let config = parse(
            "policy:\n  rules:\n    - id: allow-everything\n      effect: allow\n    - id: block-secrets\n      effect: deny\n      tool: fs_write\n",
        );
        let messages = errors(&config);
        assert!(messages[0].contains("can never apply"), "{messages:?}");
    }

    #[test]
    fn duplicate_rule_ids_are_refused() {
        let config = parse(
            "policy:\n  rules:\n    - id: dup\n      effect: allow\n      tool: a\n    - id: dup\n      effect: deny\n      tool: b\n",
        );
        assert!(errors(&config)[0].contains("duplicate rule id"));
    }

    #[test]
    fn http_transport_without_a_bind_address_is_refused() {
        let config = parse("server:\n  transports: [http]\n");
        assert!(errors(&config)[0].contains("no bind address"));
    }

    #[test]
    fn binding_beyond_loopback_warns() {
        let config = parse("server:\n  transports: [http]\n  http:\n    bind: \"0.0.0.0:8899\"\n");
        let report = validate(&config, ValidationMode::Serve);
        assert!(report.is_ok(), "{report}");
        assert!(report.diagnostics[0].message.contains("beyond loopback"));
    }

    #[test]
    fn plaintext_upstream_credentials_warn() {
        let config = parse(
            "upstreams:\n  - name: local\n    transport:\n      http:\n        url: http://localhost:9000\n",
        );
        let report = validate(&config, ValidationMode::Serve);
        assert!(report.is_ok(), "{report}");
        assert!(!report.diagnostics.is_empty());
    }

    #[test]
    fn credentials_in_an_upstream_env_block_are_refused() {
        let config = parse(
            "upstreams:\n  - name: child\n    transport:\n      stdio:\n        command: ./server\n        env:\n          API_TOKEN: literal\n",
        );
        assert!(errors(&config)[0].contains("plaintext config"));
    }

    #[test]
    fn missing_rego_module_is_refused() {
        let config = parse("policy:\n  rego: ./missing.rego\n");
        assert!(errors(&config)[0].contains("does not exist"));
    }

    #[test]
    fn constraints_on_a_deny_rule_are_refused() {
        let config = parse(
            "policy:\n  rules:\n    - id: no\n      effect: deny\n      tool: x\n      constraints:\n        memory_limit: 1MB\n",
        );
        let errors = errors(&config);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("only apply to `allow` rules"));
    }

    #[test]
    fn zero_quota_is_refused() {
        let config = parse(
            "policy:\n  rules:\n    - id: q\n      effect: allow\n      tool: x\n      constraints:\n        quota:\n          max_calls: 0\n          window: 1m\n",
        );
        let errors = errors(&config);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("at least one call"));
    }

    #[test]
    fn zero_quota_window_is_refused() {
        let config = parse(
            "policy:\n  rules:\n    - id: q\n      effect: allow\n      tool: x\n      constraints:\n        quota:\n          max_calls: 5\n          window: 0s\n",
        );
        assert!(errors(&config)[0].contains("longer than zero"));
    }

    #[test]
    fn quota_parses_with_human_units() {
        let config = parse(
            "policy:\n  rules:\n    - id: q\n      effect: allow\n      tool: search\n      caller: \"session-*\"\n      uris: [\"file:///srv/**\"]\n      constraints:\n        quota:\n          max_calls: 10\n          window: 1m\n        time_limit: 2s\n",
        );
        assert!(errors(&config).is_empty(), "{:?}", errors(&config));
        let rule = &config.policy.rules[0];
        assert_eq!(rule.caller.as_deref(), Some("session-*"));
        assert_eq!(rule.uris, vec!["file:///srv/**".to_owned()]);
        let constraints = rule.constraints.as_ref().expect("constraints");
        let quota = constraints.quota.as_ref().expect("quota");
        assert_eq!(quota.max_calls, 10);
        assert_eq!(quota.window, std::time::Duration::from_secs(60));
        assert_eq!(
            constraints.time_limit,
            Some(std::time::Duration::from_secs(2))
        );
    }

    #[test]
    fn diagnostics_render_with_hints_and_severities() {
        let diagnostic = Diagnostic::error_with_hint("a.b", "went wrong", "try this");
        assert_eq!(
            diagnostic.render(),
            "error: a.b: went wrong (hint: try this)"
        );
        assert_eq!(diagnostic.to_string(), diagnostic.render());
        assert_eq!(Diagnostic::warning("c", "meh").render(), "warning: c: meh");
    }

    #[test]
    fn an_empty_report_renders_friendly() {
        assert_eq!(
            ValidationReport::default().to_string(),
            "configuration is valid"
        );
    }
}
