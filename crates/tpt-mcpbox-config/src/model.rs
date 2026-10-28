// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The `tpt-mcpbox.yaml` data model.
//!
//! Every struct denies unknown fields: a typo in a capability grant must fail
//! loudly rather than silently widen or narrow authority. Sizes and durations
//! are parsed from human-friendly strings (`"64MB"`, `"500ms"`) and stored as
//! typed values so downstream crates never re-parse configuration.
//!
//! Field names and shapes track the design spec's configuration example
//! (`wasm_path`, `capabilities.network`, `capabilities.filesystem.read`, ...).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Current configuration schema version.
pub const CONFIG_VERSION: u32 = 1;

/// Root configuration document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema version; refuse to load a future version rather than guess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,

    /// Agent-facing transport settings.
    #[serde(default)]
    pub server: ServerConfig,

    /// Locally executed Wasm tools.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolConfig>,

    /// External MCP servers to proxy to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<UpstreamConfig>,

    /// Policy evaluation settings (Phase 3).
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Audit log settings (Phase 9).
    #[serde(default)]
    pub audit: AuditConfig,

    /// Prometheus endpoint settings (Phase 9).
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Logging settings (Phase 9).
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Agent-facing transports to expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// Newline-delimited JSON on stdin/stdout.
    Stdio,
    /// MCP Streamable HTTP.
    Http,
}

/// HTTP listener settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpServerConfig {
    /// `host:port` to bind, e.g. `127.0.0.1:8899`.
    pub bind: String,
    /// Extra origins accepted besides the loopback default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_origins: Vec<String>,
    /// Name of the secret (environment variable or `.env` key) that holds the
    /// bearer token clients must send as `Authorization: Bearer <token>`.
    /// Required for any non-loopback bind. The token itself never goes in the
    /// configuration file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_env: Option<String>,
}

/// Server transport configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Enabled transports; default is stdio only.
    #[serde(default)]
    pub transports: Vec<Transport>,
    /// HTTP listener; required when `http` is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpServerConfig>,
    /// Longest a `tools/call` may run end to end, e.g. `"30s"`. Unset means
    /// only each tool's own `time_limit` applies.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "duration_option"
    )]
    #[schemars(with = "String")]
    pub request_timeout: Option<Duration>,
}

impl ServerConfig {
    /// `true` when the stdio transport is enabled (the default).
    #[must_use]
    pub fn has_stdio(&self) -> bool {
        self.transports.is_empty() || self.transports.contains(&Transport::Stdio)
    }

    /// `true` when the Streamable HTTP transport is enabled.
    #[must_use]
    pub fn has_http(&self) -> bool {
        self.transports.contains(&Transport::Http)
    }
}

/// A locally hosted Wasm tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolConfig {
    /// Unique name the agent calls, e.g. `github_search`.
    pub name: String,
    /// Human-readable description surfaced to the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Path to a `.wasm` component on disk. Mutually exclusive with
    /// `oci_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_path: Option<PathBuf>,
    /// OCI reference to pull the component from, e.g.
    /// `oci://ghcr.io/tpt-solutions/mcpbox-fs:1.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci_ref: Option<String>,
    /// Expected SHA-256 of the component; required once publishing starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Whether the tool is advertised to the agent.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Ambient authority granted to this tool.
    #[serde(default)]
    pub capabilities: Capabilities,
    /// Secrets injected at the proxy layer for outbound requests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretBinding>,
    /// Resource limits applied per invocation.
    #[serde(default)]
    pub limits: Limits,
    /// Rate and concurrency limits.
    #[serde(default)]
    pub rate_limit: RateLimit,
}

impl ToolConfig {
    /// Human-readable origin, used in diagnostics and audit entries.
    #[must_use]
    pub fn origin_display(&self) -> String {
        if let Some(path) = &self.wasm_path {
            path.display().to_string()
        } else if let Some(reference) = &self.oci_ref {
            reference.clone()
        } else {
            "<unset>".to_owned()
        }
    }
}

/// Serde default for `enabled` fields: a configured entry is enabled unless it
/// says otherwise.
fn default_true() -> bool {
    true
}

/// Filesystem grants. Globs are resolved against the hub's working directory
/// and canonicalized before being handed to the sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesystemCapabilities {
    /// Read-only globs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    /// Read-write globs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<String>,
}

/// Everything a tool is allowed to touch. Every field defaults to *nothing*.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// Outbound host allowlist. Empty means **no network at all**.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Filesystem grants.
    #[serde(default)]
    pub filesystem: FilesystemCapabilities,
    /// Maximum linear memory, e.g. `"64MB"`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "byte_size_option"
    )]
    #[schemars(with = "String")]
    pub memory_limit: Option<u64>,
    /// Maximum wall-clock per invocation, e.g. `"2s"`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "duration_option"
    )]
    #[schemars(with = "String")]
    pub time_limit: Option<Duration>,
    /// Environment variable names to expose. Empty means none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
}

/// Maps a secret from the environment onto an outbound HTTP header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretBinding {
    /// Environment variable holding the secret value.
    pub env: String,
    /// Header name to inject, e.g. `Authorization`.
    pub header: String,
    /// Optional value prefix, e.g. `Bearer` for
    /// `Authorization: Bearer <token>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// Per-invocation resource limits.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Maximum simultaneous invocations of this tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_calls: Option<u32>,
    /// Maximum serialized `tools/call` argument size.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "byte_size_option"
    )]
    #[schemars(with = "String")]
    pub max_argument_bytes: Option<u64>,
    /// Maximum result payload the tool may return.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "byte_size_option"
    )]
    #[schemars(with = "String")]
    pub max_result_bytes: Option<u64>,
}

/// Rate and concurrency limits for one tool or client.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    /// Sustained requests per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_second: Option<f64>,
    /// Bucket size for bursty traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    /// Maximum simultaneous calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
}

impl RateLimit {
    /// `true` when no limiting is configured.
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.requests_per_second.is_none() && self.max_concurrency.is_none()
    }
}

/// How to reach an upstream MCP server.
///
/// Modelled as optional sections rather than a tagged enum because that is what
/// the YAML looks like:
///
/// ```yaml
/// transport:
///   http:
///     url: https://mcp.example/api
/// ```
///
/// Exactly one section must be set; [`UpstreamTransport::kind`] reports which.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTransport {
    /// Spawn and supervise a child process speaking MCP over stdio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdio: Option<StdioUpstream>,
    /// Talk MCP Streamable HTTP to a URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpUpstream>,
}

impl UpstreamTransport {
    /// Which section is set, or `None` when the transport is ambiguous or empty.
    #[must_use]
    pub fn kind(&self) -> Option<&'static str> {
        match (&self.stdio, &self.http) {
            (Some(_), None) => Some("stdio"),
            (None, Some(_)) => Some("http"),
            _ => None,
        }
    }

    /// `true` when exactly one transport section is set.
    #[must_use]
    pub fn is_exclusive(&self) -> bool {
        self.kind().is_some()
    }
}

/// Child-process upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StdioUpstream {
    /// Executable to spawn. Resolved from `PATH` unless absolute.
    pub command: String,
    /// Arguments passed to the executable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Extra environment variables. The inherited environment is *not*
    /// forwarded; name every variable the child needs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Working directory for the child.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
}

/// HTTP upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpUpstream {
    /// Base URL of the upstream MCP endpoint.
    pub url: String,
    /// Static headers to send. Secret values belong in `secrets`, not here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

/// An external MCP server to proxy to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Unique name used in diagnostics and audit entries.
    pub name: String,
    /// Transport used to reach it.
    pub transport: UpstreamTransport,
    /// Namespace prefix applied to this upstream's tools, e.g. `github__`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Whether the upstream is started at boot.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Tool names to expose (globs allowed). Empty means "all", subject to
    /// `deny`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Tool names to hide (globs allowed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Secret bindings applied to upstream requests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretBinding>,
    /// Renames and description overrides for this upstream's tools. The
    /// `allow` and `deny` lists above filter tools.
    #[serde(default, skip_serializing_if = "ToolOverrides::is_empty")]
    pub tools: ToolOverrides,
    /// Filter and renames for this upstream's prompts.
    #[serde(default, skip_serializing_if = "PromptFilter::is_empty")]
    pub prompts: PromptFilter,
    /// Filter for this upstream's resources, by URI glob. Setting it also
    /// hides the upstream's resource templates, since a template can reach URIs
    /// the filter would refuse.
    #[serde(default, skip_serializing_if = "ResourceFilter::is_empty")]
    pub resources: ResourceFilter,
}

impl UpstreamConfig {
    /// Effective tool name after applying the configured prefix.
    #[must_use]
    pub fn qualify(&self, tool: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{prefix}{tool}"),
            None => tool.to_owned(),
        }
    }
}

/// Renames and description overrides for an upstream's tools. Keys are the
/// upstream's own tool names. A rename changes the name agents see, before the
/// upstream prefix is added. Calls still reach the upstream's own name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolOverrides {
    /// Upstream tool name to the exposed name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rename: BTreeMap<String, String>,
    /// Upstream tool name to a replacement description.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub describe: BTreeMap<String, String>,
}

impl ToolOverrides {
    /// Whether no override is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rename.is_empty() && self.describe.is_empty()
    }
}

/// Allow/deny globs and renames for an upstream's prompts. Matching works like
/// the tool `allow`/`deny` lists, on the upstream's own prompt names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PromptFilter {
    /// Prompt names to expose (globs allowed). Empty means all, subject to
    /// `deny`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Prompt names to hide (globs allowed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Upstream prompt name to the exposed name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rename: BTreeMap<String, String>,
    /// Upstream prompt name to a replacement description.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub describe: BTreeMap<String, String>,
}

impl PromptFilter {
    /// Whether no filter or override is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
            && self.deny.is_empty()
            && self.rename.is_empty()
            && self.describe.is_empty()
    }
}

/// Allow/deny URI globs for an upstream's resources.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceFilter {
    /// URIs to expose (globs allowed). Empty means all, subject to `deny`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// URIs to hide (globs allowed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

impl ResourceFilter {
    /// Whether no filter is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

/// Whether a rule grants or refuses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// Grant the call.
    Allow,
    /// Refuse the call. This is the default, so an omitted or mistyped
    /// `policy.default` can never open the gate.
    #[default]
    Deny,
}

/// One rule in the YAML policy DSL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable identifier recorded in audit entries.
    pub id: String,
    /// Human-readable explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Allow or deny.
    pub effect: Effect,
    /// Tool name glob this rule matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// MCP method this rule matches, e.g. `tools/call`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Exact argument match, e.g. `{ path: "./workspace/notes.txt" }`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, serde_json::Value>,
    /// Target host globs this rule covers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Filesystem path globs this rule covers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Caller identity glob, e.g. `session-*`. Requests without a caller never
    /// match a rule that sets this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    /// Resource URI globs this rule covers, e.g. `file:///srv/docs/**`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uris: Vec<String>,
    /// Limits attached to an `allow` rule: the call is allowed *with* these
    /// constraints. Rejected on `deny` rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<RuleConstraints>,
}

/// Limits attached to an allowing rule.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleConstraints {
    /// Call budget per caller, enforced by the policy engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quota>,
    /// Memory ceiling handed to the runtime, e.g. `"32MB"`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "byte_size_option"
    )]
    #[schemars(with = "String")]
    pub memory_limit: Option<u64>,
    /// Wall-clock ceiling handed to the runtime, e.g. `"2s"`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "duration_option"
    )]
    #[schemars(with = "String")]
    pub time_limit: Option<Duration>,
}

/// A call budget: at most `max_calls` per caller within a sliding `window`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Quota {
    /// Calls allowed inside one window.
    pub max_calls: u32,
    /// Sliding window length, e.g. `"1m"`.
    #[serde(with = "duration_required")]
    #[schemars(with = "String")]
    pub window: Duration,
}

/// Policy evaluation configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Decision when no rule matches. Keep this `deny`: the `allow` mode exists
    /// for migration tests and is rejected by [`crate::validate`] when
    /// `dry_run` is off.
    #[serde(default)]
    pub default: Effect,
    /// YAML DSL rules, evaluated in order; first match wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// Rego module to evaluate instead of / in addition to the DSL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rego: Option<PathBuf>,
    /// Audit-only mode: log what would be denied without blocking.
    #[serde(default)]
    pub dry_run: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default: Effect::Deny,
            rules: Vec::new(),
            rego: None,
            dry_run: false,
        }
    }
}

impl PolicyConfig {
    /// `true` when nothing is allowed without an explicit rule.
    #[must_use]
    pub fn is_deny_by_default(&self) -> bool {
        self.default == Effect::Deny
    }
}

/// Audit log configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Whether the audit log is written at all.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Log file path.
    #[serde(default = "default_audit_path")]
    pub path: PathBuf,
    /// Sign each segment so tampering is detectable offline.
    #[serde(default)]
    pub sign: bool,
    /// Roll the log when it exceeds this size.
    #[serde(default = "default_segment_bytes", with = "byte_size_required")]
    #[schemars(with = "String")]
    pub max_segment_bytes: u64,
}

fn default_audit_path() -> PathBuf {
    PathBuf::from(".mcpbox/audit.log")
}

fn default_segment_bytes() -> u64 {
    64 * 1024 * 1024
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_audit_path(),
            sign: false,
            max_segment_bytes: default_segment_bytes(),
        }
    }
}

/// Prometheus endpoint configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Whether `/metrics` is served.
    #[serde(default)]
    pub enabled: bool,
    /// `host:port` for the metrics listener.
    #[serde(default = "default_metrics_bind")]
    pub bind: String,
}

fn default_metrics_bind() -> String {
    "127.0.0.1:8898".to_owned()
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_metrics_bind(),
        }
    }
}

/// Log severity filter. The default is `info`: chatty debug logging can leak
/// argument values into a terminal that is being screen-shared.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Verbose diagnostics.
    Debug,
    /// Normal operation.
    #[default]
    Info,
    /// Significant but normal events.
    Warn,
    /// Recoverable problems.
    Error,
}

/// Logging configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Minimum severity emitted.
    #[serde(default)]
    pub level: LogLevel,
    /// Emit structured JSON logs (otherwise human-readable).
    #[serde(default = "default_true")]
    pub json: bool,
    /// Include source spans in JSON output.
    #[serde(default = "default_true")]
    pub spans: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            json: true,
            spans: true,
        }
    }
}

// Serde adapters: configuration carries human-friendly strings, the rest of
// the codebase carries typed values.

/// `Option<u64>` <-> `"64MB"` / `1024`.
pub(crate) mod byte_size_option {
    use crate::units::{format_byte_size, parse_byte_size};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<u64>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_str(&format_byte_size(*bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        let raw = Option::<serde_norway::Value>::deserialize(deserializer)?;
        match raw {
            None | Some(serde_norway::Value::Null) => Ok(None),
            Some(serde_norway::Value::Number(number)) => {
                number.as_u64().map(Some).ok_or_else(|| {
                    serde::de::Error::custom("byte size must be a non-negative integer")
                })
            }
            Some(serde_norway::Value::String(text)) => parse_byte_size(&text)
                .map(Some)
                .map_err(serde::de::Error::custom),
            Some(other) => Err(serde::de::Error::custom(format!(
                "expected a byte size like `64MB`, got {other:?}"
            ))),
        }
    }
}

/// `u64` (with a default) <-> `"64MB"`.
pub(crate) mod byte_size_required {
    use super::byte_size_option;
    use crate::units::format_byte_size;
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format_byte_size(*value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        byte_size_option::deserialize(deserializer)?
            .ok_or_else(|| serde::de::Error::custom("expected a byte size like `64MB`"))
    }
}

/// `Option<Duration>` <-> `"2s"` / `500` (milliseconds).
pub(crate) mod duration_option {
    use std::time::Duration;

    use crate::units::{format_duration, parse_duration};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(duration) => serializer.serialize_str(&format_duration(*duration)),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        let raw = Option::<serde_norway::Value>::deserialize(deserializer)?;
        match raw {
            None | Some(serde_norway::Value::Null) => Ok(None),
            Some(serde_norway::Value::Number(number)) => number
                .as_u64()
                .map(|millis| Some(Duration::from_millis(millis)))
                .ok_or_else(|| serde::de::Error::custom("duration must be a non-negative integer")),
            Some(serde_norway::Value::String(text)) => parse_duration(&text)
                .map(Some)
                .map_err(serde::de::Error::custom),
            Some(other) => Err(serde::de::Error::custom(format!(
                "expected a duration like `2s`, got {other:?}"
            ))),
        }
    }
}

/// Serde adapter for a mandatory duration, accepting the same forms as
/// [`duration_option`].
pub(crate) mod duration_required {
    use std::time::Duration;

    use crate::units::{format_duration, parse_duration};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &Duration,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format_duration(*value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Duration, D::Error> {
        let raw = serde_norway::Value::deserialize(deserializer)?;
        match raw {
            serde_norway::Value::Number(number) => number
                .as_u64()
                .map(Duration::from_millis)
                .ok_or_else(|| serde::de::Error::custom("duration must be a non-negative integer")),
            serde_norway::Value::String(text) => {
                parse_duration(&text).map_err(serde::de::Error::custom)
            }
            other => Err(serde::de::Error::custom(format!(
                "expected a duration like `1m`, got {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn parse_config(yaml: &str) -> Result<Config, serde_norway::Error> {
        serde_norway::from_str(yaml)
    }

    #[test]
    fn spec_example_parses() {
        let config = parse_config(
            r#"
tools:
  - name: github_search
    wasm_path: ./tools/github.wasm
    capabilities:
      network: ["api.github.com"]
      memory_limit: "64MB"
    secrets:
      - env: GITHUB_TOKEN
        header: Authorization
        prefix: Bearer
  - name: local_files
    wasm_path: ./tools/fs.wasm
    capabilities:
      filesystem:
        read: ["./workspace/**"]
        write: ["./workspace/output/**"]
"#,
        )
        .expect("parses");

        assert_eq!(config.tools.len(), 2);
        let github = &config.tools[0];
        assert_eq!(github.name, "github_search");
        assert_eq!(github.capabilities.memory_limit, Some(64_000_000));
        assert_eq!(github.capabilities.network, vec!["api.github.com"]);
        assert_eq!(github.secrets[0].prefix.as_deref(), Some("Bearer"));
        assert!(github.origin_display().ends_with("github.wasm"));

        let fs = &config.tools[1];
        assert_eq!(
            fs.capabilities.filesystem.write,
            vec!["./workspace/output/**"]
        );
        assert_eq!(fs.capabilities.memory_limit, None);
    }

    #[test]
    fn defaults_are_deny_by_default() {
        let config = Config::default();
        assert!(config.policy.is_deny_by_default());
        assert!(config.server.has_stdio());
        assert!(!config.server.has_http());
        assert!(config.audit.enabled);
        assert_eq!(config.audit.max_segment_bytes, 64 << 20);
        assert!(!config.metrics.enabled);
        assert_eq!(config.logging.level, LogLevel::Info);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let error = parse_config("tools:\n  - name: x\n    wasm_path: a.wasm\n    netwrok: [x]\n")
            .expect_err("typo must fail");
        assert!(error.to_string().contains("netwrok"), "unexpected: {error}");
    }

    #[test]
    fn unknown_capability_keys_are_rejected() {
        let error = parse_config(
            "tools:\n  - name: x\n    wasm_path: a.wasm\n    capabilities:\n      disk: []\n",
        )
        .expect_err("typo must fail");
        assert!(error.to_string().contains("disk"), "unexpected: {error}");
    }

    #[test]
    fn sizes_and_durations_accept_bare_numbers() {
        let config = parse_config(
            "tools:\n  - name: x\n    wasm_path: a.wasm\n    capabilities:\n      memory_limit: 1024\n      time_limit: 250\n",
        )
        .expect("parses");
        let capabilities = &config.tools[0].capabilities;
        assert_eq!(capabilities.memory_limit, Some(1024));
        assert_eq!(capabilities.time_limit, Some(Duration::from_millis(250)));
    }

    #[test]
    fn bad_units_report_actionable_errors() {
        let error = parse_config(
            "tools:\n  - name: x\n    wasm_path: a.wasm\n    capabilities:\n      memory_limit: \"64 furlongs\"\n",
        )
        .expect_err("must fail");
        assert!(
            error.to_string().contains("furlongs"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn upstreams_round_trip() {
        let config = parse_config(
            r#"
upstreams:
  - name: github
    prefix: "gh__"
    transport:
      http:
        url: https://mcp.example/api
        headers:
          X-Tenant: acme
  - name: local
    transport:
      stdio:
        command: ./server
        args: ["--stdio"]
        env:
          LOG: debug
"#,
        )
        .expect("parses");

        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.upstreams[0].qualify("issues"), "gh__issues");
        assert_eq!(config.upstreams[1].qualify("issues"), "issues");
        assert_eq!(config.upstreams[0].transport.kind(), Some("http"));
        assert_eq!(config.upstreams[1].transport.kind(), Some("stdio"));
        assert!(
            config.upstreams[0]
                .transport
                .http
                .as_ref()
                .expect("http")
                .url
                .starts_with("https://")
        );
        assert_eq!(
            config.upstreams[1]
                .transport
                .stdio
                .as_ref()
                .expect("stdio")
                .env
                .get("LOG")
                .map(String::as_str),
            Some("debug")
        );
    }

    #[test]
    fn policy_rules_parse() {
        let config = parse_config(
            r#"
policy:
  default: deny
  dry_run: true
  rules:
    - id: allow-github
      effect: allow
      tool: github_*
      hosts: ["api.github.com"]
    - id: block-secrets
      effect: deny
      tool: fs_write
      paths: ["**/.ssh/**"]
"#,
        )
        .expect("parses");

        assert!(config.policy.is_deny_by_default());
        assert!(config.policy.dry_run);
        assert_eq!(config.policy.rules.len(), 2);
        assert_eq!(config.policy.rules[0].effect, Effect::Allow);
        assert_eq!(config.policy.rules[1].paths, vec!["**/.ssh/**"]);
    }

    #[test]
    fn config_serializes_back_to_yaml_with_units() {
        let config = Config::default();
        let yaml = serde_norway::to_string(&config).expect("serializes");
        assert!(yaml.contains("audit:"), "{yaml}");
        assert!(yaml.contains("64MiB"), "{yaml}");
        let round_tripped: Config = serde_norway::from_str(&yaml).expect("re-parses");
        assert_eq!(round_tripped.audit.max_segment_bytes, 64 << 20);
    }
}
