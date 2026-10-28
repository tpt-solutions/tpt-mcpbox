// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Namespaced tool catalog and call dispatch.
//!
//! Tools from the local Wasm runtime and from every upstream are merged into
//! one catalog. An upstream tool is exposed as `<prefix><name>`, and a Wasm tool
//! under its own name. A name already in use is refused at registration time
//! rather than silently renamed, so an agent never sees two tools that look
//! alike and resolve differently.
//!
//! [`Router::call`] runs every call through, in order: the shutdown gate, the
//! rate and concurrency limiter, and then the policy. Upstream calls are checked
//! by their [`PolicyGate`]; Wasm calls are checked here, because the router is
//! the only place that sees them.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::metrics::Metrics;
use serde_json::{Map, Value, json};
use tpt_mcpbox_audit::{AuditError, AuditLog};
use tpt_mcpbox_policy::{Policy, PolicyInput};
use tpt_mcpbox_protocol::prompts::Prompt;
use tpt_mcpbox_protocol::resources::Resource;
use tpt_mcpbox_protocol::tools::{CallToolResult, Tool};
use tpt_mcpbox_proxy::{PolicyGate, ProxyError, UpstreamError};
use tpt_mcpbox_runtime::{CancelToken, LoadedTool, ToolError};
use tracing::Instrument as _;

use crate::lifecycle::{Lifecycle, ShuttingDown};
use crate::limiter::{Limiter, Rejection};
use crate::templates::TemplateRoute;

/// Why a call could not be completed.
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    /// No tool with this name is in the catalog.
    #[error("unknown tool `{0}`")]
    UnknownTool(String),
    /// A tool with this exposed name is already registered.
    #[error("tool name `{0}` is already registered")]
    Conflict(String),
    /// The server is shutting down.
    #[error(transparent)]
    ShuttingDown(#[from] ShuttingDown),
    /// Rate or concurrency limit reached.
    #[error(transparent)]
    Limited(#[from] Rejection),
    /// The policy refused the call.
    #[error("denied by policy{}: {reason}", rule_suffix(.rule_id))]
    Denied {
        /// Rule that decided the call, when one did.
        rule_id: Option<String>,
        /// Human-readable reason.
        reason: String,
    },
    /// An upstream answer matched a `refuse` scan rule, so it was withheld.
    #[error("upstream response refused by scan rule `{rule}`")]
    Refused {
        /// Name of the scan rule that matched.
        rule: String,
    },
    /// The upstream failed.
    #[error(transparent)]
    Upstream(UpstreamError),
    /// The Wasm tool failed or could not run.
    #[error(transparent)]
    Tool(#[from] ToolError),
    /// The call's arguments could not be encoded for the Wasm tool.
    #[error("cannot encode arguments: {0}")]
    Encode(#[from] serde_json::Error),
    /// The blocking task running a Wasm tool panicked or was cancelled.
    #[error("tool task did not complete: {0}")]
    TaskJoin(String),
    /// The call ran past the router's request timeout and was cancelled.
    #[error("tool call exceeded the {0:?} request timeout")]
    TimedOut(Duration),
    /// The audit record could not be written. Raised before dispatch, so the
    /// call does not run unrecorded.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// No upstream serves this resource URI.
    #[error("unknown resource `{0}`")]
    UnknownResource(String),
    /// No upstream provides this prompt.
    #[error("unknown prompt `{0}`")]
    UnknownPrompt(String),
}

impl RouterError {
    /// Short, stable label for the audit log.
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::UnknownTool(_) => "unknown_tool",
            Self::Conflict(_) => "conflict",
            Self::ShuttingDown(_) => "shutting_down",
            Self::Limited(Rejection::ToolRate(_) | Rejection::ClientRate(_)) => "rate_limited",
            Self::Limited(_) => "concurrency_limited",
            Self::Denied { .. } => "denied",
            Self::Refused { .. } => "response_refused",
            Self::Upstream(_) => "upstream_error",
            Self::Tool(_) => "tool_error",
            Self::Encode(_) => "invalid_arguments",
            Self::TaskJoin(_) => "internal_error",
            Self::TimedOut(_) => "timed_out",
            Self::Audit(_) => "audit_error",
            Self::UnknownResource(_) => "unknown_resource",
            Self::UnknownPrompt(_) => "unknown_prompt",
        }
    }
}

/// Writes the `finish` record for a call that was dropped before it completed,
/// for example when the agent cancelled it. Without this the log would end
/// with a `start` that has no match. Disarmed once the call completes.
struct AbandonedCall {
    audit: Option<Arc<AuditLog>>,
    kind: &'static str,
    finish: Option<Map<String, Value>>,
    started: Instant,
}

impl AbandonedCall {
    /// Takes the finish record back, so the caller writes it and `drop` does not.
    fn disarm(&mut self) -> Map<String, Value> {
        self.finish.take().unwrap_or_default()
    }
}

impl Drop for AbandonedCall {
    fn drop(&mut self) {
        let (Some(log), Some(mut finish)) = (self.audit.take(), self.finish.take()) else {
            return;
        };
        let duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        finish.insert("outcome".to_owned(), json!("cancelled"));
        finish.insert("duration_ms".to_owned(), json!(duration_ms));
        // Synchronous on purpose: `drop` cannot await. This runs only on the
        // cancel path, and the fsync is the same one the normal path pays.
        if let Err(err) = log.append(self.kind, Value::Object(finish)) {
            tracing::error!("audit finish record failed: {err}");
        }
    }
}

fn rule_suffix(rule_id: &Option<String>) -> String {
    rule_id
        .as_deref()
        .map_or_else(String::new, |id| format!(" (rule `{id}`)"))
}

impl From<ProxyError> for RouterError {
    fn from(err: ProxyError) -> Self {
        match err {
            ProxyError::Denied { rule_id, reason } => Self::Denied { rule_id, reason },
            ProxyError::Refused { rule } => Self::Refused { rule },
            ProxyError::Upstream(err) => Self::Upstream(err),
        }
    }
}

/// Result of a successful call.
#[derive(Debug)]
pub enum ToolOutput {
    /// Result from an upstream server, passed through unchanged.
    Upstream(CallToolResult),
    /// Raw result string from a Wasm tool.
    Wasm(String),
}

pub(crate) enum Backend {
    Wasm {
        tool: Arc<LoadedTool>,
        tool_name: String,
    },
    Upstream {
        gate: Arc<PolicyGate>,
        tool_name: String,
    },
}

/// How an upstream's names and descriptions are shown to agents. Keys are the
/// upstream's own names. A rename applies before the upstream's prefix.
#[derive(Debug, Clone, Default)]
pub struct Exposure {
    /// Upstream name to the name the agent sees.
    pub rename: BTreeMap<String, String>,
    /// Upstream name to replacement description.
    pub describe: BTreeMap<String, String>,
}

impl Exposure {
    pub(crate) fn rename_of<'a>(&'a self, upstream: &'a str) -> &'a str {
        self.rename.get(upstream).map_or(upstream, String::as_str)
    }

    pub(crate) fn description_of(&self, upstream: &str) -> Option<&str> {
        self.describe.get(upstream).map(String::as_str)
    }
}

pub(crate) struct Route {
    backend: Backend,
    descriptor: Tool,
}

/// Merged catalog of Wasm and upstream tools, with the controls applied to
/// each call.
pub struct Router {
    pub(crate) routes: BTreeMap<String, Route>,
    pub(crate) limiter: Limiter,
    pub(crate) lifecycle: Lifecycle,
    pub(crate) policy: Arc<Policy>,
    pub(crate) audit: Option<Arc<AuditLog>>,
    /// Resource URI → the upstream that serves it.
    pub(crate) resources: BTreeMap<String, Arc<PolicyGate>>,
    /// Resource descriptors, as listed to the agent.
    pub(crate) resource_list: BTreeMap<String, Resource>,
    /// Resource templates, in registration order. Reads that no exact URI
    /// matches are tried against these.
    pub(crate) resource_templates: Vec<TemplateRoute>,
    /// Exposed prompt name → the upstream and its own name for the prompt.
    pub(crate) prompts: BTreeMap<String, PromptRoute>,
    /// Prompt descriptors under their exposed names.
    pub(crate) prompt_list: BTreeMap<String, Prompt>,
    /// Counters and latency histograms for every call.
    pub(crate) metrics: Arc<Metrics>,
    /// Longest a `tools/call` may run, end to end. `None` leaves only each
    /// tool's own time limit.
    pub(crate) request_timeout: Option<Duration>,
}

/// Where a prompt lives: the upstream gate and the prompt's name there.
#[derive(Debug)]
pub(crate) struct PromptRoute {
    pub(crate) gate: Arc<PolicyGate>,
    pub(crate) upstream_name: String,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("tools", &self.routes.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Router {
    /// Creates an empty router with the given limiter and policy.
    #[must_use]
    pub fn new(limiter: Limiter, policy: Arc<Policy>) -> Self {
        Self {
            routes: BTreeMap::new(),
            limiter,
            lifecycle: Lifecycle::new(),
            policy,
            audit: None,
            resources: BTreeMap::new(),
            resource_list: BTreeMap::new(),
            resource_templates: Vec::new(),
            prompts: BTreeMap::new(),
            prompt_list: BTreeMap::new(),
            metrics: Arc::new(Metrics::new()),
            request_timeout: None,
        }
    }

    /// Caps every `tools/call` at `limit`. A call that runs longer is cancelled
    /// and reported as a tool error with the outcome `timed_out`.
    #[must_use]
    pub fn with_request_timeout(mut self, limit: Duration) -> Self {
        self.request_timeout = Some(limit);
        self
    }

    /// The metrics this router updates. Share it with the endpoint that renders
    /// them.
    #[must_use]
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Records every call to `audit`: a `start` entry before dispatch and a
    /// `finish` entry with the outcome. Argument values are never recorded,
    /// only their key names.
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<AuditLog>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Registers a Wasm tool under the name in its descriptor.
    pub fn add_wasm(&mut self, tool: Arc<LoadedTool>, descriptor: Tool) -> Result<(), RouterError> {
        self.metrics.track_pool(&tool);
        let exposed = descriptor.name.clone();
        let backend = Backend::Wasm {
            tool,
            tool_name: exposed.clone(),
        };
        self.insert(
            exposed,
            Route {
                backend,
                descriptor,
            },
        )
    }

    /// Registers every tool of an upstream under `<prefix><name>`.
    ///
    /// Registration is all-or-nothing: if any name collides, nothing from this
    /// upstream is added.
    pub fn add_upstream(
        &mut self,
        prefix: Option<&str>,
        gate: impl Into<Arc<PolicyGate>>,
        tools: Vec<Tool>,
    ) -> Result<(), RouterError> {
        self.add_upstream_exposed(prefix, gate, tools, &Exposure::default())
    }

    /// Like [`Router::add_upstream`], with the upstream's renames and
    /// description overrides applied. A rename changes the name before the
    /// prefix is added; the call still goes to the upstream's own name.
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::Conflict`] on a name collision, after renames.
    pub fn add_upstream_exposed(
        &mut self,
        prefix: Option<&str>,
        gate: impl Into<Arc<PolicyGate>>,
        tools: Vec<Tool>,
        exposure: &Exposure,
    ) -> Result<(), RouterError> {
        let gate: Arc<PolicyGate> = gate.into();
        let prefix = prefix.unwrap_or("");
        let names: Vec<String> = tools
            .iter()
            .map(|tool| format!("{prefix}{}", exposure.rename_of(&tool.name)))
            .collect();

        if let Some(clash) = names.iter().find(|name| self.routes.contains_key(*name)) {
            return Err(RouterError::Conflict(clash.clone()));
        }
        let mut seen = std::collections::HashSet::new();
        if let Some(dup) = names.iter().find(|name| !seen.insert(*name)) {
            return Err(RouterError::Conflict(dup.clone()));
        }

        for (exposed, tool) in names.into_iter().zip(tools) {
            let upstream_name = tool.name.clone();
            let backend = Backend::Upstream {
                gate: Arc::clone(&gate),
                tool_name: upstream_name.clone(),
            };
            let mut descriptor = Tool {
                name: exposed.clone(),
                ..tool
            };
            if let Some(text) = exposure.description_of(&upstream_name) {
                descriptor.description = Some(text.to_owned());
            }
            self.routes.insert(
                exposed,
                Route {
                    backend,
                    descriptor,
                },
            );
        }
        Ok(())
    }

    fn insert(&mut self, exposed: String, route: Route) -> Result<(), RouterError> {
        if self.routes.contains_key(&exposed) {
            return Err(RouterError::Conflict(exposed));
        }
        self.routes.insert(exposed, route);
        Ok(())
    }

    /// Every exposed tool, in name order.
    #[must_use]
    pub fn list(&self) -> Vec<Tool> {
        self.routes.values().map(|r| r.descriptor.clone()).collect()
    }

    /// Stops admitting calls. See [`Lifecycle::shutdown`].
    pub async fn shutdown(&self, timeout: std::time::Duration) -> crate::lifecycle::Drain {
        self.lifecycle.shutdown(timeout).await
    }

    /// Dispatches one `tools/call`, recording it when auditing is enabled.
    ///
    /// `caller` identifies the session for limits and policy. `name` is the
    /// exposed name from [`Router::list`].
    ///
    /// If the `start` record cannot be written the call is refused. If the
    /// `finish` record cannot be written, the call's result is still returned
    /// and the failure is logged at error level: the tool has already run, so
    /// reporting it as failed would invite a retry.
    pub async fn call(
        &self,
        caller: &str,
        name: &str,
        arguments: Option<Map<String, Value>>,
        cancel: CancelToken,
    ) -> Result<ToolOutput, RouterError> {
        let mut keys: Vec<&str> = arguments
            .as_ref()
            .map_or_else(Vec::new, |a| a.keys().map(String::as_str).collect());
        keys.sort_unstable();
        let mut extra = Map::new();
        extra.insert("arg_keys".to_owned(), json!(keys));

        let work = self.dispatch(caller, name, arguments, cancel.clone());
        let bounded = async {
            let Some(limit) = self.request_timeout else {
                return work.await;
            };
            match tokio::time::timeout(limit, work).await {
                Ok(result) => result,
                Err(_) => {
                    // Dropping `work` does not stop a Wasm tool that is already
                    // running on a blocking thread, so the token is set here.
                    cancel.cancel();
                    Err(RouterError::TimedOut(limit))
                }
            }
        };
        self.audited("tool_call", "tool", name, caller, extra, bounded)
            .await
    }

    /// Runs `work` between a `start` and a `finish` audit record.
    ///
    /// `subject_key` names the subject in the records (`tool`, `resource` or
    /// `prompt`). `extra` adds fields to the `start` record only; it must not
    /// carry secret values.
    pub(crate) async fn audited<T>(
        &self,
        kind: &'static str,
        subject_key: &'static str,
        subject: &str,
        caller: &str,
        extra: Map<String, Value>,
        work: impl Future<Output = Result<T, RouterError>>,
    ) -> Result<T, RouterError> {
        let started = Instant::now();
        // Counted until the guard drops, which also covers a dropped call.
        let _in_flight = self.metrics.enter();
        // One span per request. Only names, outcomes and durations go on it:
        // argument values never reach the span.
        let span = tracing::info_span!(
            "request",
            kind,
            caller,
            subject,
            outcome = tracing::field::Empty,
            rule_id = tracing::field::Empty,
            duration_ms = tracing::field::Empty,
        );

        let mut start = Map::new();
        start.insert("phase".to_owned(), json!("start"));
        start.insert("caller".to_owned(), json!(caller));
        start.insert(subject_key.to_owned(), json!(subject));
        start.extend(extra);
        self.record(kind, Value::Object(start)).await?;

        // Built before the work runs, so a call dropped midway (cancelled by the
        // agent, or timed out by its caller) still gets a finish record.
        let mut base = Map::new();
        base.insert("phase".to_owned(), json!("finish"));
        base.insert("caller".to_owned(), json!(caller));
        base.insert(subject_key.to_owned(), json!(subject));
        let mut abandoned = AbandonedCall {
            audit: self.audit.clone(),
            kind,
            finish: Some(base),
            started,
        };

        let result = work.instrument(span.clone()).await;
        let mut finish = abandoned.disarm();
        let outcome = result.as_ref().map_or_else(RouterError::outcome, |_| "ok");
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.metrics
            .observe(metric_kind(kind), outcome, started.elapsed());

        span.record("outcome", outcome);
        span.record("duration_ms", duration_ms);
        finish.insert("outcome".to_owned(), json!(outcome));
        finish.insert("duration_ms".to_owned(), json!(duration_ms));
        let rule_id = match &result {
            Err(RouterError::Denied { rule_id, .. }) => Some(rule_id.clone()),
            Err(RouterError::Refused { rule }) => Some(Some(rule.clone())),
            _ => None,
        };
        if let Some(rule_id) = rule_id {
            span.record("rule_id", tracing::field::debug(&rule_id));
            finish.insert("rule_id".to_owned(), json!(rule_id));
        }
        span.in_scope(|| tracing::info!("request finished"));
        if let Err(err) = self.record(kind, Value::Object(finish)).await {
            tracing::error!("audit finish record failed: {err}");
        }
        result
    }

    async fn record(&self, kind: &'static str, data: Value) -> Result<(), RouterError> {
        let Some(log) = self.audit.clone() else {
            return Ok(());
        };
        // fsync blocks, so the write runs off the async worker threads.
        tokio::task::spawn_blocking(move || log.append(kind, data))
            .await
            .map_err(|e| RouterError::TaskJoin(e.to_string()))??;
        Ok(())
    }

    async fn dispatch(
        &self,
        caller: &str,
        name: &str,
        arguments: Option<Map<String, Value>>,
        cancel: CancelToken,
    ) -> Result<ToolOutput, RouterError> {
        let route = self
            .routes
            .get(name)
            .ok_or_else(|| RouterError::UnknownTool(name.to_owned()))?;

        let _in_flight = self.lifecycle.begin()?;
        let _permit = self.limiter.acquire_queued(name, caller).await?;

        match &route.backend {
            Backend::Upstream { gate, tool_name } => {
                let result = gate.call_tool(caller, tool_name, arguments).await?;
                Ok(ToolOutput::Upstream(result))
            }
            Backend::Wasm { tool, tool_name } => {
                let input = PolicyInput {
                    method: "tools/call".to_owned(),
                    caller: Some(caller.to_owned()),
                    tool: Some(tool_name.clone()),
                    arguments: arguments.clone().map_or(Value::Null, Value::Object),
                    ..PolicyInput::default()
                };
                let decision = self.policy.evaluate(&input);
                if !decision.is_allowed() {
                    return Err(RouterError::Denied {
                        rule_id: decision.rule_id,
                        reason: decision.reason,
                    });
                }

                let args_json =
                    serde_json::to_string(&Value::Object(arguments.unwrap_or_default()))?;
                let tool = Arc::clone(tool);
                let tool_name = tool_name.clone();
                let output =
                    tokio::task::spawn_blocking(move || tool.call(&tool_name, &args_json, &cancel))
                        .await
                        .map_err(|e| RouterError::TaskJoin(e.to_string()))?;
                Ok(ToolOutput::Wasm(output?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};
    use tpt_mcpbox_config::model::{Effect, PolicyConfig, Rule};
    use tpt_mcpbox_proxy::{Client, UpstreamOptions};

    use super::*;
    use crate::limiter::Limits;

    pub(super) fn tool(name: &str) -> Tool {
        Tool {
            name: name.to_owned(),
            title: None,
            description: None,
            input_schema: json!({ "type": "object" }),
            output_schema: None,
            annotations: None,
        }
    }

    pub(super) fn allow(tool_name: &str) -> Rule {
        Rule {
            id: format!("allow-{tool_name}"),
            description: None,
            effect: Effect::Allow,
            tool: Some(tool_name.to_owned()),
            method: None,
            args: BTreeMap::new(),
            hosts: Vec::new(),
            paths: Vec::new(),
            caller: None,
            uris: Vec::new(),
            constraints: None,
        }
    }

    pub(super) fn policy(rules: Vec<Rule>) -> Arc<Policy> {
        let config = PolicyConfig {
            rules,
            ..PolicyConfig::default()
        };
        Arc::new(Policy::from_config(&config).expect("policy compiles"))
    }

    /// Fake upstream that answers every `tools/call` with a text result.
    pub(super) fn gate(policy: Arc<Policy>) -> PolicyGate {
        let (client_side, server_side) = duplex(64 * 1024);
        let (read, write) = tokio::io::split(client_side);
        let client = Client::connect(
            read,
            write,
            UpstreamOptions {
                request_timeout: Duration::from_secs(5),
                ..UpstreamOptions::default()
            },
        );
        let (sread, mut swrite) = tokio::io::split(server_side);
        tokio::spawn(async move {
            let mut lines = BufReader::new(sread).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let msg: Value = serde_json::from_str(&line).unwrap();
                if msg["method"] == "tools/call" {
                    // `hang` never answers, so callers can exercise timeouts.
                    if msg["params"]["name"] == "hang" {
                        continue;
                    }
                    let reply = json!({
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "result": { "content": [{ "type": "text", "text": msg["params"]["name"] }] }
                    });
                    swrite
                        .write_all(format!("{reply}\n").as_bytes())
                        .await
                        .unwrap();
                }
            }
        });
        PolicyGate::new("fake", client, policy)
    }

    fn router(rules: Vec<Rule>, limits: Limits) -> Router {
        let policy = policy(rules);
        Router::new(Limiter::new([], limits), policy)
    }

    #[tokio::test]
    async fn prefixed_upstream_tools_are_listed_and_dispatched() {
        let policy = policy(vec![allow("search")]);
        let mut router = Router::new(Limiter::new([], Limits::default()), Arc::clone(&policy));
        router
            .add_upstream(Some("gh__"), gate(policy), vec![tool("search")])
            .unwrap();

        let names: Vec<_> = router.list().into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["gh__search"]);

        let out = router
            .call("agent", "gh__search", None, CancelToken::new())
            .await
            .unwrap();
        match out {
            ToolOutput::Upstream(result) => {
                assert_eq!(result.content.len(), 1);
            }
            other => panic!("expected upstream output, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn renamed_tool_is_exposed_under_its_new_name_and_called_upstream_by_its_own() {
        let policy = policy(vec![allow("search")]);
        let mut router = Router::new(Limiter::new([], Limits::default()), Arc::clone(&policy));
        let exposure = Exposure {
            rename: BTreeMap::from([("search".to_owned(), "find".to_owned())]),
            describe: BTreeMap::from([("search".to_owned(), "Find things".to_owned())]),
        };
        router
            .add_upstream_exposed(
                Some("kb__"),
                gate(Arc::clone(&policy)),
                vec![tool("search")],
                &exposure,
            )
            .unwrap();

        let listed = router.list();
        assert_eq!(listed[0].name, "kb__find");
        assert_eq!(listed[0].description.as_deref(), Some("Find things"));
        assert!(
            router
                .call("agent", "kb__search", None, CancelToken::new())
                .await
                .is_err()
        );

        // The mock upstream echoes the name it was called by, which must be its own.
        let out = router
            .call("agent", "kb__find", None, CancelToken::new())
            .await
            .unwrap();
        match out {
            ToolOutput::Upstream(result) => {
                let value = serde_json::to_value(&result).unwrap();
                assert_eq!(value["content"][0]["text"], "search");
            }
            other => panic!("expected upstream output, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn duplicate_names_are_refused() {
        let policy = policy(vec![]);
        let mut router = Router::new(Limiter::new([], Limits::default()), Arc::clone(&policy));
        router
            .add_upstream(None, gate(Arc::clone(&policy)), vec![tool("a")])
            .unwrap();
        assert!(matches!(
            router.add_upstream(None, gate(Arc::clone(&policy)), vec![tool("a")]),
            Err(RouterError::Conflict(name)) if name == "a"
        ));
    }

    #[tokio::test]
    async fn conflicting_upstream_adds_nothing() {
        let policy = policy(vec![]);
        let mut router = Router::new(Limiter::new([], Limits::default()), Arc::clone(&policy));
        router
            .add_upstream(Some("x_"), gate(Arc::clone(&policy)), vec![tool("a")])
            .unwrap();
        // "x_a" already exists, so the second upstream's "b" must not be added either.
        let err = router.add_upstream(
            Some("x_"),
            gate(Arc::clone(&policy)),
            vec![tool("b"), tool("a")],
        );
        assert!(matches!(err, Err(RouterError::Conflict(_))));
        let names: Vec<_> = router.list().into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["x_a"]);
    }

    #[tokio::test]
    async fn unknown_tool_is_reported() {
        let router = router(vec![], Limits::default());
        assert!(matches!(
            router.call("agent", "nope", None, CancelToken::new()).await,
            Err(RouterError::UnknownTool(_))
        ));
    }

    #[tokio::test]
    async fn policy_denial_is_surfaced_with_rule() {
        let policy = policy(vec![Rule {
            effect: Effect::Deny,
            ..allow("rm")
        }]);
        let mut router = Router::new(Limiter::new([], Limits::default()), Arc::clone(&policy));
        router
            .add_upstream(None, gate(policy), vec![tool("rm")])
            .unwrap();
        match router.call("agent", "rm", None, CancelToken::new()).await {
            Err(RouterError::Denied { rule_id, .. }) => {
                assert_eq!(rule_id.as_deref(), Some("allow-rm"));
            }
            other => panic!("expected denial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rate_limit_applies_before_upstream() {
        let policy = policy(vec![allow("t")]);
        let limiter = Limiter::new(
            [(
                "t",
                Limits {
                    requests_per_second: Some(1.0),
                    burst: Some(1),
                    max_concurrency: None,
                    max_wait: None,
                },
            )],
            Limits::default(),
        );
        let mut router = Router::new(limiter, Arc::clone(&policy));
        router
            .add_upstream(None, gate(policy), vec![tool("t")])
            .unwrap();

        router
            .call("agent", "t", None, CancelToken::new())
            .await
            .unwrap();
        assert!(matches!(
            router.call("agent", "t", None, CancelToken::new()).await,
            Err(RouterError::Limited(Rejection::ToolRate(_)))
        ));
    }

    #[tokio::test]
    async fn calls_are_refused_after_shutdown() {
        let policy = policy(vec![allow("t")]);
        let mut router = Router::new(Limiter::new([], Limits::default()), Arc::clone(&policy));
        router
            .add_upstream(None, gate(policy), vec![tool("t")])
            .unwrap();

        router.shutdown(Duration::from_millis(10)).await;
        assert!(matches!(
            router.call("agent", "t", None, CancelToken::new()).await,
            Err(RouterError::ShuttingDown(_))
        ));
    }
}

#[cfg(test)]
mod audit_tests {
    use std::sync::Arc;

    use serde_json::{Value, json};
    use tempfile::tempdir;
    use tpt_mcpbox_audit::AuditLog;
    use tpt_mcpbox_runtime::CancelToken;

    use super::tests::{allow, gate, policy, tool};
    use super::*;
    use crate::limiter::Limits;

    fn audited_router(
        path: &std::path::Path,
        rules: Vec<tpt_mcpbox_config::model::Rule>,
    ) -> Router {
        let policy = policy(rules);
        let log = Arc::new(AuditLog::open(path).unwrap());
        let mut router =
            Router::new(Limiter::new([], Limits::default()), Arc::clone(&policy)).with_audit(log);
        router
            .add_upstream(None, gate(policy), vec![tool("echo")])
            .unwrap();
        router
    }

    fn entries(path: &std::path::Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap()["data"].clone())
            .collect()
    }

    #[tokio::test]
    async fn request_timeout_reports_timed_out_and_cancels_the_tool() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let policy = policy(vec![allow("hang")]);
        let log = Arc::new(AuditLog::open(&path).unwrap());
        let mut router = Router::new(Limiter::new([], Limits::default()), Arc::clone(&policy))
            .with_audit(log)
            .with_request_timeout(Duration::from_millis(50));
        router
            .add_upstream(None, gate(policy), vec![tool("hang")])
            .unwrap();

        let cancel = CancelToken::new();
        let outcome = router.call("agent", "hang", None, cancel.clone()).await;
        assert!(matches!(
            outcome,
            Err(RouterError::TimedOut(limit)) if limit == Duration::from_millis(50)
        ));
        assert!(
            cancel.is_cancelled(),
            "a timed-out tool must be told to stop"
        );
        let finish = entries(&path).pop().expect("a finish record");
        assert_eq!(finish["phase"], "finish");
        assert_eq!(finish["outcome"], "timed_out");
    }

    #[tokio::test]
    async fn dropped_call_still_writes_a_finish_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let router = audited_router(&path, vec![allow("echo")]);

        // The start record is an fsync on a blocking thread, so the timeout must
        // be long enough for it. `pending` never finishes, so the timeout always
        // fires, and only the length of the wait changes.
        let never = std::future::pending::<Result<(), RouterError>>();
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            router.audited("tool_call", "tool", "echo", "agent", Map::new(), never),
        )
        .await;

        let records = entries(&path);
        assert_eq!(records.len(), 2, "start and finish: {records:?}");
        assert_eq!(records[1]["phase"], "finish");
        assert_eq!(records[1]["outcome"], "cancelled");
        assert_eq!(
            router.metrics().in_flight(),
            0,
            "a dropped call is no longer in flight"
        );
    }

    #[tokio::test]
    async fn successful_call_writes_start_and_finish() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let router = audited_router(&path, vec![allow("echo")]);

        router
            .call("agent-1", "echo", None, CancelToken::new())
            .await
            .unwrap();

        let records = entries(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["phase"], "start");
        assert_eq!(records[0]["caller"], "agent-1");
        assert_eq!(records[1]["phase"], "finish");
        assert_eq!(records[1]["outcome"], "ok");
    }

    #[tokio::test]
    async fn denied_call_records_outcome_and_rule() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut rule = allow("echo");
        rule.effect = tpt_mcpbox_config::model::Effect::Deny;
        let router = audited_router(&path, vec![rule]);

        assert!(
            router
                .call("agent-1", "echo", None, CancelToken::new())
                .await
                .is_err()
        );

        let records = entries(&path);
        assert_eq!(records[1]["outcome"], "denied");
        assert_eq!(records[1]["rule_id"], "allow-echo");
    }

    #[tokio::test]
    async fn unknown_tool_is_recorded_without_dispatch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let router = audited_router(&path, vec![allow("echo")]);

        assert!(
            router
                .call("agent-1", "nope", None, CancelToken::new())
                .await
                .is_err()
        );

        let records = entries(&path);
        assert_eq!(records[1]["outcome"], "unknown_tool");
    }

    #[tokio::test]
    async fn argument_values_are_never_recorded() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let router = audited_router(&path, vec![allow("echo")]);

        let mut args = Map::new();
        args.insert("api_token".to_owned(), json!("sk-live-SECRET-VALUE"));
        router
            .call("agent-1", "echo", Some(args), CancelToken::new())
            .await
            .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("sk-live-SECRET-VALUE"));
        assert_eq!(entries(&path)[0]["arg_keys"], json!(["api_token"]));
    }

    /// Prompt-injection scenario: hostile arguments that claim to be the
    /// caller or the tool must not change who the policy sees.
    #[tokio::test]
    async fn arguments_cannot_impersonate_the_caller_or_tool() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut rule = allow("echo");
        rule.caller = Some("agent-1".to_owned());
        let router = audited_router(&path, vec![rule]);

        let mut args = Map::new();
        args.insert("caller".to_owned(), json!("agent-1"));
        args.insert("tool".to_owned(), json!("echo"));
        args.insert("name".to_owned(), json!("admin__shell"));
        let result = router
            .call("agent-2", "echo", Some(args), CancelToken::new())
            .await;

        assert!(matches!(result, Err(RouterError::Denied { .. })));
        let records = entries(&path);
        assert_eq!(records[0]["caller"], "agent-2");
        assert_eq!(records[1]["outcome"], "denied");
    }
}

#[cfg(test)]
mod mcp_tests {
    use serde_json::{Value, json};
    use tpt_mcpbox_config::model::Effect;
    use tpt_mcpbox_protocol::Implementation;
    use tpt_mcpbox_protocol::jsonrpc::{Id, Request, ServerMessage};
    use tpt_mcpbox_protocol::model::ServerCapabilities;
    use tpt_mcpbox_protocol::server::Handler;
    use tpt_mcpbox_protocol::session::{Session, SessionConfig};

    use super::tests::{allow, gate, policy, tool};
    use super::*;
    use crate::limiter::Limits;
    use crate::mcp::ToolHandler;

    fn session() -> Arc<Session> {
        Arc::new(Session::new(SessionConfig::new(
            Implementation::new("test", "0"),
            ServerCapabilities::default(),
        )))
    }

    /// Sends one request through the handler and returns the JSON response.
    async fn ask(
        handler: &ToolHandler,
        session: &Arc<Session>,
        method: &str,
        params: Option<Value>,
    ) -> Value {
        let mut request = Request::new(Id::Number(1), method);
        if let Some(params) = params {
            request = request.with_params(params);
        }
        let Ok(Some(ServerMessage::Response(response))) = handler.handle(session, request).await
        else {
            panic!("expected a response to {method}");
        };
        serde_json::to_value(response).unwrap()
    }

    fn handler_with(rules: Vec<tpt_mcpbox_config::model::Rule>) -> ToolHandler {
        let policy = policy(rules);
        let mut router = Router::new(Limiter::new([], Limits::default()), Arc::clone(&policy));
        router
            .add_upstream(Some("gh__"), gate(policy), vec![tool("echo")])
            .unwrap();
        ToolHandler::new(Arc::new(router))
    }

    #[tokio::test]
    async fn tools_list_shows_namespaced_names() {
        let handler = handler_with(vec![allow("echo")]);
        let response = ask(&handler, &session(), "tools/list", None).await;
        assert_eq!(response["result"]["tools"][0]["name"], "gh__echo");
    }

    #[tokio::test]
    async fn allowed_call_returns_upstream_result() {
        let handler = handler_with(vec![allow("echo")]);
        let response = ask(
            &handler,
            &session(),
            "tools/call",
            Some(json!({ "name": "gh__echo", "arguments": {} })),
        )
        .await;
        assert_eq!(response["result"]["content"][0]["text"], "echo");
        assert!(response["error"].is_null());
    }

    #[tokio::test]
    async fn denied_call_is_a_tool_error_the_agent_can_read() {
        let mut rule = allow("echo");
        rule.effect = Effect::Deny;
        let handler = handler_with(vec![rule]);
        let response = ask(
            &handler,
            &session(),
            "tools/call",
            Some(json!({ "name": "gh__echo" })),
        )
        .await;
        assert_eq!(response["result"]["isError"], true);
        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("denied")
        );
    }

    #[tokio::test]
    async fn unknown_tool_is_a_protocol_error() {
        let handler = handler_with(vec![allow("echo")]);
        let response = ask(
            &handler,
            &session(),
            "tools/call",
            Some(json!({ "name": "nope" })),
        )
        .await;
        assert_eq!(response["error"]["code"], -32602);
    }

    #[tokio::test]
    async fn call_without_params_is_a_protocol_error() {
        let handler = handler_with(vec![allow("echo")]);
        let response = ask(&handler, &session(), "tools/call", None).await;
        assert_eq!(response["error"]["code"], -32602);
    }

    #[tokio::test]
    async fn unsupported_method_is_method_not_found() {
        let handler = handler_with(vec![allow("echo")]);
        let response = ask(&handler, &session(), "resources/subscribe", None).await;
        assert_eq!(response["error"]["code"], -32601);
    }
}

/// Metric label for an audit kind. Audit kinds and metric kinds differ only for
/// tool calls, which are audited as `tool_call` and counted as `tool`.
fn metric_kind(audit_kind: &'static str) -> &'static str {
    match audit_kind {
        "tool_call" => "tool",
        other => other,
    }
}

#[cfg(test)]
mod metrics_tests {
    use tpt_mcpbox_config::model::Effect;
    use tpt_mcpbox_runtime::CancelToken;

    use super::tests::{allow, gate, policy, tool};
    use super::*;
    use crate::limiter::Limits;

    #[tokio::test]
    async fn calls_are_counted_by_kind_and_outcome() {
        let mut denied = allow("rm");
        denied.effect = Effect::Deny;
        let policy = policy(vec![allow("echo"), denied]);
        let mut router = Router::new(Limiter::new([], Limits::default()), Arc::clone(&policy));
        router
            .add_upstream(
                None,
                gate(Arc::clone(&policy)),
                vec![tool("echo"), tool("rm")],
            )
            .unwrap();
        let metrics = router.metrics();

        router
            .call("agent", "echo", None, CancelToken::new())
            .await
            .unwrap();
        assert!(
            router
                .call("agent", "rm", None, CancelToken::new())
                .await
                .is_err()
        );
        assert!(
            router
                .call("agent", "nope", None, CancelToken::new())
                .await
                .is_err()
        );

        assert_eq!(metrics.calls("tool", "ok"), 1);
        assert_eq!(metrics.calls("tool", "denied"), 1);
        assert_eq!(metrics.calls("tool", "unknown_tool"), 1);
        let text = metrics.render();
        assert!(text.contains("tpt_mcpbox_calls_total{kind=\"tool\",outcome=\"ok\"} 1"));
        assert!(
            !text.contains("echo"),
            "tool names must not appear as labels"
        );
    }
}
