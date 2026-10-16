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
use std::sync::Arc;

use serde_json::{Map, Value};
use tpt_mcpbox_policy::{Policy, PolicyInput};
use tpt_mcpbox_protocol::tools::{CallToolResult, Tool};
use tpt_mcpbox_proxy::{PolicyGate, ProxyError, UpstreamError};
use tpt_mcpbox_runtime::{CancelToken, LoadedTool, ToolError};

use crate::lifecycle::{Lifecycle, ShuttingDown};
use crate::limiter::{Limiter, Rejection};

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

enum Backend {
    Wasm {
        tool: Arc<LoadedTool>,
        tool_name: String,
    },
    Upstream {
        gate: Arc<PolicyGate>,
        tool_name: String,
    },
}

struct Route {
    backend: Backend,
    descriptor: Tool,
}

/// Merged catalog of Wasm and upstream tools, with the controls applied to
/// each call.
pub struct Router {
    routes: BTreeMap<String, Route>,
    limiter: Limiter,
    lifecycle: Lifecycle,
    policy: Arc<Policy>,
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
        }
    }

    /// Registers a Wasm tool under the name in its descriptor.
    pub fn add_wasm(&mut self, tool: Arc<LoadedTool>, descriptor: Tool) -> Result<(), RouterError> {
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
        gate: PolicyGate,
        tools: Vec<Tool>,
    ) -> Result<(), RouterError> {
        let gate = Arc::new(gate);
        let prefix = prefix.unwrap_or("");
        let names: Vec<String> = tools
            .iter()
            .map(|tool| format!("{prefix}{}", tool.name))
            .collect();

        if let Some(clash) = names.iter().find(|name| self.routes.contains_key(*name)) {
            return Err(RouterError::Conflict(clash.clone()));
        }
        let mut seen = std::collections::HashSet::new();
        if let Some(dup) = names.iter().find(|name| !seen.insert(*name)) {
            return Err(RouterError::Conflict(dup.clone()));
        }

        for (exposed, tool) in names.into_iter().zip(tools) {
            let backend = Backend::Upstream {
                gate: Arc::clone(&gate),
                tool_name: tool.name.clone(),
            };
            let descriptor = Tool {
                name: exposed.clone(),
                ..tool
            };
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

    /// Dispatches one `tools/call`.
    ///
    /// `caller` identifies the session for limits and policy. `name` is the
    /// exposed name from [`Router::list`].
    pub async fn call(
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
        let _permit = self.limiter.acquire(name, caller)?;

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

    fn tool(name: &str) -> Tool {
        Tool {
            name: name.to_owned(),
            title: None,
            description: None,
            input_schema: json!({ "type": "object" }),
            output_schema: None,
            annotations: None,
        }
    }

    fn allow(tool_name: &str) -> Rule {
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

    fn policy(rules: Vec<Rule>) -> Arc<Policy> {
        let config = PolicyConfig {
            rules,
            ..PolicyConfig::default()
        };
        Arc::new(Policy::from_config(&config).expect("policy compiles"))
    }

    /// Fake upstream that answers every `tools/call` with a text result.
    fn gate(policy: Arc<Policy>) -> PolicyGate {
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
