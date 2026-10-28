// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Policy enforcement in front of an upstream client.
//!
//! [`PolicyGate`] evaluates every `tools/call` against the compiled policy
//! before anything is sent upstream. A denied call never reaches the wire. In
//! dry-run mode the engine's allow/deny is still returned to the caller here,
//! so the gate follows the same rule as the engine: the call proceeds only when
//! the decision is `allow`.

use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::{Map, Value};
use tpt_mcpbox_policy::{Decision, Policy, PolicyInput};
use tpt_mcpbox_protocol::completion::{CompleteRequest, CompleteResult, Reference};
use tpt_mcpbox_protocol::prompts::GetPromptResult;
use tpt_mcpbox_protocol::resources::ReadResourceResult;
use tpt_mcpbox_protocol::tools::CallToolResult;

use crate::connection::Connection;
use crate::upstream::UpstreamError;

/// Why a proxied call did not complete.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// The policy refused the call. Nothing was sent upstream.
    #[error("denied by policy{}: {reason}", rule_suffix(.rule_id))]
    Denied {
        /// Rule that decided the call, when one did.
        rule_id: Option<String>,
        /// Human-readable reason, safe to show to the agent.
        reason: String,
    },
    /// The call was allowed but the upstream failed.
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
}

fn rule_suffix(rule_id: &Option<String>) -> String {
    rule_id
        .as_deref()
        .map_or_else(String::new, |id| format!(" (rule `{id}`)"))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // The slot only ever holds a finished `Arc`, so a poisoned lock is still
    // safe to read.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An upstream client that consults the policy before every call.
#[derive(Debug)]
pub struct PolicyGate {
    upstream: String,
    client: Mutex<Arc<Connection>>,
    policy: Arc<Policy>,
}

impl PolicyGate {
    /// Wraps a stdio or HTTP client. `upstream` is the configured upstream
    /// name, used only for diagnostics.
    #[must_use]
    pub fn new(
        upstream: impl Into<String>,
        client: impl Into<Connection>,
        policy: Arc<Policy>,
    ) -> Self {
        Self {
            upstream: upstream.into(),
            client: Mutex::new(Arc::new(client.into())),
            policy,
        }
    }

    /// The connection calls are forwarded on right now. Calls already in
    /// flight keep the connection they started on, even after [`replace`].
    ///
    /// [`replace`]: PolicyGate::replace
    #[must_use]
    pub fn connection(&self) -> Arc<Connection> {
        Arc::clone(&lock(&self.client))
    }

    /// Swaps in a new connection, for example after the upstream process was
    /// restarted. The old one is dropped once its last in-flight call ends.
    pub fn replace(&self, client: impl Into<Connection>) {
        *lock(&self.client) = Arc::new(client.into());
    }

    /// Requests the current connection is waiting on.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.connection().in_flight()
    }

    /// Pings the current connection. Not policy-checked: it is a liveness probe
    /// the supervisor sends, not an agent call.
    ///
    /// # Errors
    ///
    /// See [`crate::ops::ping`].
    pub async fn ping(&self) -> Result<(), UpstreamError> {
        self.connection().ping().await
    }

    /// `true` when the current connection has lost its peer and needs replacing.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.connection().is_closed()
    }

    /// Name of the upstream this gate fronts.
    #[must_use]
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// Evaluates the policy for `tools/call` without forwarding anything.
    ///
    /// `caller` is the agent or session identity the policy matches on.
    #[must_use]
    pub fn check_tool_call(
        &self,
        caller: &str,
        tool: &str,
        arguments: Option<&Map<String, Value>>,
    ) -> Decision {
        let input = PolicyInput {
            method: "tools/call".to_owned(),
            caller: Some(caller.to_owned()),
            tool: Some(tool.to_owned()),
            arguments: arguments.map_or(Value::Null, |a| Value::Object(a.clone())),
            ..PolicyInput::default()
        };
        self.policy.evaluate(&input)
    }

    /// Checks the policy and, if it allows the call, forwards it upstream.
    pub async fn call_tool(
        &self,
        caller: &str,
        tool: &str,
        arguments: Option<Map<String, Value>>,
    ) -> Result<CallToolResult, ProxyError> {
        let decision = self.check_tool_call(caller, tool, arguments.as_ref());
        if !decision.is_allowed() {
            tracing::info!(
                upstream = %self.upstream,
                tool,
                caller,
                rule = ?decision.rule_id,
                "tool call denied by policy"
            );
            return Err(ProxyError::Denied {
                rule_id: decision.rule_id,
                reason: decision.reason,
            });
        }
        Ok(self.connection().call_tool(tool, arguments).await?)
    }

    /// Checks the policy for a `resources/read` and, if it allows it, reads the
    /// resource upstream. The URI is in the policy input, so URI rules apply.
    pub async fn read_resource(
        &self,
        caller: &str,
        uri: &str,
    ) -> Result<ReadResourceResult, ProxyError> {
        let input = PolicyInput {
            method: "resources/read".to_owned(),
            caller: Some(caller.to_owned()),
            uris: vec![uri.to_owned()],
            ..PolicyInput::default()
        };
        self.authorize(&input, "resource read", uri)?;
        Ok(self.connection().read_resource(uri).await?)
    }

    /// Checks the policy for a `prompts/get` and, if it allows it, renders the
    /// prompt upstream. Rules can match the prompt's arguments and the method.
    pub async fn get_prompt(
        &self,
        caller: &str,
        name: &str,
        arguments: Option<Map<String, Value>>,
    ) -> Result<GetPromptResult, ProxyError> {
        let input = PolicyInput {
            method: "prompts/get".to_owned(),
            caller: Some(caller.to_owned()),
            arguments: arguments
                .as_ref()
                .map_or(Value::Null, |a| Value::Object(a.clone())),
            ..PolicyInput::default()
        };
        self.authorize(&input, "prompt", name)?;
        Ok(self.connection().get_prompt(name, arguments).await?)
    }

    /// Checks the policy for a `completion/complete` and, if it allows it, asks
    /// upstream. The reference must already name the upstream's own prompt, as
    /// the router rewrites it. A resource reference is a URI, so URI rules apply.
    pub async fn complete(
        &self,
        caller: &str,
        request: &CompleteRequest,
    ) -> Result<CompleteResult, ProxyError> {
        let (kind, subject, uris) = match &request.r#ref {
            Reference::Prompt { name, .. } => ("prompt", name.clone(), Vec::new()),
            Reference::Resource { uri } => ("resource", uri.clone(), vec![uri.clone()]),
        };
        let input = PolicyInput {
            method: "completion/complete".to_owned(),
            caller: Some(caller.to_owned()),
            uris,
            ..PolicyInput::default()
        };
        self.authorize(&input, kind, &subject)?;
        Ok(self.connection().complete(request).await?)
    }

    fn authorize(&self, input: &PolicyInput, kind: &str, subject: &str) -> Result<(), ProxyError> {
        let decision = self.policy.evaluate(input);
        if decision.is_allowed() {
            return Ok(());
        }
        tracing::info!(
            upstream = %self.upstream,
            kind,
            subject,
            rule = ?decision.rule_id,
            "request denied by policy"
        );
        Err(ProxyError::Denied {
            rule_id: decision.rule_id,
            reason: decision.reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_error_names_the_rule() {
        let err = ProxyError::Denied {
            rule_id: Some("deny-secrets".to_owned()),
            reason: "tool not allowed".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "denied by policy (rule `deny-secrets`): tool not allowed"
        );
    }

    #[test]
    fn denied_error_without_rule_omits_it() {
        let err = ProxyError::Denied {
            rule_id: None,
            reason: "default deny".to_owned(),
        };
        assert_eq!(err.to_string(), "denied by policy: default deny");
    }
}

#[cfg(test)]
mod gate_tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};
    use tpt_mcpbox_config::model::{Effect, PolicyConfig, Rule};

    use super::*;
    use crate::upstream::{Client, UpstreamOptions};

    fn rule(id: &str, effect: Effect, tool: &str) -> Rule {
        Rule {
            id: id.to_owned(),
            description: None,
            effect,
            tool: Some(tool.to_owned()),
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

    /// Returns a client and a counter of `tools/call` requests that reached
    /// the fake upstream.
    fn upstream() -> (Client, Arc<AtomicUsize>) {
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

        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let (sread, mut swrite) = tokio::io::split(server_side);
        tokio::spawn(async move {
            let mut lines = BufReader::new(sread).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let msg: serde_json::Value = serde_json::from_str(&line).unwrap();
                if msg["method"] == "tools/call" {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let reply = json!({
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "result": { "content": [{ "type": "text", "text": "ok" }] }
                    });
                    swrite
                        .write_all(format!("{reply}\n").as_bytes())
                        .await
                        .unwrap();
                }
            }
        });
        (client, calls)
    }

    #[tokio::test]
    async fn allowed_call_is_forwarded() {
        let (client, calls) = upstream();
        let gate = PolicyGate::new(
            "fake",
            client,
            policy(vec![rule("allow-echo", Effect::Allow, "echo")]),
        );
        let result = gate.call_tool("agent", "echo", None).await.unwrap();
        assert_eq!(result.content.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn denied_call_never_reaches_upstream() {
        let (client, calls) = upstream();
        let gate = PolicyGate::new(
            "fake",
            client,
            policy(vec![rule("deny-rm", Effect::Deny, "rm")]),
        );
        match gate.call_tool("agent", "rm", None).await {
            Err(ProxyError::Denied { rule_id, .. }) => {
                assert_eq!(rule_id.as_deref(), Some("deny-rm"));
            }
            other => panic!("expected denial, got {other:?}"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn default_deny_blocks_unlisted_tool() {
        let (client, calls) = upstream();
        let gate = PolicyGate::new(
            "fake",
            client,
            policy(vec![rule("allow-echo", Effect::Allow, "echo")]),
        );
        assert!(matches!(
            gate.call_tool("agent", "other", None).await,
            Err(ProxyError::Denied { .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(test)]
mod feature_gate_tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};
    use tpt_mcpbox_config::model::{Effect, PolicyConfig, Rule};

    use super::*;
    use crate::upstream::{Client, UpstreamOptions};

    fn policy(rules: Vec<Rule>) -> Arc<Policy> {
        let config = PolicyConfig {
            rules,
            ..PolicyConfig::default()
        };
        Arc::new(Policy::from_config(&config).expect("policy compiles"))
    }

    /// Fake upstream answering `resources/read` and `prompts/get`. Returns the
    /// number of each that reached it.
    fn upstream() -> (Client, Arc<AtomicUsize>, Arc<AtomicUsize>) {
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

        let reads = Arc::new(AtomicUsize::new(0));
        let prompts = Arc::new(AtomicUsize::new(0));
        let (read_count, prompt_count) = (Arc::clone(&reads), Arc::clone(&prompts));
        let (sread, mut swrite) = tokio::io::split(server_side);
        tokio::spawn(async move {
            let mut lines = BufReader::new(sread).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let msg: serde_json::Value = serde_json::from_str(&line).unwrap();
                let result = match msg["method"].as_str() {
                    Some("resources/read") => {
                        read_count.fetch_add(1, Ordering::SeqCst);
                        json!({ "contents": [{ "uri": msg["params"]["uri"], "text": "data" }] })
                    }
                    Some("prompts/get") => {
                        prompt_count.fetch_add(1, Ordering::SeqCst);
                        json!({ "messages": [] })
                    }
                    _ => continue,
                };
                let reply = json!({ "jsonrpc": "2.0", "id": msg["id"], "result": result });
                swrite
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        (client, reads, prompts)
    }

    fn uri_rule(glob: &str) -> Rule {
        Rule {
            id: "allow-ok-files".to_owned(),
            description: None,
            effect: Effect::Allow,
            tool: None,
            method: Some("resources/read".to_owned()),
            args: BTreeMap::new(),
            hosts: Vec::new(),
            paths: Vec::new(),
            caller: None,
            uris: vec![glob.to_owned()],
            constraints: None,
        }
    }

    #[tokio::test]
    async fn allowed_resource_uri_is_read() {
        let (client, reads, _) = upstream();
        let gate = PolicyGate::new("fake", client, policy(vec![uri_rule("file:///ok/*")]));
        let result = gate
            .read_resource("agent", "file:///ok/a.txt")
            .await
            .unwrap();
        assert_eq!(result.contents.len(), 1);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resource_uri_outside_the_rule_never_reaches_upstream() {
        let (client, reads, _) = upstream();
        let gate = PolicyGate::new("fake", client, policy(vec![uri_rule("file:///ok/*")]));
        assert!(matches!(
            gate.read_resource("agent", "file:///etc/passwd").await,
            Err(ProxyError::Denied { .. })
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn prompt_get_is_denied_by_a_method_rule() {
        let (client, _, prompts) = upstream();
        let deny = Rule {
            id: "no-prompts".to_owned(),
            effect: Effect::Deny,
            method: Some("prompts/get".to_owned()),
            uris: Vec::new(),
            ..uri_rule("*")
        };
        let gate = PolicyGate::new("fake", client, policy(vec![deny]));
        assert!(matches!(
            gate.get_prompt("agent", "summarise", None).await,
            Err(ProxyError::Denied { rule_id: Some(ref id), .. }) if id == "no-prompts"
        ));
        assert_eq!(prompts.load(Ordering::SeqCst), 0);
    }
}
