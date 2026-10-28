// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Resources and prompts, aggregated alongside tools.
//!
//! Resources are keyed by URI, and a URI that two upstreams both serve is
//! refused rather than overridden. A read that matches no exact URI is tried
//! against the upstreams' resource templates, in registration order. Prompts are namespaced the same way as
//! tools (`<prefix><name>`) and are refused on collision.
//!
//! Each call runs inside the same audit bracket as a tool call, and passes the
//! shutdown gate and the client limits. The per-tool limits are keyed by tool
//! name, so they do not apply here. Listings are fixed when the upstream is
//! registered, so `list_changed` is not forwarded yet.

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::{Map, Value, json};
use tpt_mcpbox_protocol::completion::{CompleteRequest, CompleteResult, Reference};
use tpt_mcpbox_protocol::prompts::{GetPromptResult, Prompt};
use tpt_mcpbox_protocol::resources::{ReadResourceResult, Resource, ResourceTemplate};
use tpt_mcpbox_proxy::PolicyGate;

use crate::dispatch::{Exposure, PromptRoute, Router, RouterError};
use crate::templates::{Pattern, TemplateRoute};

/// Client-limit key for resource reads. No per-tool limits are keyed on it.
const RESOURCE_READ_KEY: &str = "resources/read";
/// Client-limit key for prompt gets.
const PROMPT_GET_KEY: &str = "prompts/get";
/// Client-limit key for completions.
const COMPLETE_KEY: &str = "completion/complete";

impl Router {
    /// Registers an upstream's resources under their URIs.
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::Conflict`] naming the first URI that is already
    /// served, or repeated within `resources`. Nothing is added in that case.
    pub fn add_upstream_resources(
        &mut self,
        gate: Arc<PolicyGate>,
        resources: Vec<Resource>,
    ) -> Result<(), RouterError> {
        if let Some(clash) = resources
            .iter()
            .find(|resource| self.resources.contains_key(&resource.uri))
        {
            return Err(RouterError::Conflict(clash.uri.clone()));
        }
        let mut seen = HashSet::new();
        if let Some(dup) = resources
            .iter()
            .find(|resource| !seen.insert(resource.uri.as_str()))
        {
            return Err(RouterError::Conflict(dup.uri.clone()));
        }

        for resource in resources {
            self.resources
                .insert(resource.uri.clone(), Arc::clone(&gate));
            self.resource_list.insert(resource.uri.clone(), resource);
        }
        Ok(())
    }

    /// Registers an upstream's resource templates. A template whose pattern
    /// cannot be parsed is left out with a warning, since routing it would be a
    /// guess. Nothing is added if a template repeats one already registered.
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::Conflict`] naming the first repeated `uriTemplate`.
    pub fn add_upstream_resource_templates(
        &mut self,
        gate: Arc<PolicyGate>,
        templates: Vec<ResourceTemplate>,
    ) -> Result<(), RouterError> {
        let mut seen: HashSet<&str> = self
            .resource_templates
            .iter()
            .map(|route| route.template.uri_template.as_str())
            .collect();
        if let Some(dup) = templates
            .iter()
            .find(|template| !seen.insert(template.uri_template.as_str()))
        {
            return Err(RouterError::Conflict(dup.uri_template.clone()));
        }

        for template in templates {
            match Pattern::parse(&template.uri_template) {
                Some(pattern) => self.resource_templates.push(TemplateRoute {
                    template,
                    pattern,
                    gate: Arc::clone(&gate),
                }),
                None => tracing::warn!(
                    template = %template.uri_template,
                    "resource template uses an unsupported form; not served"
                ),
            }
        }
        Ok(())
    }

    /// Registers an upstream's prompts under `<prefix><name>`.
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::Conflict`] on a name collision. Nothing is added
    /// in that case.
    pub fn add_upstream_prompts(
        &mut self,
        prefix: Option<&str>,
        gate: Arc<PolicyGate>,
        prompts: Vec<Prompt>,
    ) -> Result<(), RouterError> {
        self.add_upstream_prompts_exposed(prefix, gate, prompts, &Exposure::default())
    }

    /// Like [`Router::add_upstream_prompts`], with the upstream's renames and
    /// description overrides applied.
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::Conflict`] on a name collision, after renames.
    pub fn add_upstream_prompts_exposed(
        &mut self,
        prefix: Option<&str>,
        gate: Arc<PolicyGate>,
        prompts: Vec<Prompt>,
        exposure: &Exposure,
    ) -> Result<(), RouterError> {
        let prefix = prefix.unwrap_or("");
        let exposed: Vec<String> = prompts
            .iter()
            .map(|prompt| format!("{prefix}{}", exposure.rename_of(&prompt.name)))
            .collect();

        if let Some(clash) = exposed.iter().find(|name| self.prompts.contains_key(*name)) {
            return Err(RouterError::Conflict(clash.clone()));
        }
        let mut seen = HashSet::new();
        if let Some(dup) = exposed.iter().find(|name| !seen.insert(name.as_str())) {
            return Err(RouterError::Conflict(dup.clone()));
        }

        for (name, prompt) in exposed.into_iter().zip(prompts) {
            let upstream_name = prompt.name.clone();
            let description = exposure
                .describe
                .get(&upstream_name)
                .cloned()
                .or(prompt.description.clone());
            self.prompts.insert(
                name.clone(),
                PromptRoute {
                    gate: Arc::clone(&gate),
                    upstream_name,
                },
            );
            self.prompt_list.insert(
                name.clone(),
                Prompt {
                    name,
                    description,
                    ..prompt
                },
            );
        }
        Ok(())
    }

    /// Whether any resource or resource template is served, so the server may
    /// advertise `resources`.
    #[must_use]
    pub fn serves_resources(&self) -> bool {
        !self.resources.is_empty() || !self.resource_templates.is_empty()
    }

    /// Whether any prompt is served, so the server may advertise `prompts`.
    #[must_use]
    pub fn serves_prompts(&self) -> bool {
        !self.prompts.is_empty()
    }

    /// Whether any completable reference (a prompt or a resource template) is
    /// served. Completion also needs an upstream that supports it.
    #[must_use]
    pub fn serves_completion_targets(&self) -> bool {
        !self.prompts.is_empty() || !self.resource_templates.is_empty()
    }

    /// Every resource, in URI order.
    #[must_use]
    pub fn list_resources(&self) -> Vec<Resource> {
        self.resource_list.values().cloned().collect()
    }

    /// Every resource template, in registration order.
    #[must_use]
    pub fn list_resource_templates(&self) -> Vec<ResourceTemplate> {
        self.resource_templates
            .iter()
            .map(|route| route.template.clone())
            .collect()
    }

    /// Every prompt under its exposed name, in name order.
    #[must_use]
    pub fn list_prompts(&self) -> Vec<Prompt> {
        self.prompt_list.values().cloned().collect()
    }

    /// Reads a resource through the upstream that serves it.
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::UnknownResource`] when no upstream serves `uri`,
    /// and [`RouterError::Denied`] when the policy refuses the read.
    pub async fn read_resource(
        &self,
        caller: &str,
        uri: &str,
    ) -> Result<ReadResourceResult, RouterError> {
        self.audited(
            "resource_read",
            "resource",
            uri,
            caller,
            Map::new(),
            self.serve_resource(caller, uri),
        )
        .await
    }

    async fn serve_resource(
        &self,
        caller: &str,
        uri: &str,
    ) -> Result<ReadResourceResult, RouterError> {
        // An exact URI wins; otherwise the first template that expands to it.
        let gate = match self.resources.get(uri) {
            Some(gate) => gate,
            None => self
                .resource_templates
                .iter()
                .find(|route| route.pattern.matches(uri))
                .map(|route| &route.gate)
                .ok_or_else(|| RouterError::UnknownResource(uri.to_owned()))?,
        };
        let _in_flight = self.lifecycle.begin()?;
        let _permit = self.limiter.acquire(RESOURCE_READ_KEY, caller)?;
        gate.read_resource(caller, uri)
            .await
            .map_err(RouterError::from)
    }

    /// Renders a prompt through the upstream that provides it.
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::UnknownPrompt`] for an unknown name, and
    /// [`RouterError::Denied`] when the policy refuses the request.
    pub async fn get_prompt(
        &self,
        caller: &str,
        name: &str,
        arguments: Option<Map<String, Value>>,
    ) -> Result<GetPromptResult, RouterError> {
        let mut keys: Vec<&str> = arguments
            .as_ref()
            .map_or_else(Vec::new, |a| a.keys().map(String::as_str).collect());
        keys.sort_unstable();
        let mut extra = Map::new();
        extra.insert("arg_keys".to_owned(), json!(keys));

        self.audited(
            "prompt_get",
            "prompt",
            name,
            caller,
            extra,
            self.serve_prompt(caller, name, arguments),
        )
        .await
    }

    /// Completes a prompt argument or a resource template variable through the
    /// upstream that owns it. The reference is rewritten to that upstream's own
    /// name first, since an exposed prompt name may carry a prefix.
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::UnknownPrompt`] or [`RouterError::UnknownResource`]
    /// when nothing owns the reference, and [`RouterError::Denied`] when the
    /// policy refuses it.
    pub async fn complete(
        &self,
        caller: &str,
        request: CompleteRequest,
    ) -> Result<CompleteResult, RouterError> {
        let subject = match &request.r#ref {
            Reference::Prompt { name, .. } => name.clone(),
            Reference::Resource { uri } => uri.clone(),
        };
        self.audited(
            "completion",
            "ref",
            &subject,
            caller,
            Map::new(),
            self.serve_complete(caller, request),
        )
        .await
    }

    async fn serve_complete(
        &self,
        caller: &str,
        request: CompleteRequest,
    ) -> Result<CompleteResult, RouterError> {
        match &request.r#ref {
            Reference::Prompt { name, argument } => {
                let route = self
                    .prompts
                    .get(name)
                    .ok_or_else(|| RouterError::UnknownPrompt(name.clone()))?;
                let _in_flight = self.lifecycle.begin()?;
                let _permit = self.limiter.acquire(COMPLETE_KEY, caller)?;
                let forwarded = CompleteRequest {
                    r#ref: Reference::Prompt {
                        name: route.upstream_name.clone(),
                        argument: argument.clone(),
                    },
                    ..request
                };
                route
                    .gate
                    .complete(caller, &forwarded)
                    .await
                    .map_err(RouterError::from)
            }
            Reference::Resource { uri } => {
                let route = self
                    .resource_templates
                    .iter()
                    .find(|route| route.template.uri_template == *uri)
                    .ok_or_else(|| RouterError::UnknownResource(uri.clone()))?;
                let _in_flight = self.lifecycle.begin()?;
                let _permit = self.limiter.acquire(COMPLETE_KEY, caller)?;
                route
                    .gate
                    .complete(caller, &request)
                    .await
                    .map_err(RouterError::from)
            }
        }
    }

    async fn serve_prompt(
        &self,
        caller: &str,
        name: &str,
        arguments: Option<Map<String, Value>>,
    ) -> Result<GetPromptResult, RouterError> {
        let route = self
            .prompts
            .get(name)
            .ok_or_else(|| RouterError::UnknownPrompt(name.to_owned()))?;
        let _in_flight = self.lifecycle.begin()?;
        let _permit = self.limiter.acquire(PROMPT_GET_KEY, caller)?;
        route
            .gate
            .get_prompt(caller, &route.upstream_name, arguments)
            .await
            .map_err(RouterError::from)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};
    use tpt_mcpbox_config::model::{Effect, PolicyConfig, Rule};
    use tpt_mcpbox_policy::Policy;
    use tpt_mcpbox_protocol::completion::Argument;
    use tpt_mcpbox_proxy::{Client, UpstreamOptions};

    use super::*;
    use crate::Limiter;
    use crate::limiter::Limits;

    fn method_rule(id: &str, method: &str, effect: Effect) -> Rule {
        Rule {
            id: id.to_owned(),
            description: None,
            effect,
            tool: None,
            method: Some(method.to_owned()),
            args: std::collections::BTreeMap::new(),
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

    /// Fake upstream with one resource and one prompt named `summarise`.
    /// Returns the gate and a count of prompt requests that reached it.
    fn gate(policy: Arc<Policy>) -> (PolicyGate, Arc<AtomicUsize>) {
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

        let prompt_requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&prompt_requests);
        let (sread, mut swrite) = tokio::io::split(server_side);
        tokio::spawn(async move {
            let mut lines = BufReader::new(sread).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let msg: Value = serde_json::from_str(&line).unwrap();
                let result = match msg["method"].as_str() {
                    Some("resources/list") => {
                        json!({ "resources": [{ "uri": "file:///notes/a.txt", "name": "a" }] })
                    }
                    Some("resources/read") => json!({
                        "contents": [{ "uri": msg["params"]["uri"], "text": "hello" }]
                    }),
                    Some("prompts/list") => {
                        json!({ "prompts": [{ "name": "summarise", "arguments": [] }] })
                    }
                    Some("prompts/get") => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        json!({ "messages": [] })
                    }
                    Some("completion/complete") => {
                        let name = msg["params"]["ref"]["name"].as_str().unwrap_or_default();
                        let value = msg["params"]["argument"]["value"]
                            .as_str()
                            .unwrap_or_default();
                        json!({ "completion": { "values": [format!("{name}:{value}")] } })
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
        (PolicyGate::new("fake", client, policy), prompt_requests)
    }

    fn resource(uri: &str) -> Resource {
        Resource {
            uri: uri.to_owned(),
            name: "x".to_owned(),
            title: None,
            description: None,
            mime_type: None,
            annotations: None,
        }
    }

    fn prompt(name: &str) -> Prompt {
        Prompt {
            name: name.to_owned(),
            title: None,
            description: None,
            arguments: Vec::new(),
        }
    }

    fn router(policy: Arc<Policy>) -> Router {
        Router::new(Limiter::new([], Limits::default()), policy)
    }

    #[tokio::test]
    async fn listed_resource_is_read_through_its_upstream() {
        let policy = policy(vec![method_rule(
            "allow-read",
            "resources/read",
            Effect::Allow,
        )]);
        let (gate, _) = gate(Arc::clone(&policy));
        let mut router = router(policy);
        router
            .add_upstream_resources(Arc::new(gate), vec![resource("file:///notes/a.txt")])
            .unwrap();

        assert_eq!(router.list_resources().len(), 1);
        let result = router
            .read_resource("agent", "file:///notes/a.txt")
            .await
            .unwrap();
        assert_eq!(result.contents.len(), 1);
    }

    fn template(uri_template: &str) -> ResourceTemplate {
        serde_json::from_value(json!({ "uriTemplate": uri_template, "name": "t" }))
            .expect("template parses")
    }

    #[tokio::test]
    async fn expanded_template_uri_is_read_through_its_upstream() {
        let policy = policy(vec![method_rule(
            "allow-read",
            "resources/read",
            Effect::Allow,
        )]);
        let (gate, _) = gate(Arc::clone(&policy));
        let mut router = router(policy);
        router
            .add_upstream_resource_templates(Arc::new(gate), vec![template("logs://{app}/{date}")])
            .unwrap();

        assert_eq!(router.list_resource_templates().len(), 1);
        let result = router
            .read_resource("agent", "logs://web/2026-10-28")
            .await
            .unwrap();
        assert_eq!(result.contents.len(), 1);
        // A URI that does not expand the template is still unknown.
        assert!(matches!(
            router.read_resource("agent", "logs://web/a/b").await,
            Err(RouterError::UnknownResource(_))
        ));
    }

    #[tokio::test]
    async fn repeated_template_is_refused() {
        let policy = policy(Vec::new());
        let (first, _) = gate(Arc::clone(&policy));
        let (second, _) = gate(Arc::clone(&policy));
        let mut router = router(policy);
        router
            .add_upstream_resource_templates(Arc::new(first), vec![template("logs://{app}")])
            .unwrap();
        assert!(matches!(
            router.add_upstream_resource_templates(Arc::new(second), vec![template("logs://{app}")]),
            Err(RouterError::Conflict(ref name)) if name == "logs://{app}"
        ));
        assert_eq!(
            router.list_resource_templates().len(),
            1,
            "nothing added on conflict"
        );
    }

    #[tokio::test]
    async fn prompt_completion_is_routed_with_the_upstream_name() {
        let policy = policy(vec![method_rule(
            "allow-complete",
            "completion/complete",
            Effect::Allow,
        )]);
        let (gate, _) = gate(Arc::clone(&policy));
        let mut router = router(policy);
        router
            .add_upstream_prompts(Some("kb__"), Arc::new(gate), vec![prompt("summarise")])
            .unwrap();

        let request = CompleteRequest {
            r#ref: Reference::Prompt {
                name: "kb__summarise".to_owned(),
                argument: Some("topic".to_owned()),
            },
            argument: Argument {
                name: "topic".to_owned(),
                value: "ab".to_owned(),
            },
            context: None,
        };
        let result = router.complete("agent", request).await.unwrap();
        // The upstream saw its own name, not the prefixed one.
        assert_eq!(result.completion.values, ["summarise:ab"]);
    }

    #[tokio::test]
    async fn completion_for_an_unknown_prompt_is_refused() {
        let router = router(policy(Vec::new()));
        let request = CompleteRequest {
            r#ref: Reference::Prompt {
                name: "nope".to_owned(),
                argument: None,
            },
            argument: Argument {
                name: "x".to_owned(),
                value: String::new(),
            },
            context: None,
        };
        assert!(matches!(
            router.complete("agent", request).await,
            Err(RouterError::UnknownPrompt(_))
        ));
    }

    #[tokio::test]
    async fn unknown_resource_is_reported() {
        let policy = policy(Vec::new());
        let router = router(policy);
        assert!(matches!(
            router.read_resource("agent", "file:///nope").await,
            Err(RouterError::UnknownResource(_))
        ));
    }

    #[tokio::test]
    async fn the_same_resource_uri_from_two_upstreams_is_refused() {
        let policy = policy(Vec::new());
        let (first, _) = gate(Arc::clone(&policy));
        let (second, _) = gate(Arc::clone(&policy));
        let mut router = router(policy);
        router
            .add_upstream_resources(Arc::new(first), vec![resource("file:///a")])
            .unwrap();
        assert!(matches!(
            router.add_upstream_resources(Arc::new(second), vec![resource("file:///a")]),
            Err(RouterError::Conflict(uri)) if uri == "file:///a"
        ));
    }

    #[tokio::test]
    async fn prompts_are_namespaced_and_rendered_under_their_upstream_name() {
        let policy = policy(vec![method_rule("allow-get", "prompts/get", Effect::Allow)]);
        let (gate, count) = gate(Arc::clone(&policy));
        let mut router = router(policy);
        router
            .add_upstream_prompts(Some("kb__"), Arc::new(gate), vec![prompt("summarise")])
            .unwrap();

        let names: Vec<_> = router.list_prompts().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["kb__summarise"]);

        router
            .get_prompt("agent", "kb__summarise", None)
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn denied_prompt_never_reaches_upstream() {
        let policy = policy(vec![method_rule("no-prompts", "prompts/get", Effect::Deny)]);
        let (gate, count) = gate(Arc::clone(&policy));
        let mut router = router(policy);
        router
            .add_upstream_prompts(None, Arc::new(gate), vec![prompt("summarise")])
            .unwrap();

        assert!(matches!(
            router.get_prompt("agent", "summarise", None).await,
            Err(RouterError::Denied { rule_id: Some(ref id), .. }) if id == "no-prompts"
        ));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unknown_prompt_is_reported() {
        let router = router(policy(Vec::new()));
        assert!(matches!(
            router.get_prompt("agent", "nope", None).await,
            Err(RouterError::UnknownPrompt(_))
        ));
    }

    #[tokio::test]
    async fn resource_reads_are_audited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let policy = policy(vec![method_rule(
            "allow-read",
            "resources/read",
            Effect::Allow,
        )]);
        let (gate, _) = gate(Arc::clone(&policy));
        let mut router =
            router(policy).with_audit(Arc::new(tpt_mcpbox_audit::AuditLog::open(&path).unwrap()));
        router
            .add_upstream_resources(Arc::new(gate), vec![resource("file:///notes/a.txt")])
            .unwrap();

        router
            .read_resource("agent", "file:///notes/a.txt")
            .await
            .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let kinds: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect();
        assert_eq!(kinds.len(), 2);
        assert_eq!(kinds[0]["kind"], "resource_read");
        assert_eq!(kinds[1]["data"]["outcome"], "ok");
    }
}
