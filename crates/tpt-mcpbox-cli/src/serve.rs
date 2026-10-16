// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! `tpt-mcpbox run`: assemble the hub from configuration and serve it on stdio.
//!
//! Startup order matters for safety. The configuration must pass the serve-mode
//! validation, every referenced secret must resolve, and the policy must
//! compile before any tool or upstream is loaded. A failure at any step stops
//! the hub before it accepts a call.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use serde_json::{Value, json};
use tpt_mcpbox_audit::AuditLog;
use tpt_mcpbox_config::Redactor;
use tpt_mcpbox_config::model::{Config, UpstreamConfig};
use tpt_mcpbox_config::secrets::SecretStore;
use tpt_mcpbox_config::validate::{self, Severity, ValidationMode};
use tpt_mcpbox_policy::Policy;
use tpt_mcpbox_protocol::Implementation;
use tpt_mcpbox_protocol::model::{
    PromptsCapability, ResourcesCapability, ServerCapabilities, ToolsCapability,
};
use tpt_mcpbox_protocol::server::Handler;
use tpt_mcpbox_protocol::session::SessionConfig;
use tpt_mcpbox_protocol::tools::Tool;
use tpt_mcpbox_protocol::transport::stdio::{self, StdioOptions};
use tpt_mcpbox_proxy::{Client, Connection, HttpClient, PolicyGate, UpstreamOptions};
use tpt_mcpbox_router::mcp::ToolHandler;
use tpt_mcpbox_router::{Limiter, Limits, Router};
use tpt_mcpbox_runtime::Runtime;

use crate::VERSION;

/// How long shutdown waits for in-flight calls before giving up.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds the router from the configuration: Wasm tools, upstreams, policy and
/// audit. Relative paths in the configuration are resolved against `base`, the
/// directory of the configuration file.
///
/// # Errors
///
/// Returns a message naming the first thing that prevented startup.
pub(crate) async fn build_router(config: &Config, base: &Path) -> Result<Hub, String> {
    if !config.server.has_stdio() {
        return Err(
            "no supported server transport is enabled; add `stdio` under server.transports"
                .to_owned(),
        );
    }
    if config.server.has_http() {
        tracing::warn!("the HTTP server transport is not implemented yet; serving stdio only");
    }

    let report = validate::validate(config, ValidationMode::Serve);
    if !report.is_ok() {
        return Err(format!(
            "{} error(s) must be fixed before the hub can serve traffic",
            report.of_severity(Severity::Error).len()
        ));
    }

    let bindings: Vec<_> = config
        .tools
        .iter()
        .filter(|t| t.enabled)
        .flat_map(|t| t.secrets.clone())
        .chain(
            config
                .upstreams
                .iter()
                .filter(|u| u.enabled)
                .flat_map(|u| u.secrets.clone()),
        )
        .collect();
    let secrets = SecretStore::from_dotenv_file(bindings, &base.join(".env"))
        .map_err(|error| error.to_string())?;
    let redactor = Arc::new(Redactor::from_store(&secrets));

    let policy =
        Arc::new(Policy::from_config(&config.policy).map_err(|error| format!("policy: {error}"))?);

    let audit = if config.audit.enabled {
        let path = base.join(&config.audit.path);
        Some(Arc::new(
            AuditLog::open(&path).map_err(|error| format!("audit log: {error}"))?,
        ))
    } else {
        None
    };

    let tool_limits: Vec<(&str, Limits)> = config
        .tools
        .iter()
        .filter(|t| t.enabled)
        .map(|t| (t.name.as_str(), Limits::from(&t.rate_limit)))
        .collect();
    let mut router = Router::new(
        Limiter::new(tool_limits, Limits::default()),
        Arc::clone(&policy),
    );
    let startup_audit = audit.clone();
    record_secret_bindings(startup_audit.as_deref(), config)?;
    if let Some(audit) = audit {
        router = router.with_audit(audit);
    }

    let runtime = Runtime::new().map_err(|error| error.to_string())?;
    for tool in config.tools.iter().filter(|t| t.enabled) {
        let loaded = Arc::new(
            runtime
                .load_tool(tool, &secrets, base)
                .map_err(|error| format!("tool `{}`: {error}", tool.name))?,
        );
        let descriptors = parse_descriptors(loaded.descriptors())
            .map_err(|e| format!("tool `{}`: {e}", tool.name))?;
        record(
            startup_audit.as_deref(),
            "tool_loaded",
            json!({ "tool": tool.name, "digest": loaded.digest(), "tools": descriptors.len() }),
        )?;
        for descriptor in descriptors {
            router
                .add_wasm(Arc::clone(&loaded), descriptor)
                .map_err(|error| error.to_string())?;
        }
    }

    for upstream in config.upstreams.iter().filter(|u| u.enabled) {
        let connection = connect(upstream, &secrets, &redactor)?;
        let fail = |error: tpt_mcpbox_proxy::UpstreamError| {
            format!("upstream `{}`: {error}", upstream.name)
        };

        let handshake = connection.initialize().await.map_err(fail)?;
        let listed = connection.list_tools().await.map_err(fail)?;
        // Only ask for what the upstream says it has, so a server without
        // resources is not sent a request it would answer with an error.
        let resources = if handshake.capabilities.resources.is_some() {
            connection.list_resources().await.map_err(fail)?
        } else {
            Vec::new()
        };
        let prompts = if handshake.capabilities.prompts.is_some() {
            connection.list_prompts().await.map_err(fail)?
        } else {
            Vec::new()
        };

        let visible = Visibility::new(upstream)?;
        let tools: Vec<Tool> = listed
            .into_iter()
            .filter(|tool| visible.allows(&tool.name))
            .collect();
        let gate = Arc::new(PolicyGate::new(
            upstream.name.clone(),
            connection,
            Arc::clone(&policy),
        ));
        let prefix = upstream.prefix.as_deref();
        record(
            startup_audit.as_deref(),
            "upstream_connected",
            json!({
                "upstream": upstream.name,
                "transport": if upstream.transport.stdio.is_some() { "stdio" } else { "http" },
                "tools": tools.len(),
                "resources": resources.len(),
                "prompts": prompts.len(),
            }),
        )?;
        router
            .add_upstream(prefix, Arc::clone(&gate), tools)
            .map_err(|error| format!("upstream `{}`: {error}", upstream.name))?;
        router
            .add_upstream_resources(Arc::clone(&gate), resources)
            .map_err(|error| format!("upstream `{}`: {error}", upstream.name))?;
        router
            .add_upstream_prompts(prefix, gate, prompts)
            .map_err(|error| format!("upstream `{}`: {error}", upstream.name))?;
    }

    Ok(Hub {
        router: Arc::new(router),
        redactor,
    })
}

/// A configured hub: the router that serves calls, and the redactor that keeps
/// secret values out of every reply.
pub(crate) struct Hub {
    pub(crate) router: Arc<Router>,
    pub(crate) redactor: Arc<Redactor>,
}

/// Serves the hub on stdin/stdout until the agent disconnects or the process is
/// asked to stop, then drains in-flight calls.
///
/// # Errors
///
/// Returns a message if the stdio transport fails.
pub(crate) async fn serve_stdio(hub: Hub) -> Result<(), String> {
    let capabilities = ServerCapabilities {
        tools: Some(ToolsCapability {
            list_changed: Some(false),
        }),
        resources: Some(ResourcesCapability {
            subscribe: Some(false),
            list_changed: Some(false),
        }),
        prompts: Some(PromptsCapability {
            list_changed: Some(false),
        }),
        ..ServerCapabilities::default()
    };
    let session = SessionConfig::new(Implementation::new("tpt-mcpbox", VERSION), capabilities);
    let handler: Arc<dyn Handler> = Arc::new(
        ToolHandler::new(Arc::clone(&hub.router)).with_redactor(Arc::clone(&hub.redactor)),
    );

    let served = tokio::select! {
        result = stdio::serve(handler, session, StdioOptions::default()) => result,
        () = shutdown_signal() => {
            tracing::info!("stop requested; no longer reading requests");
            Ok(())
        }
    };
    let drain = hub.router.shutdown(DRAIN_TIMEOUT).await;
    tracing::info!(?drain, "shut down");
    served.map_err(|error| format!("stdio transport failed: {error}"))
}

/// Writes one startup record. Startup stops if the record cannot be written:
/// the same rule that refuses a call whose start record fails.
fn record(log: Option<&AuditLog>, kind: &str, data: Value) -> Result<(), String> {
    match log {
        Some(log) => log
            .append(kind, data)
            .map(|_| ())
            .map_err(|error| format!("audit log: {error}")),
        None => Ok(()),
    }
}

/// Records which secret names are bound to which tool or upstream. Only names
/// are written, never values.
fn record_secret_bindings(log: Option<&AuditLog>, config: &Config) -> Result<(), String> {
    for tool in config.tools.iter().filter(|t| t.enabled) {
        for binding in &tool.secrets {
            record(
                log,
                "secret_bound",
                json!({ "name": binding.env, "scope": "tool", "owner": tool.name }),
            )?;
        }
    }
    for upstream in config.upstreams.iter().filter(|u| u.enabled) {
        for binding in &upstream.secrets {
            record(
                log,
                "secret_bound",
                json!({ "name": binding.env, "scope": "upstream", "owner": upstream.name }),
            )?;
        }
    }
    Ok(())
}

/// Resolves on Ctrl-C, or on SIGTERM where the platform has it.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = ctrl_c.await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

fn connect(
    upstream: &UpstreamConfig,
    secrets: &SecretStore,
    redactor: &Arc<Redactor>,
) -> Result<Connection, String> {
    let options = UpstreamOptions::default();
    if let Some(stdio) = &upstream.transport.stdio {
        let client = Client::spawn(stdio, options, Arc::clone(redactor))
            .map_err(|error| format!("upstream `{}`: {error}", upstream.name))?;
        return Ok(client.into());
    }
    if let Some(http) = &upstream.transport.http {
        let mut headers = http.headers.clone();
        headers.extend(
            secrets
                .headers_for(&upstream.secrets)
                .map_err(|error| format!("upstream `{}`: {error}", upstream.name))?,
        );
        let client = HttpClient::new(&http.url, &headers, options)
            .map_err(|error| format!("upstream `{}`: {error}", upstream.name))?;
        return Ok(client.into());
    }
    Err(format!("upstream `{}` has no transport", upstream.name))
}

/// Allow and deny globs for one upstream's tools. An empty allow list means
/// every tool, subject to the deny list.
struct Visibility {
    allow: Option<GlobSet>,
    deny: Option<GlobSet>,
}

impl Visibility {
    fn new(upstream: &UpstreamConfig) -> Result<Self, String> {
        Ok(Self {
            allow: globs(&upstream.allow, &upstream.name)?,
            deny: globs(&upstream.deny, &upstream.name)?,
        })
    }

    fn allows(&self, tool: &str) -> bool {
        self.allow.as_ref().is_none_or(|set| set.is_match(tool))
            && !self.deny.as_ref().is_some_and(|set| set.is_match(tool))
    }
}

fn globs(patterns: &[String], upstream: &str) -> Result<Option<GlobSet>, String> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern)
            .map_err(|error| format!("upstream `{upstream}`: glob `{pattern}`: {error}"))?;
        builder.add(glob);
    }
    builder
        .build()
        .map(Some)
        .map_err(|error| format!("upstream `{upstream}`: {error}"))
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    name: String,
    #[serde(default)]
    description: Option<String>,
    input_schema: Value,
}

/// Reads the descriptor array a Wasm component reports at load time.
fn parse_descriptors(json: &str) -> Result<Vec<Tool>, String> {
    let items: Vec<Descriptor> =
        serde_json::from_str(json).map_err(|error| format!("invalid tool descriptors: {error}"))?;
    Ok(items
        .into_iter()
        .map(|d| Tool {
            name: d.name,
            title: None,
            description: d.description,
            input_schema: d.input_schema,
            output_schema: None,
            annotations: None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_parse_into_tools() {
        let tools = parse_descriptors(
            r#"[{"name":"echo","description":"returns its arguments","input_schema":{"type":"object"}}]"#,
        )
        .unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(
            tools[0].description.as_deref(),
            Some("returns its arguments")
        );
    }

    #[test]
    fn malformed_descriptors_are_rejected() {
        assert!(parse_descriptors("not json").is_err());
    }

    #[test]
    fn empty_allow_list_exposes_everything_except_denied() {
        let visible = Visibility {
            allow: None,
            deny: globs(&["rm*".to_owned()], "t").unwrap(),
        };
        assert!(visible.allows("search"));
        assert!(!visible.allows("rm_all"));
    }

    #[test]
    fn allow_list_restricts_to_matching_names() {
        let visible = Visibility {
            allow: globs(&["search*".to_owned()], "t").unwrap(),
            deny: None,
        };
        assert!(visible.allows("search_code"));
        assert!(!visible.allows("delete_repo"));
    }
}
