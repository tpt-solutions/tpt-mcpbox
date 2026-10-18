// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! `tpt-mcpbox run`: assemble the hub from configuration and serve it on stdio.
//!
//! Startup order matters for safety. The configuration must pass the serve-mode
//! validation, every referenced secret must resolve, and the policy must
//! compile before any tool or upstream is loaded. A failure at any step stops
//! the hub before it accepts a call.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use serde_json::{Value, json};
use tpt_mcpbox_audit::AuditLog;
use tpt_mcpbox_config::Redactor;
use tpt_mcpbox_config::model::SecretBinding;
use tpt_mcpbox_config::model::{
    Config, HttpServerConfig, MetricsConfig, ServerConfig, UpstreamConfig,
};
use tpt_mcpbox_config::secrets::{SecretStore, SecretString};
use tpt_mcpbox_config::validate::{self, Severity, ValidationMode};
use tpt_mcpbox_policy::Policy;
use tpt_mcpbox_protocol::Implementation;
use tpt_mcpbox_protocol::model::{
    PromptsCapability, ResourcesCapability, ServerCapabilities, ToolsCapability,
};
use tpt_mcpbox_protocol::server::Handler;
use tpt_mcpbox_protocol::session::SessionConfig;
use tpt_mcpbox_protocol::tools::Tool;
use tpt_mcpbox_protocol::transport::http::{HttpOptions, OriginPolicy, StreamableHttpServer};
use tpt_mcpbox_protocol::transport::stdio::{self, StdioOptions};
use tpt_mcpbox_proxy::{Client, Connection, HttpClient, PolicyGate, UpstreamOptions};
use tpt_mcpbox_router::mcp::ToolHandler;
use tpt_mcpbox_router::{Limiter, Limits, Metrics, Router};
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
    if !config.server.has_stdio() && !config.server.has_http() {
        return Err(
            "no server transport is enabled; add `stdio` or `http` under server.transports"
                .to_owned(),
        );
    }

    let report = validate::validate(config, ValidationMode::Serve);
    if !report.is_ok() {
        return Err(format!(
            "{} error(s) must be fixed before the hub can serve traffic",
            report.of_severity(Severity::Error).len()
        ));
    }

    let http_token_binding = config
        .server
        .http
        .as_ref()
        .and_then(|http| http.bearer_env.clone())
        .map(|env| SecretBinding {
            env,
            header: "Authorization".to_owned(),
            prefix: Some("Bearer".to_owned()),
        });
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
        .chain(http_token_binding.clone())
        .collect();
    let secrets = SecretStore::from_dotenv_file(bindings, &base.join(".env"))
        .map_err(|error| error.to_string())?;
    let redactor = Arc::new(Redactor::from_store(&secrets));
    let http_authorization = match &http_token_binding {
        Some(binding) => {
            let token = secrets
                .get(&binding.env)
                .ok_or_else(|| format!("secret `{}` is not set", binding.env))?;
            Some(Arc::new(SecretString::new(format!(
                "Bearer {}",
                token.expose()
            ))))
        }
        None => None,
    };

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
        http_authorization,
    })
}

/// A configured hub: the router that serves calls, the redactor that keeps
/// secret values out of every reply, and the `Authorization` value the HTTP
/// listener requires, when a bearer token is configured.
pub(crate) struct Hub {
    pub(crate) router: Arc<Router>,
    pub(crate) redactor: Arc<Redactor>,
    pub(crate) http_authorization: Option<Arc<SecretString>>,
}

/// Serves the hub on every enabled transport, then drains in-flight calls.
///
/// The stdio transport ends when stdin closes. An HTTP listener, if enabled,
/// keeps serving after that until a stop signal arrives. Both transports stop
/// on a stop signal.
///
/// # Errors
///
/// Returns a message if a transport fails.
pub(crate) async fn serve(
    hub: Hub,
    server: ServerConfig,
    metrics_config: MetricsConfig,
) -> Result<(), String> {
    let handler: Arc<dyn Handler> = Arc::new(
        ToolHandler::new(Arc::clone(&hub.router)).with_redactor(Arc::clone(&hub.redactor)),
    );

    // Bind before starting anything, so a bad address stops startup.
    let metrics_task = if metrics_config.enabled {
        let listener = bind_metrics(&metrics_config).await?;
        let metrics = hub.router.metrics();
        Some(tokio::spawn(serve_metrics(listener, metrics)))
    } else {
        None
    };

    let http_task = match server.http.as_ref().filter(|_| server.has_http()) {
        Some(http) => {
            let listener = bind_http(http, hub.http_authorization.is_some()).await?;
            let origin_policy = origin_policy(http);
            let authorization = hub.http_authorization.clone();
            let handler = Arc::clone(&handler);
            Some(tokio::spawn(async move {
                serve_http(
                    listener,
                    handler,
                    session_config(),
                    origin_policy,
                    authorization,
                )
                .await
            }))
        }
        None => None,
    };

    let stdio_result = if server.has_stdio() {
        tokio::select! {
            result = stdio::serve(Arc::clone(&handler), session_config(), StdioOptions::default()) => {
                result.map_err(|error| format!("stdio transport failed: {error}"))
            }
            () = shutdown_signal() => {
                tracing::info!("stop requested; no longer reading requests");
                Ok(())
            }
        }
    } else {
        shutdown_signal().await;
        Ok(())
    };

    let http_result = match http_task {
        Some(task) => match task.await {
            Ok(result) => result,
            Err(error) => Err(format!("http transport task failed: {error}")),
        },
        None => Ok(()),
    };

    let metrics_result = match metrics_task {
        Some(task) => match task.await {
            Ok(result) => result,
            Err(error) => Err(format!("metrics task failed: {error}")),
        },
        None => Ok(()),
    };

    let drain = hub.router.shutdown(DRAIN_TIMEOUT).await;
    tracing::info!(?drain, "shut down");
    stdio_result.and(http_result).and(metrics_result)
}

/// Binds the metrics listener. It is loopback-only with no authentication, so
/// a scraper must run on this machine.
async fn bind_metrics(metrics: &MetricsConfig) -> Result<tokio::net::TcpListener, String> {
    let addr: SocketAddr = metrics
        .bind
        .parse()
        .map_err(|error| format!("metrics bind `{}`: {error}", metrics.bind))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "metrics bind `{}` is not a loopback address; metrics are not authenticated",
            metrics.bind
        ));
    }
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|error| format!("metrics bind `{addr}`: {error}"))
}

/// Serves `GET /metrics` in the Prometheus text format until a stop signal.
async fn serve_metrics(
    listener: tokio::net::TcpListener,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let metrics = Arc::clone(&metrics);
            async move {
                (
                    [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
                    metrics.render(),
                )
            }
        }),
    );
    if let Ok(addr) = listener.local_addr() {
        tracing::info!(%addr, "serving Prometheus metrics");
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| format!("metrics transport failed: {error}"))
}

/// The identity and capabilities the hub reports in `initialize`.
fn session_config() -> SessionConfig {
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
    SessionConfig::new(Implementation::new("tpt-mcpbox", VERSION), capabilities)
}

/// Binds the HTTP listener. A non-loopback address is accepted only with a
/// bearer token configured, because anyone who can reach the port could
/// otherwise drive the hub.
async fn bind_http(
    http: &HttpServerConfig,
    authenticated: bool,
) -> Result<tokio::net::TcpListener, String> {
    let addr: SocketAddr = http
        .bind
        .parse()
        .map_err(|error| format!("http bind `{}`: {error}", http.bind))?;
    if !addr.ip().is_loopback() && !authenticated {
        return Err(format!(
            "http bind `{}` is not a loopback address; set server.http.bearer_env so clients must authenticate",
            http.bind
        ));
    }
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|error| format!("http bind `{addr}`: {error}"))
}

/// Origins accepted by the HTTP listener: loopback by default, or the explicit
/// list from the configuration.
fn origin_policy(http: &HttpServerConfig) -> OriginPolicy {
    if http.allowed_origins.is_empty() {
        OriginPolicy::LoopbackOnly
    } else {
        OriginPolicy::AllowList(http.allowed_origins.clone())
    }
}

async fn serve_http(
    listener: tokio::net::TcpListener,
    handler: Arc<dyn Handler>,
    session: SessionConfig,
    origin_policy: OriginPolicy,
    authorization: Option<Arc<SecretString>>,
) -> Result<(), String> {
    let options = HttpOptions {
        origin_policy,
        ..HttpOptions::default()
    };
    let server = StreamableHttpServer::with_options(handler, session, options);
    let mut app = server.router();
    let authenticated = authorization.is_some();
    if let Some(expected) = authorization {
        app = app.layer(middleware::from_fn_with_state(expected, require_bearer));
    }
    if let Ok(addr) = listener.local_addr() {
        tracing::info!(%addr, authenticated, "serving MCP over Streamable HTTP");
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| format!("http transport failed: {error}"))
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

/// Rejects requests whose `Authorization` header is not the configured bearer
/// value. The check is constant-time, so the response timing does not reveal
/// how much of the token matched.
async fn require_bearer(
    State(expected): State<Arc<SecretString>>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if authorized(&expected, presented) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "a valid bearer token is required",
        )
            .into_response()
    }
}

/// `true` when `presented` is exactly the expected `Authorization` value.
fn authorized(expected: &SecretString, presented: Option<&str>) -> bool {
    presented.is_some_and(|value| expected.constant_time_eq(value))
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

#[cfg(test)]
mod auth_tests {
    use super::*;

    fn expected() -> SecretString {
        SecretString::new("Bearer sk-test-token-123")
    }

    #[test]
    fn exact_authorization_value_is_accepted() {
        assert!(authorized(&expected(), Some("Bearer sk-test-token-123")));
    }

    #[test]
    fn wrong_or_missing_authorization_is_rejected() {
        assert!(!authorized(&expected(), Some("Bearer sk-test-token-124")));
        assert!(!authorized(&expected(), Some("sk-test-token-123")));
        assert!(!authorized(&expected(), Some("")));
        assert!(!authorized(&expected(), None));
    }
}
