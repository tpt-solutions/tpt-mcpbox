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
use tpt_mcpbox_protocol::prompts::Prompt;
use tpt_mcpbox_protocol::resources::Resource;
use tpt_mcpbox_protocol::server::Handler;
use tpt_mcpbox_protocol::session::SessionConfig;
use tpt_mcpbox_protocol::tools::Tool;
use tpt_mcpbox_protocol::transport::http::{HttpOptions, OriginPolicy, StreamableHttpServer};
use tpt_mcpbox_protocol::transport::stdio::{self, StdioOptions};
use tpt_mcpbox_proxy::supervise::{Respawn, RestartPolicy, supervise};
use tpt_mcpbox_proxy::{
    Client, Connection, HttpClient, PolicyGate, ResponseScanner, UpstreamOptions,
};
use tpt_mcpbox_router::mcp::ToolHandler;
use tpt_mcpbox_router::{Exposure, Limiter, Limits, Metrics, Router};
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
    if let Some(limit) = config.server.request_timeout {
        router = router.with_request_timeout(limit);
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

    let mut upstream_completions = false;
    for upstream in config.upstreams.iter().filter(|u| u.enabled) {
        let connection = connect(upstream, &secrets, &redactor)?;
        let fail = |error: tpt_mcpbox_proxy::UpstreamError| {
            format!("upstream `{}`: {error}", upstream.name)
        };

        let handshake = connection.initialize().await.map_err(fail)?;
        upstream_completions |= handshake.capabilities.completions.is_some();
        let listed = connection.list_tools().await.map_err(fail)?;
        // Only ask for what the upstream says it has, so a server without
        // resources is not sent a request it would answer with an error.
        let (resources, templates) = if handshake.capabilities.resources.is_some() {
            (
                connection.list_resources().await.map_err(fail)?,
                connection.list_resource_templates().await.map_err(fail)?,
            )
        } else {
            (Vec::new(), Vec::new())
        };
        let prompts = if handshake.capabilities.prompts.is_some() {
            connection.list_prompts().await.map_err(fail)?
        } else {
            Vec::new()
        };

        let tools = visible_tools(upstream, listed)?;
        let prompts = visible_prompts(upstream, prompts)?;
        let resources = visible_resources(upstream, resources)?;
        // A template can reach URIs the resource filter refuses, so templates
        // are hidden whenever that filter is set.
        let templates = if upstream.resources.is_empty() {
            templates
        } else {
            Vec::new()
        };
        let mut tool_names: Vec<String> = tools.iter().map(|tool| tool.name.clone()).collect();
        tool_names.sort();
        let scanner = ResponseScanner::new(&upstream.scan)
            .map_err(|error| format!("upstream `{}`: scan rule: {error}", upstream.name))?;
        let gate = Arc::new(
            PolicyGate::new(upstream.name.clone(), connection, Arc::clone(&policy))
                .with_scanner(scanner),
        );
        if upstream.transport.stdio.is_some() {
            // Only supervised upstreams have an up/down state to report.
            let metrics = router.metrics();
            let name = upstream.name.clone();
            metrics.set_upstream_up(&name, true);
            supervise(
                Arc::clone(&gate),
                respawn(
                    upstream.clone(),
                    secrets.clone(),
                    Arc::clone(&redactor),
                    tool_names,
                    startup_audit.clone(),
                ),
                RestartPolicy::default(),
                Arc::new(move |up| metrics.set_upstream_up(&name, up)),
            );
        }
        let prefix = upstream.prefix.as_deref();
        record(
            startup_audit.as_deref(),
            "upstream_connected",
            json!({
                "upstream": upstream.name,
                "transport": if upstream.transport.stdio.is_some() { "stdio" } else { "http" },
                "tools": tools.len(),
                "resources": resources.len(),
                "resource_templates": templates.len(),
                "prompts": prompts.len(),
            }),
        )?;
        let tool_exposure = Exposure {
            rename: upstream.tools.rename.clone(),
            describe: upstream.tools.describe.clone(),
        };
        let prompt_exposure = Exposure {
            rename: upstream.prompts.rename.clone(),
            describe: upstream.prompts.describe.clone(),
        };
        router
            .add_upstream_exposed(prefix, Arc::clone(&gate), tools, &tool_exposure)
            .map_err(|error| format!("upstream `{}`: {error}", upstream.name))?;
        router
            .add_upstream_resources(Arc::clone(&gate), resources)
            .map_err(|error| format!("upstream `{}`: {error}", upstream.name))?;
        router
            .add_upstream_resource_templates(Arc::clone(&gate), templates)
            .map_err(|error| format!("upstream `{}`: {error}", upstream.name))?;
        router
            .add_upstream_prompts_exposed(prefix, gate, prompts, &prompt_exposure)
            .map_err(|error| format!("upstream `{}`: {error}", upstream.name))?;
    }

    Ok(Hub {
        router: Arc::new(router),
        redactor,
        http_authorization,
        upstream_completions,
    })
}

/// A configured hub: the router that serves calls, the redactor that keeps
/// secret values out of every reply, and the `Authorization` value the HTTP
/// listener requires, when a bearer token is configured.
pub(crate) struct Hub {
    pub(crate) router: Arc<Router>,
    pub(crate) redactor: Arc<Redactor>,
    pub(crate) http_authorization: Option<Arc<SecretString>>,
    /// Whether any upstream declared `completions` in its handshake.
    pub(crate) upstream_completions: bool,
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
            let session = session_config(&hub);
            Some(tokio::spawn(async move {
                serve_http(listener, handler, session, origin_policy, authorization).await
            }))
        }
        None => None,
    };

    let stdio_result = if server.has_stdio() {
        tokio::select! {
            result = stdio::serve(Arc::clone(&handler), session_config(&hub), StdioOptions::default()) => {
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

/// The identity and capabilities the hub reports in `initialize`. An optional
/// capability is advertised only when the hub can serve it, so an agent never
/// calls a method that would fail for lack of anything behind it.
fn session_config(hub: &Hub) -> SessionConfig {
    let router = &hub.router;
    let capabilities = ServerCapabilities {
        tools: Some(ToolsCapability {
            list_changed: Some(false),
        }),
        resources: router.serves_resources().then_some(ResourcesCapability {
            subscribe: Some(false),
            list_changed: Some(false),
        }),
        prompts: router.serves_prompts().then_some(PromptsCapability {
            list_changed: Some(false),
        }),
        completions: (hub.upstream_completions && router.serves_completion_targets())
            .then(|| json!({})),
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

/// Builds the restart function for one stdio upstream. A replacement must
/// complete the handshake and list the same tools the router registered at
/// startup, because the router's catalog cannot change while serving.
fn respawn(
    upstream: UpstreamConfig,
    secrets: SecretStore,
    redactor: Arc<Redactor>,
    expected: Vec<String>,
    audit: Option<Arc<AuditLog>>,
) -> Respawn {
    Arc::new(move || {
        let upstream = upstream.clone();
        let secrets = secrets.clone();
        let redactor = Arc::clone(&redactor);
        let expected = expected.clone();
        let audit = audit.clone();
        Box::pin(async move {
            let connection = connect(&upstream, &secrets, &redactor)?;
            connection
                .initialize()
                .await
                .map_err(|error| error.to_string())?;
            let listed = connection
                .list_tools()
                .await
                .map_err(|error| error.to_string())?;
            let mut names: Vec<String> = visible_tools(&upstream, listed)?
                .into_iter()
                .map(|tool| tool.name)
                .collect();
            names.sort();
            if names != expected {
                return Err(format!(
                    "tool list changed: {} tool(s) now, {} at startup",
                    names.len(),
                    expected.len()
                ));
            }
            record(
                audit.as_deref(),
                "upstream_restarted",
                json!({ "upstream": upstream.name }),
            )?;
            Ok(connection)
        })
    })
}

/// Allow and deny globs over one upstream's names. An empty allow list means
/// every name, subject to the deny list.
struct Visibility {
    allow: Option<GlobSet>,
    deny: Option<GlobSet>,
}

impl Visibility {
    fn new(allow: &[String], deny: &[String], upstream: &str) -> Result<Self, String> {
        Ok(Self {
            allow: globs(allow, upstream)?,
            deny: globs(deny, upstream)?,
        })
    }

    fn allows(&self, name: &str) -> bool {
        self.allow.as_ref().is_none_or(|set| set.is_match(name))
            && !self.deny.as_ref().is_some_and(|set| set.is_match(name))
    }
}

/// The tools an upstream exposes after its `allow`/`deny` lists. Renames and
/// descriptions are checked against everything the upstream lists, so a typo
/// fails at startup instead of silently doing nothing.
fn visible_tools(upstream: &UpstreamConfig, listed: Vec<Tool>) -> Result<Vec<Tool>, String> {
    let names: Vec<&str> = listed.iter().map(|tool| tool.name.as_str()).collect();
    let overrides = upstream
        .tools
        .rename
        .keys()
        .chain(upstream.tools.describe.keys());
    check_known(&upstream.name, "tool", &names, overrides)?;

    let visible = Visibility::new(&upstream.allow, &upstream.deny, &upstream.name)?;
    Ok(listed
        .into_iter()
        .filter(|tool| visible.allows(&tool.name))
        .collect())
}

/// The prompts an upstream exposes after its `prompts` filter.
fn visible_prompts(upstream: &UpstreamConfig, listed: Vec<Prompt>) -> Result<Vec<Prompt>, String> {
    let names: Vec<&str> = listed.iter().map(|prompt| prompt.name.as_str()).collect();
    let overrides = upstream
        .prompts
        .rename
        .keys()
        .chain(upstream.prompts.describe.keys());
    check_known(&upstream.name, "prompt", &names, overrides)?;

    let filter = &upstream.prompts;
    let visible = Visibility::new(&filter.allow, &filter.deny, &upstream.name)?;
    Ok(listed
        .into_iter()
        .filter(|prompt| visible.allows(&prompt.name))
        .collect())
}

/// The resources an upstream exposes after its `resources` filter, by URI.
fn visible_resources(
    upstream: &UpstreamConfig,
    listed: Vec<Resource>,
) -> Result<Vec<Resource>, String> {
    let filter = &upstream.resources;
    let visible = Visibility::new(&filter.allow, &filter.deny, &upstream.name)?;
    Ok(listed
        .into_iter()
        .filter(|resource| visible.allows(&resource.uri))
        .collect())
}

/// Refuses an override that names something the upstream does not list.
fn check_known<'a>(
    upstream: &str,
    kind: &str,
    listed: &[&str],
    keys: impl Iterator<Item = &'a String>,
) -> Result<(), String> {
    match keys.into_iter().find(|key| !listed.contains(&key.as_str())) {
        Some(key) => Err(format!(
            "upstream `{upstream}`: override for {kind} `{key}`, which the upstream does not list"
        )),
        None => Ok(()),
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

    /// The `fake_upstream` example, built next to the test binary. A plain
    /// `cargo test -p tpt-mcpbox-cli` builds it; a name-filtered run may not.
    fn fake_upstream() -> std::path::PathBuf {
        let mut dir = std::env::current_exe().expect("test binary path");
        dir.pop(); // deps
        dir.pop(); // debug
        let path = dir
            .join("examples")
            .join(format!("fake_upstream{}", std::env::consts::EXE_SUFFIX));
        assert!(
            path.exists(),
            "build the fake first: cargo build -p tpt-mcpbox-cli --example fake_upstream"
        );
        path
    }

    /// Builds a hub whose only upstream is the fake, with an allow-all policy.
    /// Single quotes keep Windows paths free of YAML escapes.
    async fn hub_with_fake_upstream(dir: &Path, state: &Path, log: &Path) -> Hub {
        let yaml = format!(
            "policy:\n  default: deny\n  rules:\n    - id: allow-all\n      effect: allow\n      tool: '*'\n\
             upstreams:\n  - name: fake\n    transport:\n      stdio:\n        command: '{}'\n        args: ['{}', '{}']\n",
            fake_upstream().display(),
            state.display(),
            log.display(),
        );
        let config = tpt_mcpbox_config::load::load_str(&yaml, "test config").expect("config loads");
        build_router(&config, dir).await.expect("hub builds")
    }

    async fn call(router: &Router, tool: &str) -> bool {
        router
            .call("agent", tool, None, tpt_mcpbox_runtime::CancelToken::new())
            .await
            .is_ok()
    }

    fn starts(log: &Path) -> usize {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .count()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn crashed_upstream_is_restarted_and_serves_again() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = dir.path().join("state");
        let log = dir.path().join("starts.log");
        std::fs::write(&state, "same").expect("state written");
        let hub = hub_with_fake_upstream(dir.path(), &state, &log).await;
        let router = Arc::clone(&hub.router);

        assert!(call(&router, "echo").await, "the first child serves calls");
        // The child exits without replying, so the call fails.
        assert!(!call(&router, "crash").await);

        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while !call(&router, "echo").await {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("the restarted upstream serves calls again");
        assert!(starts(&log) >= 2, "a second child was started");
        // The gauge is set just after the swap, so wait for it.
        let metrics = router.metrics();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !metrics
                .render()
                .contains("tpt_mcpbox_upstream_up{upstream=\"fake\"} 1")
            {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the upstream is reported up again");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restart_that_changes_the_tool_list_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = dir.path().join("state");
        let log = dir.path().join("starts.log");
        std::fs::write(&state, "same").expect("state written");
        let hub = hub_with_fake_upstream(dir.path(), &state, &log).await;
        let router = Arc::clone(&hub.router);

        assert!(call(&router, "echo").await);
        // The next child will expose a different tool list.
        std::fs::write(&state, "changed").expect("state written");
        assert!(!call(&router, "crash").await);

        // Wait until the supervisor has retried at least twice. The log proves
        // the attempts ran, so the failing echo below means the changed
        // replacement was refused, not that no restart was tried.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while starts(&log) < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("the supervisor retried");
        assert!(
            !call(&router, "echo").await,
            "a replacement with different tools must not be swapped in"
        );
    }

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

    fn upstream(extra: serde_json::Value) -> UpstreamConfig {
        let mut value = json!({
            "name": "kb",
            "transport": { "stdio": { "command": "true" } },
        });
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).expect("upstream config parses")
    }

    fn tool_named(name: &str) -> Tool {
        serde_json::from_value(json!({ "name": name, "inputSchema": { "type": "object" } }))
            .unwrap()
    }

    fn prompt_named(name: &str) -> Prompt {
        serde_json::from_value(json!({ "name": name })).unwrap()
    }

    fn resource_at(uri: &str) -> Resource {
        serde_json::from_value(json!({ "uri": uri, "name": uri })).unwrap()
    }

    #[test]
    fn rename_of_an_unlisted_tool_is_refused() {
        let config = upstream(json!({ "tools": { "rename": { "nope": "x" } } }));
        let error = visible_tools(&config, vec![tool_named("search")]).unwrap_err();
        assert!(error.contains("`nope`"), "{error}");
    }

    #[test]
    fn tool_filter_applies_before_the_rename_check_and_hides_the_tool() {
        let config = upstream(json!({
            "deny": ["rm*"],
            "tools": { "rename": { "rm_all": "wipe" } }
        }));
        // `rm_all` is listed, so the rename is accepted, but the deny hides it.
        let visible =
            visible_tools(&config, vec![tool_named("search"), tool_named("rm_all")]).unwrap();
        let names: Vec<_> = visible.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["search"]);
    }

    #[test]
    fn prompt_filter_and_override_names_are_checked() {
        let config = upstream(json!({
            "prompts": { "allow": ["sum*"], "describe": { "summarise": "Shorter" } }
        }));
        let visible = visible_prompts(
            &config,
            vec![prompt_named("summarise"), prompt_named("draft")],
        )
        .unwrap();
        let names: Vec<_> = visible.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["summarise"]);

        let typo = upstream(json!({ "prompts": { "describe": { "sumarise": "x" } } }));
        assert!(visible_prompts(&typo, vec![prompt_named("summarise")]).is_err());
    }

    #[test]
    fn resource_filter_is_by_uri() {
        let config = upstream(json!({ "resources": { "deny": ["secret://*"] } }));
        let visible = visible_resources(
            &config,
            vec![resource_at("file:///a.txt"), resource_at("secret://key")],
        )
        .unwrap();
        let uris: Vec<_> = visible.iter().map(|r| r.uri.as_str()).collect();
        assert_eq!(uris, ["file:///a.txt"]);
    }

    #[test]
    fn an_empty_hub_advertises_only_tools() {
        let policy = Policy::from_config(&tpt_mcpbox_config::model::PolicyConfig::default())
            .expect("default policy compiles");
        let hub = Hub {
            router: Arc::new(Router::new(
                Limiter::new([], Limits::default()),
                Arc::new(policy),
            )),
            redactor: Arc::new(Redactor::new()),
            http_authorization: None,
            upstream_completions: true,
        };
        let capabilities = session_config(&hub).capabilities;
        assert!(capabilities.tools.is_some());
        assert!(capabilities.resources.is_none());
        assert!(capabilities.prompts.is_none());
        // Completion needs a prompt or template to complete for.
        assert!(capabilities.completions.is_none());
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
