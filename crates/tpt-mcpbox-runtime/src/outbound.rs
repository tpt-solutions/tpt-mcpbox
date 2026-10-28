// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The host side of `wasi:http/outgoing-handler`.
//!
//! Every outbound request a tool makes passes through [`HttpPolicy::prepare`]
//! before it leaves the host. That is where the domain allowlist is enforced,
//! where configured secrets are injected as headers (so they never enter the
//! guest), where hop-by-hop headers are stripped, and where time and size limits
//! are applied.

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use globset::{GlobBuilder, GlobMatcher};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, Uri, uri::Scheme};
use tpt_mcpbox_config::secrets::ResolvedHeader;
use tpt_mcpbox_policy::normalize::normalize_host;
use wasmtime_wasi_http::{
    Error as HttpError, RequestOptions, WasiBody, WasiHttpHooks, default_send_request,
};

use crate::error::ToolError;

/// Headers that describe one hop and must not be forwarded (RFC 9110 §7.6.1),
/// plus proxy credentials, which the proxy must never pass on from the guest.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Outbound request body ceiling when the tool does not set one.
pub(crate) const DEFAULT_REQUEST_BYTES: u64 = 16 * 1024 * 1024;

/// Per-tool outbound policy, built once when the tool is loaded.
#[derive(Debug)]
pub(crate) struct HttpPolicy {
    tool: String,
    hosts: Vec<GlobMatcher>,
    injected: Vec<Injected>,
    time_limit: Duration,
    max_request_bytes: u64,
}

/// Per-call check run on each outbound request's normalised host, after the
/// tool's own allowlist. `Err` carries the reason the request is refused.
pub type HostCheck = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// A secret header and the hosts it may be sent to.
#[derive(Debug)]
struct Injected {
    name: HeaderName,
    value: HeaderValue,
    /// Empty means every host the tool may reach.
    hosts: Vec<GlobMatcher>,
}

/// Why an outbound request was refused. Returned to the guest as a
/// `wasi:http` error code, and logged with the tool name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The URI is not HTTPS, names a non-default port, or names a host that is
    /// not on the allowlist.
    Denied(String),
    /// The declared body is larger than the tool's limit.
    BodyTooLarge(u64),
}

impl HttpPolicy {
    /// Build the policy for one tool.
    ///
    /// `network` is the tool's host allowlist. `secret_headers` are the resolved
    /// secret bindings, each with the hosts it may be sent to.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::InvalidConfig`] for a host glob that does not compile,
    /// a secret host that is not on the allowlist, or a header name or value
    /// that is not valid HTTP.
    pub(crate) fn new(
        tool: &str,
        network: &[String],
        secret_headers: &[ResolvedHeader],
        time_limit: Duration,
        max_request_bytes: Option<u64>,
    ) -> Result<Self, ToolError> {
        let invalid = |message: String| ToolError::InvalidConfig {
            tool: tool.to_owned(),
            message,
        };

        let hosts = network
            .iter()
            .map(|pattern| {
                GlobBuilder::new(&pattern.to_ascii_lowercase())
                    .build()
                    .map(|glob| glob.compile_matcher())
                    .map_err(|e| invalid(format!("network host `{pattern}`: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let injected = secret_headers
            .iter()
            .map(|header| {
                let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| {
                    invalid(format!("secret header name `{}` is not valid", header.name))
                })?;
                let mut value = HeaderValue::from_str(header.value.expose()).map_err(|_| {
                    invalid(format!("secret for header `{name}` is not a valid value"))
                })?;
                // Keeps the value out of debug output and any transport logging.
                value.set_sensitive(true);
                let hosts = header
                    .hosts
                    .iter()
                    .map(|pattern| {
                        let pattern = pattern.to_ascii_lowercase();
                        // A scoped host must be one the tool may reach, or the
                        // binding could never apply.
                        if !network.iter().any(|allowed| {
                            allowed.eq_ignore_ascii_case(&pattern)
                                || glob_matches(allowed, &pattern)
                        }) {
                            return Err(invalid(format!(
                                "secret for header `{name}` names host `{pattern}`, which is not on the network allowlist"
                            )));
                        }
                        GlobBuilder::new(&pattern)
                            .build()
                            .map(|glob| glob.compile_matcher())
                            .map_err(|e| invalid(format!("secret host `{pattern}`: {e}")))
                    })
                    .collect::<Result<Vec<_>, ToolError>>()?;
                Ok(Injected { name, value, hosts })
            })
            .collect::<Result<Vec<_>, ToolError>>()?;

        Ok(Self {
            tool: tool.to_owned(),
            hosts,
            injected,
            time_limit,
            max_request_bytes: max_request_bytes.unwrap_or(DEFAULT_REQUEST_BYTES),
        })
    }

    /// Decide whether a request to `uri` may leave the host.
    pub(crate) fn admit(&self, uri: &Uri, declared_body: Option<u64>) -> Result<(), Refusal> {
        if uri.scheme() != Some(&Scheme::HTTPS) {
            return Err(Refusal::Denied(
                "only https is allowed for tool network access".to_owned(),
            ));
        }
        if uri.port_u16().is_some_and(|port| port != 443) {
            return Err(Refusal::Denied(
                "only the default https port is allowed".to_owned(),
            ));
        }
        // `Uri::host` drops userinfo, so `https://user@allowed.test/` would be
        // judged on its host alone. Credentials in the authority are refused.
        if uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err(Refusal::Denied(
                "userinfo is not allowed in tool request URLs".to_owned(),
            ));
        }
        let host = uri
            .host()
            .and_then(normalize_host)
            .ok_or_else(|| Refusal::Denied("host is not a plain DNS name".to_owned()))?;
        if !self.hosts.iter().any(|glob| glob.is_match(&host)) {
            return Err(Refusal::Denied(format!(
                "host `{host}` is not on the allowlist"
            )));
        }
        if let Some(size) = declared_body
            && size > self.max_request_bytes
        {
            return Err(Refusal::BodyTooLarge(size));
        }
        Ok(())
    }

    /// Strip hop-by-hop headers, inject secret headers, and clamp timeouts to the
    /// tool's time limit. Call only after [`HttpPolicy::admit`] has passed.
    /// `uri` is the request target, which decides which scoped secrets apply.
    pub(crate) fn prepare(
        &self,
        uri: &Uri,
        headers: &mut HeaderMap,
        options: RequestOptions,
        deadline: Option<Instant>,
    ) -> RequestOptions {
        // Headers named by `Connection` are hop-scoped too, so drop them as well.
        let named: Vec<HeaderName> = headers
            .get_all(http::header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
            .collect();
        for name in named {
            headers.remove(name);
        }
        for name in HOP_BY_HOP {
            headers.remove(*name);
        }

        // The guest cannot override an injected credential: the injected value
        // replaces whatever it sent under that name.
        let host = uri.host().and_then(normalize_host);
        for secret in &self.injected {
            let scoped_out = !secret.hosts.is_empty()
                && !host
                    .as_deref()
                    .is_some_and(|host| secret.hosts.iter().any(|glob| glob.is_match(host)));
            if !scoped_out {
                headers.insert(secret.name.clone(), secret.value.clone());
            }
        }

        // An unset timeout means "as long as the tool may run", so it is never
        // left open-ended.
        // Never longer than the tool's time limit, nor than the time left on the
        // call (SR-05).
        let cap = deadline.map_or(self.time_limit, |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .min(self.time_limit)
        });
        let clamp = |timeout: Option<Duration>| Some(timeout.unwrap_or(cap).min(cap));
        RequestOptions {
            connect_timeout: clamp(options.connect_timeout),
            first_byte_timeout: clamp(options.first_byte_timeout),
            between_bytes_timeout: clamp(options.between_bytes_timeout),
        }
    }

    /// Map a refusal onto the `wasi:http` error the guest receives.
    pub(crate) fn error(&self, refusal: &Refusal) -> HttpError {
        match refusal {
            Refusal::Denied(reason) => {
                tracing::warn!(tool = %self.tool, reason, "outbound request refused");
                HttpError::HttpRequestDenied
            }
            Refusal::BodyTooLarge(size) => {
                tracing::warn!(tool = %self.tool, size, "outbound body over limit");
                HttpError::HttpRequestBodySize(Some(*size))
            }
        }
    }
}

/// `true` when the glob `pattern` matches `candidate`, both compared in lower case.
fn glob_matches(pattern: &str, candidate: &str) -> bool {
    GlobBuilder::new(&pattern.to_ascii_lowercase())
        .build()
        .is_ok_and(|glob| {
            glob.compile_matcher()
                .is_match(candidate.to_ascii_lowercase())
        })
}

/// The `wasi:http` hooks for one tool. Every outbound request passes through
/// [`HttpPolicy`] before `default_send_request` sends it.
pub(crate) struct PolicyHooks {
    pub(crate) policy: Arc<HttpPolicy>,
    /// When the current call must end. Set by the runtime for each call, so an
    /// outbound request cannot outlive the call that made it (SR-05).
    pub(crate) deadline: Option<Instant>,
    /// Policy check for the current call, if the caller supplied one.
    pub(crate) check: Option<HostCheck>,
}

impl PolicyHooks {
    pub(crate) fn new(policy: Arc<HttpPolicy>) -> Self {
        Self {
            policy,
            deadline: None,
            check: None,
        }
    }
}

impl WasiHttpHooks for PolicyHooks {
    fn send_request(
        &mut self,
        mut request: Request<WasiBody>,
        options: Option<RequestOptions>,
        fut: Box<dyn Future<Output = Result<(), HttpError>> + Send>,
    ) -> Box<
        dyn Future<
                Output = Result<
                    (
                        Response<WasiBody>,
                        Box<dyn Future<Output = Result<(), HttpError>> + Send>,
                    ),
                    HttpError,
                >,
            > + Send,
    > {
        let policy = Arc::clone(&self.policy);
        if let Err(refusal) = policy.admit(request.uri(), declared_length(request.headers())) {
            return Box::new(async move { Err(policy.error(&refusal)) });
        }
        let uri = request.uri().clone();
        if let Some(check) = &self.check
            && let Some(host) = uri.host().and_then(normalize_host)
            && let Err(reason) = check(&host)
        {
            return Box::new(async move { Err(policy.error(&Refusal::Denied(reason))) });
        }
        let options = policy.prepare(
            &uri,
            request.headers_mut(),
            options.unwrap_or_default(),
            self.deadline,
        );
        // Dropped, as the wasmtime default implementation does.
        _ = fut;
        Box::new(async move {
            use http_body_util::BodyExt;

            let (response, io) = default_send_request(request, Some(options)).await?;
            Ok((
                response.map(BodyExt::boxed_unsync),
                Box::new(io) as Box<dyn Future<Output = _> + Send>,
            ))
        })
    }
}

/// `true` when `addr` is a host-internal or non-public destination.
///
/// An allowlisted name can still resolve to one of these, which would let a
/// tool reach services on the machine or its network (including cloud metadata
/// at `169.254.169.254`). IPv4-mapped IPv6 addresses are judged as IPv4.
#[must_use]
// Not called from the connection path yet; see todo.md (Phase 4, SSRF).
#[allow(dead_code)]
pub(crate) fn is_internal_address(addr: IpAddr) -> bool {
    match addr.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // Carrier-grade NAT, 100.64.0.0/10.
                || (a == 100 && (64..128).contains(&b))
                // "This network", 0.0.0.0/8.
                || a == 0
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique local, fc00::/7.
                || (first & 0xfe00) == 0xfc00
                // Link-local, fe80::/10.
                || (first & 0xffc0) == 0xfe80
        }
    }
}

/// Read the declared `Content-Length`, if the header is present and numeric.
pub(crate) fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use tpt_mcpbox_config::SecretString;

    use super::*;

    fn policy(hosts: &[&str]) -> HttpPolicy {
        HttpPolicy::new(
            "github",
            &hosts.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>(),
            &[],
            Duration::from_secs(5),
            None,
        )
        .expect("policy builds")
    }

    fn uri(text: &str) -> Uri {
        text.parse().expect("valid uri")
    }

    #[test]
    fn allowlisted_https_host_is_admitted() {
        let policy = policy(&["api.github.com"]);
        assert!(
            policy
                .admit(&uri("https://api.github.com/search"), None)
                .is_ok()
        );
        assert!(
            policy
                .admit(&uri("https://API.github.com./x"), None)
                .is_ok()
        );
    }

    #[test]
    fn hosts_off_the_allowlist_are_refused() {
        let policy = policy(&["api.github.com"]);
        assert!(matches!(
            policy.admit(&uri("https://evil.example/"), None),
            Err(Refusal::Denied(_))
        ));
    }

    #[test]
    fn empty_allowlist_means_no_network() {
        let policy = policy(&[]);
        assert!(policy.admit(&uri("https://api.github.com/"), None).is_err());
    }

    #[test]
    fn userinfo_tricks_resolve_to_the_real_host() {
        let policy = policy(&["api.github.com"]);
        // The connection goes to evil.example, so the allowlist must refuse it.
        assert!(
            policy
                .admit(&uri("https://api.github.com@evil.example/"), None)
                .is_err()
        );
    }

    #[test]
    fn userinfo_in_front_of_an_allowed_host_is_refused() {
        let policy = policy(&["api.github.com"]);
        assert!(matches!(
            policy.admit(&uri("https://evil@api.github.com/"), None),
            Err(Refusal::Denied(_))
        ));
    }

    #[test]
    fn plain_http_is_refused_even_for_an_allowed_host() {
        let policy = policy(&["api.github.com"]);
        assert!(matches!(
            policy.admit(&uri("http://api.github.com/"), None),
            Err(Refusal::Denied(_))
        ));
    }

    #[test]
    fn non_default_ports_are_refused() {
        let policy = policy(&["api.github.com"]);
        assert!(
            policy
                .admit(&uri("https://api.github.com:8443/"), None)
                .is_err()
        );
        assert!(
            policy
                .admit(&uri("https://api.github.com:443/"), None)
                .is_ok()
        );
    }

    #[test]
    fn declared_body_over_the_limit_is_refused() {
        let policy = HttpPolicy::new(
            "t",
            &["api.github.com".to_owned()],
            &[],
            Duration::from_secs(5),
            Some(10),
        )
        .expect("builds");
        assert_eq!(
            policy.admit(&uri("https://api.github.com/"), Some(11)),
            Err(Refusal::BodyTooLarge(11))
        );
        assert!(
            policy
                .admit(&uri("https://api.github.com/"), Some(10))
                .is_ok()
        );
    }

    #[test]
    fn hop_by_hop_and_connection_named_headers_are_stripped() {
        let policy = policy(&["api.github.com"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "connection",
            HeaderValue::from_static("x-internal, keep-alive"),
        );
        headers.insert("x-internal", HeaderValue::from_static("secret-route"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("accept", HeaderValue::from_static("application/json"));

        policy.prepare(
            &uri("https://api.github.com/"),
            &mut headers,
            default_config(),
            None,
        );

        assert!(headers.get("x-internal").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("transfer-encoding").is_none());
        assert!(headers.get("connection").is_none());
        assert_eq!(headers.get("accept").unwrap(), "application/json");
    }

    fn secret(hosts: &[&str]) -> ResolvedHeader {
        ResolvedHeader {
            name: "Authorization".to_owned(),
            value: SecretString::new("Bearer real-token"),
            hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
        }
    }

    fn policy_with(network: &[&str], secrets: &[ResolvedHeader]) -> Result<HttpPolicy, ToolError> {
        HttpPolicy::new(
            "github",
            &network.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>(),
            secrets,
            Duration::from_secs(5),
            None,
        )
    }

    #[test]
    fn scoped_secret_is_sent_only_to_its_hosts() {
        let policy = policy_with(
            &["api.github.com", "*.example.test"],
            &[secret(&["api.github.com"])],
        )
        .expect("builds");

        let mut to_github = HeaderMap::new();
        policy.prepare(
            &uri("https://api.github.com/"),
            &mut to_github,
            default_config(),
            None,
        );
        assert_eq!(to_github.get("authorization").unwrap(), "Bearer real-token");

        // Allowed by the network list, but not a host the secret is scoped to.
        let mut to_other = HeaderMap::new();
        policy.prepare(
            &uri("https://hook.example.test/"),
            &mut to_other,
            default_config(),
            None,
        );
        assert!(to_other.get("authorization").is_none());
    }

    #[test]
    fn unscoped_secret_keeps_the_old_every_host_behaviour() {
        let policy = policy_with(&["*.example.test"], &[secret(&[])]).expect("builds");
        let mut headers = HeaderMap::new();
        policy.prepare(
            &uri("https://hook.example.test/"),
            &mut headers,
            default_config(),
            None,
        );
        assert_eq!(headers.get("authorization").unwrap(), "Bearer real-token");
    }

    #[test]
    fn a_secret_scoped_to_a_host_off_the_allowlist_is_refused() {
        let err = policy_with(&["api.github.com"], &[secret(&["evil.test"])]).unwrap_err();
        assert!(matches!(err, ToolError::InvalidConfig { .. }));
    }

    #[test]
    fn injected_secret_replaces_a_guest_supplied_value() {
        let policy = policy_with(&["api.github.com"], &[secret(&[])]).expect("builds");

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer guest-guess"),
        );
        policy.prepare(
            &uri("https://api.github.com/"),
            &mut headers,
            default_config(),
            None,
        );

        let value = headers.get("authorization").expect("present");
        assert_eq!(value, "Bearer real-token");
        assert!(value.is_sensitive());
    }

    #[test]
    fn timeouts_are_clamped_to_the_tool_time_limit() {
        let policy = policy(&["api.github.com"]);
        let requested = RequestOptions {
            first_byte_timeout: Some(Duration::from_secs(600)),
            ..default_config()
        };
        let options = policy.prepare(
            &uri("https://api.github.com/"),
            &mut HeaderMap::new(),
            requested,
            None,
        );
        assert_eq!(options.first_byte_timeout, Some(Duration::from_secs(5)));
        assert_eq!(options.connect_timeout, Some(Duration::from_secs(1)));
    }

    #[test]
    fn timeouts_are_clamped_to_the_time_left_on_the_call() {
        let policy = policy(&["api.github.com"]);
        let deadline = Instant::now() + Duration::from_secs(2);
        let options = policy.prepare(
            &uri("https://api.github.com/"),
            &mut HeaderMap::new(),
            RequestOptions::default(),
            Some(deadline),
        );
        // The tool allows 5 s, but only about 2 s of the call remain.
        let connect = options.connect_timeout.expect("set");
        assert!(connect <= Duration::from_secs(2), "{connect:?}");
        assert!(connect > Duration::from_millis(1500), "{connect:?}");
    }

    #[test]
    fn unset_timeouts_default_to_the_tool_time_limit() {
        let policy = policy(&["api.github.com"]);
        let options = policy.prepare(
            &uri("https://api.github.com/"),
            &mut HeaderMap::new(),
            RequestOptions::default(),
            None,
        );
        assert_eq!(options.connect_timeout, Some(Duration::from_secs(5)));
        assert_eq!(options.first_byte_timeout, Some(Duration::from_secs(5)));
        assert_eq!(options.between_bytes_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn content_length_is_read_when_numeric() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("42"));
        assert_eq!(declared_length(&headers), Some(42));
        headers.insert("content-length", HeaderValue::from_static("many"));
        assert_eq!(declared_length(&headers), None);
    }

    #[test]
    fn internal_addresses_are_classified() {
        for text in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:10.0.0.5",
        ] {
            let addr: IpAddr = text.parse().unwrap();
            assert!(is_internal_address(addr), "{text} should be internal");
        }
    }

    #[test]
    fn public_addresses_are_not_classified_as_internal() {
        for text in ["140.82.112.3", "1.1.1.1", "100.128.0.1", "2606:4700::1111"] {
            let addr: IpAddr = text.parse().unwrap();
            assert!(!is_internal_address(addr), "{text} should be public");
        }
    }

    fn default_config() -> RequestOptions {
        RequestOptions {
            connect_timeout: Some(Duration::from_secs(1)),
            first_byte_timeout: Some(Duration::from_secs(30)),
            between_bytes_timeout: Some(Duration::from_secs(30)),
        }
    }
}
