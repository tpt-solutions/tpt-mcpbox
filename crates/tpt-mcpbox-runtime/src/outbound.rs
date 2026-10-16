// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The host side of `wasi:http/outgoing-handler`.
//!
//! Every outbound request a tool makes passes through [`HttpPolicy::prepare`]
//! before it leaves the host. That is where the domain allowlist is enforced,
//! where configured secrets are injected as headers (so they never enter the
//! guest), where hop-by-hop headers are stripped, and where time and size limits
//! are applied.

use std::collections::BTreeMap;
use std::time::Duration;

use globset::{GlobBuilder, GlobMatcher};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Uri, uri::Scheme};
use tpt_mcpbox_policy::normalize::normalize_host;
use wasmtime_wasi_http::bindings::http::types::ErrorCode;
use wasmtime_wasi_http::types::OutgoingRequestConfig;

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
    injected: Vec<(HeaderName, HeaderValue)>,
    time_limit: Duration,
    max_request_bytes: u64,
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
    /// header values from its secret bindings.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::InvalidConfig`] for a host glob that does not compile,
    /// or a header name or value that is not valid HTTP.
    pub(crate) fn new(
        tool: &str,
        network: &[String],
        secret_headers: &BTreeMap<String, String>,
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
            .map(|(name, value)| {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| invalid(format!("secret header name `{name}` is not valid")))?;
                let mut value = HeaderValue::from_str(value).map_err(|_| {
                    invalid(format!("secret for header `{name}` is not a valid value"))
                })?;
                // Keeps the value out of debug output and any transport logging.
                value.set_sensitive(true);
                Ok((name, value))
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
        let host = uri
            .host()
            .and_then(normalize_host)
            .ok_or_else(|| Refusal::Denied("host is not a plain DNS name".to_owned()))?;
        if !self.hosts.iter().any(|glob| glob.is_match(&host)) {
            return Err(Refusal::Denied(format!(
                "host `{host}` is not on the allowlist"
            )));
        }
        if let Some(size) = declared_body {
            if size > self.max_request_bytes {
                return Err(Refusal::BodyTooLarge(size));
            }
        }
        Ok(())
    }

    /// Strip hop-by-hop headers, inject secret headers, and clamp timeouts to the
    /// tool's time limit. Call only after [`HttpPolicy::admit`] has passed.
    pub(crate) fn prepare(&self, headers: &mut HeaderMap, config: &mut OutgoingRequestConfig) {
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
        for (name, value) in &self.injected {
            headers.insert(name.clone(), value.clone());
        }

        config.connect_timeout = config.connect_timeout.min(self.time_limit);
        config.first_byte_timeout = config.first_byte_timeout.min(self.time_limit);
        config.between_bytes_timeout = config.between_bytes_timeout.min(self.time_limit);
    }

    /// Map a refusal onto the `wasi:http` error the guest receives.
    pub(crate) fn error_code(&self, refusal: &Refusal) -> ErrorCode {
        match refusal {
            Refusal::Denied(reason) => {
                tracing::warn!(tool = %self.tool, reason, "outbound request refused");
                ErrorCode::HttpRequestDenied
            }
            Refusal::BodyTooLarge(size) => {
                tracing::warn!(tool = %self.tool, size, "outbound body over limit");
                ErrorCode::HttpRequestBodySize(Some(*size))
            }
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
    use super::*;

    fn policy(hosts: &[&str]) -> HttpPolicy {
        HttpPolicy::new(
            "github",
            &hosts.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>(),
            &BTreeMap::new(),
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
            &BTreeMap::new(),
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

        let mut config = default_config();
        policy.prepare(&mut headers, &mut config);

        assert!(headers.get("x-internal").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("transfer-encoding").is_none());
        assert!(headers.get("connection").is_none());
        assert_eq!(headers.get("accept").unwrap(), "application/json");
    }

    #[test]
    fn injected_secret_replaces_a_guest_supplied_value() {
        let mut secrets = BTreeMap::new();
        secrets.insert("Authorization".to_owned(), "Bearer real-token".to_owned());
        let policy = HttpPolicy::new(
            "github",
            &["api.github.com".to_owned()],
            &secrets,
            Duration::from_secs(5),
            None,
        )
        .expect("builds");

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer guest-guess"),
        );
        let mut config = default_config();
        policy.prepare(&mut headers, &mut config);

        let value = headers.get("authorization").expect("present");
        assert_eq!(value, "Bearer real-token");
        assert!(value.is_sensitive());
    }

    #[test]
    fn timeouts_are_clamped_to_the_tool_time_limit() {
        let policy = policy(&["api.github.com"]);
        let mut config = default_config();
        config.first_byte_timeout = Duration::from_secs(600);
        policy.prepare(&mut HeaderMap::new(), &mut config);
        assert_eq!(config.first_byte_timeout, Duration::from_secs(5));
        assert_eq!(config.connect_timeout, Duration::from_secs(1));
    }

    #[test]
    fn content_length_is_read_when_numeric() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("42"));
        assert_eq!(declared_length(&headers), Some(42));
        headers.insert("content-length", HeaderValue::from_static("many"));
        assert_eq!(declared_length(&headers), None);
    }

    fn default_config() -> OutgoingRequestConfig {
        OutgoingRequestConfig {
            use_tls: true,
            connect_timeout: Duration::from_secs(1),
            first_byte_timeout: Duration::from_secs(30),
            between_bytes_timeout: Duration::from_secs(30),
        }
    }
}
