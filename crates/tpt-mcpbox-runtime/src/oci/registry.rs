// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! A small OCI distribution client for anonymous pulls.
//!
//! It fetches one manifest and one blob. Requests go through the same outbound
//! path as tool traffic (`crate::send`), so TLS is the same pure-Rust stack.
//! Bearer-token challenges are answered anonymously; no credentials are read
//! from the environment. Redirects are followed, but the bearer token is sent
//! only to the registry's own host. Plain `http` is accepted only for loopback
//! registries, so a token never crosses the network in the clear.

use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, LOCATION, WWW_AUTHENTICATE};
use http::{HeaderMap, Method, Request, StatusCode, Uri, uri::Scheme};
use http_body_util::{BodyExt, Empty, combinators::MapErr};
use serde::Deserialize;
use wasmtime_wasi_http::{Error as HttpError, RequestOptions};

use super::OciError;
use super::cache::sha256_hex;
use super::reference::{Reference, validate_digest};
use crate::send;

/// Largest manifest accepted.
const MAX_MANIFEST: usize = 4 * 1024 * 1024;
/// Largest token response accepted.
const MAX_TOKEN: usize = 64 * 1024;
/// Largest module accepted. Components are small; this bounds memory use.
pub(crate) const MAX_MODULE: u64 = 64 * 1024 * 1024;
/// Redirects followed for one request.
const MAX_REDIRECTS: usize = 5;

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";

/// Media types that identify a WebAssembly module layer.
const WASM_MEDIA_TYPES: &[&str] = &[
    "application/wasm",
    "application/vnd.wasm.content.layer.v1+wasm",
];

/// The one layer a module is stored in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layer {
    /// Lowercase hex SHA-256 of the module bytes.
    pub(crate) hex: String,
    /// Declared size in bytes.
    pub(crate) size: u64,
}

/// An anonymous session with one registry, for one repository.
pub(crate) struct Registry {
    /// Registry host, as written in the reference (may include a port).
    host: String,
    /// Repository path, used for the token scope.
    repository: String,
    /// Bearer token obtained from the registry's challenge, if any.
    token: Option<String>,
    /// The `Basic` authorization value for the token endpoint, if the operator
    /// configured credentials for this registry.
    basic: Option<String>,
    /// Requests and redirects are bounded by these timeouts.
    options: RequestOptions,
}

/// The status, headers and body of one exchange.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

type EmptyBody = MapErr<Empty<Bytes>, fn(Infallible) -> HttpError>;

impl Registry {
    /// A session for `reference`'s registry and repository.
    pub(crate) fn new(reference: &Reference, credentials: Option<&str>) -> Self {
        Self {
            host: reference.registry.clone(),
            repository: reference.repository.clone(),
            token: None,
            basic: credentials.map(|pair| {
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(pair)
                )
            }),
            options: RequestOptions {
                connect_timeout: Some(Duration::from_secs(15)),
                first_byte_timeout: Some(Duration::from_secs(60)),
                between_bytes_timeout: Some(Duration::from_secs(30)),
            },
        }
    }

    /// Fetches the manifest for `reference` and returns its single module layer.
    ///
    /// A digest in the reference must match the manifest's bytes. For a tag, a
    /// `Docker-Content-Digest` header, when present, must match too.
    pub(crate) async fn module_layer(&mut self, reference: &Reference) -> Result<Layer, OciError> {
        let body = self
            .manifest(reference.manifest_reference(), reference.digest.as_deref())
            .await?;
        match parse_document(&body)? {
            Document::Image(layer) => Ok(layer),
            Document::Index(entries) => {
                let entry = select_wasm(&entries)?;
                let body = self.manifest(&entry.digest, Some(&entry.digest)).await?;
                match parse_document(&body)? {
                    Document::Image(layer) => Ok(layer),
                    Document::Index(_) => Err(OciError::Manifest(
                        "an image index may not point at another index".to_owned(),
                    )),
                }
            }
        }
    }

    /// Fetches a manifest by tag or digest. Its bytes must match `digest` when one
    /// is given, and the registry's `Docker-Content-Digest`, when it sends one.
    async fn manifest(
        &mut self,
        reference: &str,
        digest: Option<&str>,
    ) -> Result<Vec<u8>, OciError> {
        let path = format!("/v2/{}/manifests/{}", self.repository, reference);
        let reply = self.get(&path, Some(MANIFEST_ACCEPT), MAX_MANIFEST).await?;
        ensure_success(&reply, &path)?;

        let actual = format!("sha256:{}", sha256_hex(&reply.body));
        if let Some(expected) = digest
            && expected != actual
        {
            return Err(OciError::Digest {
                what: "manifest",
                expected: expected.to_owned(),
                actual,
            });
        }
        if let Some(header) = reply.headers.get("docker-content-digest") {
            let header = header.to_str().unwrap_or_default();
            if header != actual {
                return Err(OciError::Digest {
                    what: "manifest",
                    expected: header.to_owned(),
                    actual,
                });
            }
        }
        Ok(reply.body)
    }

    /// Fetches the blob with `layer`'s digest, checks its size and digest, and
    /// returns the bytes.
    pub(crate) async fn blob(&mut self, layer: &Layer) -> Result<Vec<u8>, OciError> {
        let limit = usize::try_from(layer.size).unwrap_or(usize::MAX);
        let path = format!("/v2/{}/blobs/sha256:{}", self.repository, layer.hex);
        let reply = self
            .get(&path, Some("application/octet-stream"), limit)
            .await?;
        ensure_success(&reply, &path)?;
        if reply.body.len() as u64 != layer.size {
            return Err(OciError::Manifest(format!(
                "blob `sha256:{}` is {} bytes, the manifest says {}",
                layer.hex,
                reply.body.len(),
                layer.size
            )));
        }
        let actual = sha256_hex(&reply.body);
        if actual != layer.hex {
            return Err(OciError::Digest {
                what: "module",
                expected: format!("sha256:{}", layer.hex),
                actual: format!("sha256:{actual}"),
            });
        }
        Ok(reply.body)
    }

    /// GET `path` on the registry, answering one bearer challenge if needed.
    async fn get(
        &mut self,
        path: &str,
        accept: Option<&str>,
        limit: usize,
    ) -> Result<Reply, OciError> {
        let uri = self.url(path)?;
        let reply = self.follow(uri.clone(), accept, limit, true, None).await?;
        if reply.status != StatusCode::UNAUTHORIZED || self.token.is_some() {
            return Ok(reply);
        }
        let challenge = reply
            .headers
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_bearer_challenge)
            .ok_or_else(|| {
                OciError::Auth(format!("{path}: unauthorised, and no bearer challenge"))
            })?;
        self.token = Some(self.fetch_token(&challenge).await?);
        self.follow(uri, accept, limit, true, None).await
    }

    /// Requests `uri` and follows redirects. The token is attached only while the
    /// request stays on the registry's own host.
    async fn follow(
        &self,
        mut uri: Uri,
        accept: Option<&str>,
        limit: usize,
        registry_request: bool,
        basic: Option<String>,
    ) -> Result<Reply, OciError> {
        for hop in 0..=MAX_REDIRECTS {
            let on_registry = registry_request && self.is_registry_host(&uri);
            // Credentials go on the first hop only, never after a redirect.
            let auth = if on_registry {
                self.token.as_deref().map(|token| format!("Bearer {token}"))
            } else if hop == 0 {
                basic.clone()
            } else {
                None
            };
            let reply = self.exchange(&uri, accept, auth.as_deref(), limit).await?;
            if !reply.status.is_redirection() {
                return Ok(reply);
            }
            let Some(location) = reply.headers.get(LOCATION).and_then(|v| v.to_str().ok()) else {
                return Ok(reply);
            };
            uri = resolve(&uri, location)?;
        }
        Err(OciError::Transport(format!(
            "more than {MAX_REDIRECTS} redirects"
        )))
    }

    /// Exchanges one GET and reads its body up to `limit` bytes.
    async fn exchange(
        &self,
        uri: &Uri,
        accept: Option<&str>,
        auth: Option<&str>,
        limit: usize,
    ) -> Result<Reply, OciError> {
        if !scheme_allowed(uri) {
            return Err(OciError::Transport(format!(
                "refusing plain http to a non-loopback host: {}",
                host_of(uri)
            )));
        }
        let mut builder = Request::builder().method(Method::GET).uri(uri.clone());
        if let Some(accept) = accept {
            builder = builder.header(ACCEPT, accept);
        }
        if let Some(auth) = auth {
            builder = builder.header(AUTHORIZATION, auth);
        }
        let mut request = builder
            .body(empty_body())
            .map_err(|error| OciError::Transport(error.to_string()))?;
        if let Some(value) = request.headers_mut().get_mut(AUTHORIZATION) {
            value.set_sensitive(true);
        }

        let egress = send::Egress::Registry {
            max_response_bytes: limit as u64,
        };
        let (response, io) = send::send_request(request, self.options, egress)
            .await
            .map_err(|error| OciError::Transport(format!("{}: {error}", host_of(uri))))?;
        // The connection must be driven for the body to arrive.
        tokio::spawn(async move {
            let _ = io.await;
        });

        let (parts, mut body) = response.into_parts();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| OciError::Transport(error.to_string()))?;
            if let Some(data) = frame.data_ref() {
                if bytes.len().saturating_add(data.len()) > limit {
                    return Err(OciError::TooLarge {
                        limit: limit as u64,
                    });
                }
                bytes.extend_from_slice(data);
            }
        }
        Ok(Reply {
            status: parts.status,
            headers: parts.headers,
            body: bytes,
        })
    }

    /// Answers a bearer challenge anonymously and returns the token.
    async fn fetch_token(&self, challenge: &BearerChallenge) -> Result<String, OciError> {
        let scope = challenge
            .scope
            .clone()
            .unwrap_or_else(|| format!("repository:{}:pull", self.repository));
        let mut query = format!("scope={}", encode(&scope));
        if let Some(service) = &challenge.service {
            query.push_str(&format!("&service={}", encode(service)));
        }
        let separator = if challenge.realm.contains('?') {
            '&'
        } else {
            '?'
        };
        let uri: Uri = format!("{}{separator}{query}", challenge.realm)
            .parse()
            .map_err(|_| OciError::Auth("the token realm is not a valid URL".to_owned()))?;

        // The token request is anonymous, so it sends no registry credentials.
        let reply = self
            .follow(uri, None, MAX_TOKEN, false, self.basic.clone())
            .await?;
        ensure_success(&reply, "token")?;
        #[derive(Deserialize)]
        struct TokenReply {
            token: Option<String>,
            access_token: Option<String>,
        }
        let parsed: TokenReply = serde_json::from_slice(&reply.body)
            .map_err(|error| OciError::Auth(format!("token response: {error}")))?;
        parsed
            .token
            .or(parsed.access_token)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| OciError::Auth("token response has no token".to_owned()))
    }

    /// The absolute URL for `path` on this registry.
    fn url(&self, path: &str) -> Result<Uri, OciError> {
        let scheme = if is_loopback(&self.host) {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{}{path}", self.host)
            .parse()
            .map_err(|_| OciError::Reference(format!("cannot form a URL for `{path}`")))
    }

    fn is_registry_host(&self, uri: &Uri) -> bool {
        uri.authority()
            .is_some_and(|authority| authority.as_str().eq_ignore_ascii_case(&self.host))
    }
}

fn empty_body() -> EmptyBody {
    Empty::<Bytes>::new().map_err(|never: Infallible| match never {})
}

fn ensure_success(reply: &Reply, path: &str) -> Result<(), OciError> {
    if reply.status.is_success() {
        Ok(())
    } else {
        Err(OciError::Status {
            status: reply.status.as_u16(),
            path: path.to_owned(),
        })
    }
}

/// Plain `http` is allowed only for loopback hosts, which is where a local test
/// or development registry runs.
fn scheme_allowed(uri: &Uri) -> bool {
    uri.scheme() == Some(&Scheme::HTTPS)
        || (uri.scheme() == Some(&Scheme::HTTP) && is_loopback(&host_of(uri)))
}

fn is_loopback(host: &str) -> bool {
    let name = host.rsplit_once(':').map_or(host, |(name, _)| name);
    name == "localhost" || name.starts_with("127.")
}

fn host_of(uri: &Uri) -> String {
    uri.authority()
        .map_or_else(String::new, |authority| authority.as_str().to_owned())
}

/// Resolves a redirect `location` against the request URI.
fn resolve(base: &Uri, location: &str) -> Result<Uri, OciError> {
    let target: Uri = match location.parse::<Uri>() {
        Ok(uri) if uri.scheme().is_some() => uri,
        _ => {
            let scheme = base.scheme_str().unwrap_or("https");
            let authority = host_of(base);
            format!("{scheme}://{authority}{location}")
                .parse()
                .map_err(|_| OciError::Transport("redirect to an invalid URL".to_owned()))?
        }
    };
    if scheme_allowed(&target) {
        Ok(target)
    } else {
        Err(OciError::Transport(format!(
            "refusing a redirect to {target}"
        )))
    }
}

/// A parsed `WWW-Authenticate: Bearer` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BearerChallenge {
    pub(crate) realm: String,
    pub(crate) service: Option<String>,
    pub(crate) scope: Option<String>,
}

/// Parses a `Bearer` challenge such as
/// `Bearer realm="https://auth/token",service="reg",scope="repository:a:pull"`.
pub(crate) fn parse_bearer_challenge(value: &str) -> Option<BearerChallenge> {
    let params = value.trim();
    let rest = params
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("bearer "))
        .map(|_| &params[7..])?;

    let mut fields = HashMap::new();
    let mut remaining = rest.trim_start();
    while !remaining.is_empty() {
        let (key, after_key) = remaining.split_once('=')?;
        let key = key
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_ascii_lowercase();
        let quoted = after_key.trim_start().strip_prefix('"')?;
        let (value, after_value) = quoted.split_once('"')?;
        fields.insert(key, value.to_owned());
        remaining = after_value
            .trim_start()
            .trim_start_matches(',')
            .trim_start();
    }

    let realm = fields.remove("realm")?;
    Some(BearerChallenge {
        realm,
        service: fields.remove("service"),
        scope: fields.remove("scope"),
    })
}

/// Percent-encodes a query value (RFC 3986 unreserved characters are kept).
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawManifest {
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    manifests: Option<serde_json::Value>,
    #[serde(default)]
    layers: Vec<RawLayer>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLayer {
    media_type: String,
    digest: String,
    size: u64,
}

#[derive(Deserialize)]
struct RawIndex {
    #[serde(default)]
    manifests: Vec<RawIndexEntry>,
}

#[derive(Deserialize)]
struct RawIndexEntry {
    digest: String,
    #[serde(default)]
    platform: Option<RawPlatform>,
}

#[derive(Deserialize)]
struct RawPlatform {
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    architecture: Option<String>,
}

/// One entry of an image index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexEntry {
    /// `sha256:<hex>` of the entry's manifest.
    pub(crate) digest: String,
    pub(crate) os: Option<String>,
    pub(crate) architecture: Option<String>,
}

/// A parsed manifest: either an image with its module layer, or an index.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Document {
    Image(Layer),
    Index(Vec<IndexEntry>),
}

/// Parses a manifest or an image index.
pub(crate) fn parse_document(bytes: &[u8]) -> Result<Document, OciError> {
    let manifest: RawManifest = serde_json::from_slice(bytes)
        .map_err(|error| OciError::Manifest(format!("not a JSON manifest: {error}")))?;
    let is_index = manifest.manifests.is_some()
        || manifest
            .media_type
            .as_deref()
            .is_some_and(|t| t.contains("index") || t.contains("manifest.list"));
    if !is_index {
        return parse_image(manifest).map(Document::Image);
    }

    let index: RawIndex = serde_json::from_slice(bytes)
        .map_err(|error| OciError::Manifest(format!("not a JSON image index: {error}")))?;
    if index.manifests.is_empty() {
        return Err(OciError::Manifest("the image index is empty".to_owned()));
    }
    let entries = index
        .manifests
        .into_iter()
        .map(|entry| {
            validate_digest(&entry.digest).map_err(OciError::Manifest)?;
            let platform = entry.platform;
            Ok(IndexEntry {
                digest: entry.digest,
                os: platform.as_ref().and_then(|p| p.os.clone()),
                architecture: platform.and_then(|p| p.architecture),
            })
        })
        .collect::<Result<Vec<_>, OciError>>()?;
    Ok(Document::Index(entries))
}

/// The entry that holds a WebAssembly module: platform `wasi`, or architecture
/// `wasm`.
pub(crate) fn select_wasm(entries: &[IndexEntry]) -> Result<&IndexEntry, OciError> {
    entries
        .iter()
        .find(|entry| {
            entry.os.as_deref() == Some("wasi") || entry.architecture.as_deref() == Some("wasm")
        })
        .ok_or_else(|| OciError::Manifest("the image index has no wasi or wasm entry".to_owned()))
}

/// Parses a manifest that must be an image. An index is refused here.
#[cfg(test)]
pub(crate) fn parse_manifest(bytes: &[u8]) -> Result<Layer, OciError> {
    match parse_document(bytes)? {
        Document::Image(layer) => Ok(layer),
        Document::Index(_) => Err(OciError::Manifest(
            "the reference is an image index, not a single manifest".to_owned(),
        )),
    }
}

/// Picks the module layer out of an image manifest.
///
/// A manifest with exactly one WebAssembly layer is used. A manifest with no
/// WebAssembly layer but exactly one layer of any type is used too. Anything
/// ambiguous is refused.
fn parse_image(manifest: RawManifest) -> Result<Layer, OciError> {
    let wasm: Vec<&RawLayer> = manifest
        .layers
        .iter()
        .filter(|layer| WASM_MEDIA_TYPES.contains(&layer.media_type.as_str()))
        .collect();
    let layer = match (wasm.as_slice(), manifest.layers.as_slice()) {
        ([only], _) => *only,
        ([], [only]) => only,
        ([], []) => {
            return Err(OciError::Manifest("the manifest has no layers".to_owned()));
        }
        ([], _) => {
            return Err(OciError::Manifest(
                "the manifest has several layers and none is a WebAssembly module".to_owned(),
            ));
        }
        _ => {
            return Err(OciError::Manifest(format!(
                "the manifest has {} WebAssembly layers; expected one",
                wasm.len()
            )));
        }
    };

    validate_digest(&layer.digest).map_err(OciError::Manifest)?;
    if layer.size > MAX_MODULE {
        return Err(OciError::TooLarge { limit: MAX_MODULE });
    }
    let hex = layer
        .digest
        .strip_prefix("sha256:")
        .unwrap_or_default()
        .to_owned();
    Ok(Layer {
        hex,
        size: layer.size,
    })
}

#[cfg(test)]
mod tests {
    use super::{Layer, encode, parse_bearer_challenge, parse_manifest, resolve};
    use http::Uri;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn manifest(layers: &str) -> String {
        format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{layers}]}}"#
        )
    }

    fn layer(media_type: &str, size: u64) -> String {
        format!(r#"{{"mediaType":"{media_type}","digest":"sha256:{HEX}","size":{size}}}"#)
    }

    #[test]
    fn a_single_wasm_layer_is_selected() {
        let text = manifest(&layer("application/wasm", 10));
        assert_eq!(
            parse_manifest(text.as_bytes()).unwrap(),
            Layer {
                hex: HEX.to_owned(),
                size: 10
            }
        );
    }

    #[test]
    fn a_lone_layer_of_another_type_is_accepted() {
        let text = manifest(&layer("application/vnd.oci.image.layer.v1.tar", 10));
        assert_eq!(parse_manifest(text.as_bytes()).unwrap().size, 10);
    }

    #[test]
    fn ambiguous_and_index_manifests_are_refused() {
        let two = manifest(&format!(
            "{},{}",
            layer("application/wasm", 1),
            layer("application/wasm", 2)
        ));
        assert!(parse_manifest(two.as_bytes()).is_err());
        let index = r#"{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#;
        assert!(parse_manifest(index.as_bytes()).is_err());
        let docker_list =
            r#"{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json"}"#;
        assert!(parse_manifest(docker_list.as_bytes()).is_err());
    }

    #[test]
    fn oversized_and_badly_digested_layers_are_refused() {
        let big = manifest(&layer("application/wasm", u64::MAX));
        assert!(parse_manifest(big.as_bytes()).is_err());
        let bad = r#"{"layers":[{"mediaType":"application/wasm","digest":"sha512:x","size":1}]}"#;
        assert!(parse_manifest(bad.as_bytes()).is_err());
    }

    #[test]
    fn bearer_challenges_are_parsed() {
        let value = r#"Bearer realm="https://auth.example/token",service="reg.example",scope="repository:org/tool:pull""#;
        let challenge = parse_bearer_challenge(value).unwrap();
        assert_eq!(challenge.realm, "https://auth.example/token");
        assert_eq!(challenge.service.as_deref(), Some("reg.example"));
        assert_eq!(challenge.scope.as_deref(), Some("repository:org/tool:pull"));
        assert!(parse_bearer_challenge("Basic realm=\"x\"").is_none());
        assert!(parse_bearer_challenge("Bearer service=\"x\"").is_none());
    }

    #[test]
    fn query_values_are_percent_encoded() {
        assert_eq!(
            encode("repository:org/tool:pull"),
            "repository%3Aorg%2Ftool%3Apull"
        );
    }

    #[test]
    fn plain_http_redirects_are_refused_unless_loopback() {
        let base: Uri = "https://ghcr.io/v2/x/blobs/y".parse().unwrap();
        assert!(resolve(&base, "https://cdn.example/blob").is_ok());
        assert!(resolve(&base, "http://cdn.example/blob").is_err());
        assert!(resolve(&base, "http://127.0.0.1:9/blob").is_ok());
        assert_eq!(
            resolve(&base, "/relative").unwrap().to_string(),
            "https://ghcr.io/relative"
        );
    }
}
