// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! OCI module pulls against a fake registry on loopback.
//!
//! The fake speaks just enough of the distribution API: a bearer challenge with
//! an anonymous token endpoint, manifests by tag or digest, blobs (optionally
//! behind a redirect or corrupted), and an image index. Loopback is the only
//! place plain `http` is accepted, which is what makes this test possible.

use std::future::IntoFuture;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::{HeaderValue, StatusCode, header};
use tpt_mcpbox_config::{Capabilities, Limits, RateLimit, SecretStore, ToolConfig};
use tpt_mcpbox_http::Body;
use tpt_mcpbox_http::Response;
use tpt_mcpbox_http::{Request, State};
use tpt_mcpbox_runtime::oci::{self, Cache, OciError, sha256_hex};
use tpt_mcpbox_runtime::{PROBE_SHA256, PROBE_WASM, Runtime, ToolError};

const TOKEN: &str = "test-token";

/// What the fake registry serves.
struct Fake {
    module: Vec<u8>,
    port: u16,
    /// Require the bearer token on registry paths.
    auth: bool,
    /// Redirect blob requests to `/cdn/<digest>`.
    redirect: bool,
    /// Serve a blob with one byte flipped.
    corrupt: bool,
    /// Serve an image index instead of a manifest.
    index: bool,
    /// Serve a tag as an index with a Linux entry and a wasm entry, whose
    /// manifest is only reachable by digest.
    index_with_wasm: bool,
    /// Require this exact `Authorization` value at the token endpoint.
    basic: Option<String>,
    /// Requests seen, to prove a cache hit makes none.
    requests: AtomicUsize,
    /// Token requests seen.
    token_requests: AtomicUsize,
}

/// The image manifest a registry serves for `module`: one wasm layer.
fn manifest_for(module: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:{empty}","size":2}},"layers":[{{"mediaType":"application/wasm","digest":"sha256:{layer}","size":{size}}}]}}"#,
        empty = sha256_hex(b"{}"),
        layer = sha256_hex(module),
        size = module.len(),
    )
    .into_bytes()
}

const INDEX: &[u8] =
    br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#;

async fn handle(State(fake): State<Arc<Fake>>, request: Request) -> Response {
    fake.requests.fetch_add(1, Ordering::SeqCst);
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let auth = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    if path == "/token" {
        fake.token_requests.fetch_add(1, Ordering::SeqCst);
        if let Some(expected) = &fake.basic
            && auth.as_deref() != Some(expected.as_str())
        {
            return status(StatusCode::UNAUTHORIZED);
        }
        // The anonymous token request must name the repository and service.
        assert!(
            query.contains("scope=") && query.contains("service="),
            "{query}"
        );
        return json(format!(r#"{{"token":"{TOKEN}"}}"#).into_bytes());
    }
    let digest = sha256_hex(&fake.module);
    if path == format!("/cdn/sha256:{digest}") {
        return bytes(fake.module.clone());
    }
    if fake.auth && auth.as_deref() != Some(&format!("Bearer {TOKEN}")) {
        let challenge = format!(
            r#"Bearer realm="http://127.0.0.1:{}/token",service="fake-registry",scope="repository:tools/probe:pull""#,
            fake.port
        );
        return http::Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_str(&challenge).expect("ascii challenge"),
            )
            .body(Body::empty())
            .expect("response");
    }
    if path.starts_with("/v2/tools/probe/manifests/") {
        let reference = path.trim_start_matches("/v2/tools/probe/manifests/");
        if fake.index {
            return json_typed(INDEX.to_vec(), "application/vnd.oci.image.index.v1+json");
        }
        if fake.index_with_wasm && !reference.starts_with("sha256:") {
            let manifest = manifest_for(&fake.module);
            let index = format!(
                r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{linux}","size":1,"platform":{{"os":"linux","architecture":"amd64"}}}},{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{wasm}","size":{size},"platform":{{"os":"wasi","architecture":"wasm"}}}}]}}"#,
                linux = "1".repeat(64),
                wasm = sha256_hex(&manifest),
                size = manifest.len(),
            );
            return json_typed(
                index.into_bytes(),
                "application/vnd.oci.image.index.v1+json",
            );
        }
        return json_typed(
            manifest_for(&fake.module),
            "application/vnd.oci.image.manifest.v1+json",
        );
    }
    if let Some(blob) = path.strip_prefix("/v2/tools/probe/blobs/sha256:") {
        if blob != digest {
            return status(StatusCode::NOT_FOUND);
        }
        if fake.redirect {
            // A relative redirect, which the client must resolve against the request.
            return http::Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(header::LOCATION, format!("/cdn/sha256:{digest}"))
                .body(Body::empty())
                .expect("response");
        }
        let mut served = fake.module.clone();
        if fake.corrupt {
            served[0] ^= 0xff;
        }
        return bytes(served);
    }
    status(StatusCode::NOT_FOUND)
}

fn status(code: StatusCode) -> Response {
    http::Response::builder()
        .status(code)
        .body(Body::empty())
        .expect("response")
}

fn bytes(body: Vec<u8>) -> Response {
    http::Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .expect("response")
}

fn json(body: Vec<u8>) -> Response {
    json_typed(body, "application/json")
}

fn json_typed(body: Vec<u8>, content_type: &str) -> Response {
    http::Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .expect("response")
}

/// Starts a fake registry and returns its address and shared state.
async fn registry(configure: impl FnOnce(&mut Fake)) -> (u16, Arc<Fake>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("address").port();
    let mut fake = Fake {
        module: PROBE_WASM.to_vec(),
        port,
        auth: false,
        redirect: false,
        corrupt: false,
        index: false,
        index_with_wasm: false,
        basic: None,
        requests: AtomicUsize::new(0),
        token_requests: AtomicUsize::new(0),
    };
    configure(&mut fake);
    let fake = Arc::new(fake);
    let app = tpt_mcpbox_http::Router::new()
        .fallback(handle)
        .with_state(Arc::clone(&fake));
    tokio::spawn(tpt_mcpbox_http::serve(listener, app).into_future());
    (port, fake)
}

fn cache() -> (tempfile::TempDir, Cache) {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = Cache::new(dir.path().join("cache"));
    (dir, cache)
}

fn reference(port: u16, tail: &str) -> String {
    format!("oci://127.0.0.1:{port}/tools/probe{tail}")
}

#[tokio::test]
async fn a_tag_pull_is_verified_cached_and_then_served_without_the_network() {
    let (port, fake) = registry(|_| {}).await;
    let (_dir, cache) = cache();

    let first = oci::fetch_module(&reference(port, ":1"), &cache, None)
        .await
        .expect("pull");
    assert_eq!(first.bytes, PROBE_WASM);
    assert_eq!(first.sha256, sha256_hex(PROBE_WASM));
    assert!(!first.from_cache);
    assert_eq!(
        fake.token_requests.load(Ordering::SeqCst),
        0,
        "no auth on this registry"
    );

    // With the module pinned, the cache alone satisfies the request.
    let before = fake.requests.load(Ordering::SeqCst);
    let second = oci::fetch_module(&reference(port, ":1"), &cache, Some(&first.sha256))
        .await
        .expect("cached pull");
    assert!(second.from_cache);
    assert_eq!(second.bytes, PROBE_WASM);
    assert_eq!(
        fake.requests.load(Ordering::SeqCst),
        before,
        "a cache hit makes no request"
    );
}

#[tokio::test]
async fn bearer_challenges_are_answered_anonymously() {
    let (port, fake) = registry(|f| f.auth = true).await;
    let (_dir, cache) = cache();

    let pulled = oci::fetch_module(&reference(port, ":1"), &cache, None)
        .await
        .expect("pull through the token step");
    assert_eq!(pulled.bytes, PROBE_WASM);
    assert_eq!(fake.token_requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_manifest_digest_pins_the_manifest_and_redirects_are_followed() {
    let (port, _fake) = registry(|f| {
        f.redirect = true;
        f.auth = true;
    })
    .await;
    let (_dir, cache) = cache();

    // The digest of the manifest the registry serves for this module.
    let manifest_digest = format!("sha256:{}", sha256_hex(&manifest_for(PROBE_WASM)));

    let pulled = oci::fetch_module(
        &reference(port, &format!("@{manifest_digest}")),
        &cache,
        None,
    )
    .await
    .expect("pull by manifest digest");
    assert_eq!(pulled.bytes, PROBE_WASM);
}

#[tokio::test]
async fn a_wrong_manifest_digest_is_refused() {
    let (port, _fake) = registry(|_| {}).await;
    let (_dir, cache) = cache();
    let wrong = format!("sha256:{}", "0".repeat(64));
    let error = oci::fetch_module(&reference(port, &format!("@{wrong}")), &cache, None)
        .await
        .expect_err("manifest digest must match");
    assert!(
        matches!(
            error,
            OciError::Digest {
                what: "manifest",
                ..
            }
        ),
        "{error}"
    );
}

#[tokio::test]
async fn a_module_that_does_not_match_its_pin_is_refused() {
    let (port, _fake) = registry(|_| {}).await;
    let (_dir, cache) = cache();
    let pin = "ab".repeat(32);
    let error = oci::fetch_module(&reference(port, ":1"), &cache, Some(&pin))
        .await
        .expect_err("pin must match");
    assert!(matches!(error, OciError::Pin { .. }), "{error}");
}

#[tokio::test]
async fn a_blob_whose_bytes_do_not_match_is_refused_and_not_cached() {
    let (port, _fake) = registry(|f| f.corrupt = true).await;
    let (_dir, cache) = cache();
    let error = oci::fetch_module(&reference(port, ":1"), &cache, None)
        .await
        .expect_err("corrupt blob must fail");
    assert!(
        matches!(error, OciError::Digest { what: "module", .. }),
        "{error}"
    );
    assert!(!cache.path_for(&sha256_hex(PROBE_WASM)).exists());
}

#[tokio::test]
async fn an_image_index_is_refused() {
    let (port, _fake) = registry(|f| f.index = true).await;
    let (_dir, cache) = cache();
    let error = oci::fetch_module(&reference(port, ":1"), &cache, None)
        .await
        .expect_err("index must be refused");
    assert!(matches!(error, OciError::Manifest(_)), "{error}");
}

#[tokio::test]
async fn a_tampered_cache_entry_is_not_used() {
    let (port, _fake) = registry(|_| {}).await;
    let (_dir, cache) = cache();
    let digest = sha256_hex(PROBE_WASM);
    // Plant bytes under the right name but the wrong content.
    cache.put(b"not the module").expect("write");
    std::fs::write(cache.path_for(&digest), b"tampered").expect("tamper");

    let pulled = oci::fetch_module(&reference(port, ":1"), &cache, Some(&digest))
        .await
        .expect("falls back to the registry");
    assert!(!pulled.from_cache);
    assert_eq!(pulled.bytes, PROBE_WASM);
}

fn oci_tool(reference: &str, sha256: Option<String>) -> ToolConfig {
    ToolConfig {
        name: "probe".to_owned(),
        description: None,
        wasm_path: None,
        oci_ref: Some(reference.to_owned()),
        oci_auth: None,
        sha256,
        minisign_key: None,
        enabled: true,
        capabilities: Capabilities::default(),
        secrets: Vec::new(),
        limits: Limits::default(),
        rate_limit: RateLimit::default(),
    }
}

#[tokio::test]
async fn an_oci_tool_loads_through_the_async_loader() {
    let (port, _fake) = registry(|_| {}).await;
    let (_dir, cache) = cache();
    let runtime = Runtime::new().expect("runtime");
    let config = oci_tool(&reference(port, ":1"), Some(PROBE_SHA256.trim().to_owned()));

    let tool = runtime
        .load_tool_async(
            &config,
            &SecretStore::new(),
            std::path::Path::new("."),
            &cache,
        )
        .await
        .expect("OCI tool loads");
    assert_eq!(tool.digest(), PROBE_SHA256.trim());
}

#[tokio::test]
async fn oci_tools_with_signatures_are_refused_until_supported() {
    let (port, _fake) = registry(|_| {}).await;
    let (_dir, cache) = cache();
    let runtime = Runtime::new().expect("runtime");
    let mut config = oci_tool(&reference(port, ":1"), None);
    config.minisign_key = Some("RWQ".to_owned());
    let error = runtime
        .load_tool_async(
            &config,
            &SecretStore::new(),
            std::path::Path::new("."),
            &cache,
        )
        .await
        .map(|_| ())
        .expect_err("signatures refused");
    assert!(matches!(error, ToolError::Unsupported { .. }), "{error}");
}

#[tokio::test]
async fn a_pin_mismatch_surfaces_as_a_module_fetch_error() {
    let (port, _fake) = registry(|_| {}).await;
    let (_dir, cache) = cache();
    let runtime = Runtime::new().expect("runtime");
    let config = oci_tool(&reference(port, ":1"), Some("cd".repeat(32)));
    let error = runtime
        .load_tool_async(
            &config,
            &SecretStore::new(),
            std::path::Path::new("."),
            &cache,
        )
        .await
        .map(|_| ())
        .expect_err("pin must match");
    assert!(matches!(error, ToolError::ModuleFetch { .. }), "{error}");
}

#[tokio::test]
async fn an_index_with_a_wasm_entry_is_pulled_through_that_entry() {
    let (port, _fake) = registry(|f| f.index_with_wasm = true).await;
    let (_dir, cache) = cache();
    let pulled = oci::fetch_module(&reference(port, ":1"), &cache, None)
        .await
        .expect("the wasm entry is pulled");
    assert_eq!(pulled.bytes, PROBE_WASM);
}

#[tokio::test]
async fn a_private_registry_needs_the_configured_credentials() {
    use base64::Engine as _;
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("alice:s3cret")
    );
    let (port, fake) = registry(|f| {
        f.auth = true;
        f.basic = Some(basic);
    })
    .await;
    let (_dir, cache) = cache();

    let anonymous = oci::fetch_module(&reference(port, ":1"), &cache, None).await;
    assert!(anonymous.is_err(), "no credentials, no module");

    let wrong =
        oci::fetch_module_with_auth(&reference(port, ":1"), &cache, None, Some("alice:nope")).await;
    assert!(wrong.is_err(), "wrong credentials are refused");

    let pulled =
        oci::fetch_module_with_auth(&reference(port, ":1"), &cache, None, Some("alice:s3cret"))
            .await
            .expect("the right credentials pull");
    assert_eq!(pulled.bytes, PROBE_WASM);
    assert!(fake.token_requests.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn a_tool_loads_with_credentials_from_its_secret() {
    use base64::Engine as _;
    use tpt_mcpbox_config::{OciAuth, SecretStore, secrets::SourceKind};
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("bob:hunter2")
    );
    let (port, _fake) = registry(|f| {
        f.auth = true;
        f.basic = Some(basic);
    })
    .await;
    let (_dir, cache) = cache();
    let runtime = Runtime::new().expect("runtime");

    let mut config = oci_tool(&reference(port, ":1"), None);
    config.oci_auth = Some(OciAuth {
        secret: "TPT_TEST_REGISTRY_LOGIN".to_owned(),
    });

    // The secret is absent: refused before any request.
    let missing = runtime
        .load_tool_async(
            &config,
            &SecretStore::new(),
            std::path::Path::new("."),
            &cache,
        )
        .await
        .map(|_| ())
        .expect_err("missing secret refused");
    assert!(
        matches!(missing, ToolError::ModuleFetch { .. }),
        "{missing}"
    );

    let mut store = SecretStore::new();
    store.insert(
        "TPT_TEST_REGISTRY_LOGIN",
        "bob:hunter2".to_owned(),
        SourceKind::Injected,
    );
    runtime
        .load_tool_async(&config, &store, std::path::Path::new("."), &cache)
        .await
        .expect("the tool loads with its credentials");
}
