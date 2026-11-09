// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Module sources from OCI registries (`oci_ref` in the configuration).
//!
//! A pull resolves a reference to a manifest, takes its one WebAssembly layer,
//! and stores the bytes in a content-addressed cache. Two pins can apply:
//!
//! * the reference's digest pins the **manifest** (`@sha256:...`),
//! * the tool's `sha256` pins the **module** bytes.
//!
//! When the module pin is set and already cached, nothing is fetched. A tag
//! alone is not a pin: the registry can move it, so the tool then loads whatever
//! the tag points at, with a warning. Use a digest or `sha256` to pin.

mod cache;
mod reference;
mod registry;

use std::fmt;
use std::path::PathBuf;

pub use cache::{CACHE_DIR_ENV, Cache, default_cache_dir, sha256_hex};
pub use reference::Reference;

use registry::Registry;

/// Why a module could not be pulled or verified.
#[derive(Debug, thiserror::Error)]
pub enum OciError {
    /// The reference is malformed or names no registry.
    #[error("invalid OCI reference: {0}")]
    Reference(String),
    /// The registry could not be reached, or the transport failed.
    #[error("registry transport: {0}")]
    Transport(String),
    /// The registry refused the request, even after the anonymous token step.
    #[error("registry authentication: {0}")]
    Auth(String),
    /// The registry answered with an unexpected status.
    #[error("registry answered {status} for {path}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// Request path (no host, no token).
        path: String,
    },
    /// The manifest is not a usable module manifest.
    #[error("manifest: {0}")]
    Manifest(String),
    /// A download or response exceeded its size limit.
    #[error("size limit of {limit} bytes exceeded")]
    TooLarge {
        /// The limit that was exceeded.
        limit: u64,
    },
    /// Bytes do not match the digest that names them.
    #[error("{what} digest mismatch: expected {expected}, got {actual}")]
    Digest {
        /// `manifest` or `module`.
        what: &'static str,
        /// The digest that was asked for.
        expected: String,
        /// The digest of the bytes received.
        actual: String,
    },
    /// The module differs from the `sha256` pin in the configuration.
    #[error("module pinned to sha256:{expected}, but the reference resolves to sha256:{actual}")]
    Pin {
        /// Pinned digest (lowercase hex).
        expected: String,
        /// Digest the reference resolved to (lowercase hex).
        actual: String,
    },
    /// The cache could not be read or written.
    #[error("cache {}: {source}", path.display())]
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// A module that has been fetched or found in the cache.
#[derive(Clone, PartialEq, Eq)]
pub struct Pulled {
    /// The module bytes, verified against `sha256`.
    pub bytes: Vec<u8>,
    /// Lowercase hex SHA-256 of `bytes`.
    pub sha256: String,
    /// The reference the module was resolved from, in canonical form.
    pub reference: String,
    /// `true` when no network request was needed.
    pub from_cache: bool,
}

impl fmt::Debug for Pulled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pulled")
            .field("bytes", &self.bytes.len())
            .field("sha256", &self.sha256)
            .field("reference", &self.reference)
            .field("from_cache", &self.from_cache)
            .finish()
    }
}

/// Fetches the module behind `reference`, using `cache` when it can.
///
/// `module_pin`, when given, is the expected SHA-256 of the module bytes (with
/// or without a `sha256:` prefix). A cached entry under that digest is returned
/// without any network request.
///
/// # Errors
///
/// Returns [`OciError`] for a malformed reference, a registry or transport
/// failure, a manifest that is not a module manifest, a digest mismatch, or an
/// oversized module.
pub async fn fetch_module(
    reference: &str,
    cache: &Cache,
    module_pin: Option<&str>,
) -> Result<Pulled, OciError> {
    fetch_module_with_auth(reference, cache, module_pin, None).await
}

/// As [`fetch_module`], with `credentials` (`username:password`) for a private
/// registry. The credentials are sent only to the registry's token endpoint, as
/// Basic authentication, and never to a redirect target.
///
/// # Errors
///
/// As [`fetch_module`].
pub async fn fetch_module_with_auth(
    reference: &str,
    cache: &Cache,
    module_pin: Option<&str>,
    credentials: Option<&str>,
) -> Result<Pulled, OciError> {
    let reference = Reference::parse(reference)?;
    let pin = module_pin.map(normalise_pin).transpose()?;

    if let Some(hex) = &pin
        && let Some(bytes) = cache.get(hex)?
    {
        return Ok(pulled(bytes, &reference, true));
    }

    let mut registry = Registry::new(&reference, credentials);
    let layer = registry.module_layer(&reference).await?;
    if let Some(pin) = &pin
        && pin != &layer.hex
    {
        return Err(OciError::Pin {
            expected: pin.clone(),
            actual: layer.hex,
        });
    }
    if let Some(bytes) = cache.get(&layer.hex)? {
        return Ok(pulled(bytes, &reference, true));
    }

    let bytes = registry.blob(&layer).await?;
    cache.put(&bytes)?;
    Ok(pulled(bytes, &reference, false))
}

fn pulled(bytes: Vec<u8>, reference: &Reference, from_cache: bool) -> Pulled {
    let sha256 = sha256_hex(&bytes);
    Pulled {
        bytes,
        sha256,
        reference: reference.to_string(),
        from_cache,
    }
}

/// Accepts `sha256:<hex>` or bare hex, and returns lowercase hex.
fn normalise_pin(pin: &str) -> Result<String, OciError> {
    let hex = pin.strip_prefix("sha256:").unwrap_or(pin);
    let digest = format!("sha256:{}", hex.to_ascii_lowercase());
    reference::validate_digest(&digest).map_err(OciError::Reference)?;
    Ok(digest["sha256:".len()..].to_owned())
}

#[cfg(test)]
mod tests {
    use super::normalise_pin;

    #[test]
    fn pins_accept_both_spellings() {
        let hex = "ab".repeat(32);
        assert_eq!(normalise_pin(&hex).unwrap(), hex);
        assert_eq!(normalise_pin(&format!("sha256:{hex}")).unwrap(), hex);
        assert!(normalise_pin("sha256:xyz").is_err());
    }
}
