// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Module sources and digest pinning.
//!
//! The module's bytes are read once, hashed, and that same buffer is compiled.
//! Hashing and compiling separate reads would leave a window in which the file
//! could be replaced after the check, so the check and the compile share one
//! read.

use std::path::{Path, PathBuf};

use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};

use crate::error::ToolError;

/// A module's bytes, with the digest they hash to.
#[derive(Debug)]
pub(crate) struct Module {
    pub(crate) bytes: Vec<u8>,
    /// Lowercase hex SHA-256 of `bytes`.
    pub(crate) digest: String,
}

/// Read a module from disk and check it against the configured pin.
///
/// With no pin the module loads, and its digest is logged so the operator can
/// add it to the configuration. A pin that is not 64 hex digits is a
/// configuration error, not a silent skip.
///
/// With `public_key` set, the module must also carry a minisign signature in
/// `<path>.minisig` that verifies under that key. The signature is checked on
/// the same bytes that are compiled, so the check cannot be raced.
pub(crate) fn load_file(
    tool: &str,
    path: &Path,
    pin: Option<&str>,
    public_key: Option<&str>,
) -> Result<Module, ToolError> {
    let bytes = std::fs::read(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let digest = hex::encode(Sha256::digest(&bytes));

    match pin {
        Some(expected) => {
            let expected = normalise_pin(tool, expected)?;
            if expected != digest {
                return Err(ToolError::IntegrityMismatch {
                    tool: tool.to_owned(),
                    expected,
                    actual: digest,
                });
            }
        }
        None => {
            tracing::warn!(
                tool,
                sha256 = %digest,
                "tool module is not pinned; add `sha256: {digest}` to its configuration",
            );
        }
    }

    if let Some(key) = public_key {
        verify_signature(tool, path, &bytes, key)?;
    }

    Ok(Module { bytes, digest })
}

/// The signature file for a module: the module's path with `.minisig` appended.
fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".minisig");
    PathBuf::from(name)
}

/// Checks `bytes` against the minisign signature beside `path`.
fn verify_signature(
    tool: &str,
    path: &Path,
    bytes: &[u8],
    public_key: &str,
) -> Result<(), ToolError> {
    let key = PublicKey::from_base64(public_key).map_err(|error| ToolError::InvalidConfig {
        tool: tool.to_owned(),
        message: format!("`minisign_key` is not a minisign public key: {error}"),
    })?;
    let sig_path = signature_path(path);
    let text = std::fs::read_to_string(&sig_path).map_err(|error| ToolError::SignatureInvalid {
        tool: tool.to_owned(),
        reason: format!("cannot read {}: {error}", sig_path.display()),
    })?;
    let signature = Signature::decode(&text).map_err(|error| ToolError::SignatureInvalid {
        tool: tool.to_owned(),
        reason: format!(
            "{} is not a minisign signature: {error}",
            sig_path.display()
        ),
    })?;
    key.verify(bytes, &signature)
        .map_err(|error| ToolError::SignatureInvalid {
            tool: tool.to_owned(),
            reason: format!("the module does not verify under `minisign_key`: {error}"),
        })
}

/// Accept `sha256:<hex>` or bare hex, in any case, and return lowercase hex.
fn normalise_pin(tool: &str, pin: &str) -> Result<String, ToolError> {
    let bare = pin
        .strip_prefix("sha256:")
        .unwrap_or(pin)
        .to_ascii_lowercase();
    if bare.len() != 64 || !bare.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ToolError::InvalidConfig {
            tool: tool.to_owned(),
            message: format!("`sha256` must be 64 hex digits, got {pin:?}"),
        });
    }
    Ok(bare)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `bytes` as a module and a minisign signature made with a fresh key.
    /// Returns the module path and the public key that verifies it.
    fn signed(dir: &Path, bytes: &[u8]) -> (PathBuf, String) {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().expect("keypair");
        let signature = minisign::sign(None, &pair.sk, bytes, None, None).expect("signs");
        let path = dir.join("tool.wasm");
        std::fs::write(&path, bytes).expect("write module");
        std::fs::write(signature_path(&path), signature.into_string()).expect("write sig");
        (path, pair.pk.to_base64())
    }

    #[test]
    fn a_module_signed_by_the_configured_key_loads() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (path, key) = signed(dir.path(), b"hello");
        let module = load_file("t", &path, None, Some(&key)).expect("loads");
        assert_eq!(module.bytes, b"hello");
    }

    #[test]
    fn a_module_signed_by_another_key_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (path, _) = signed(dir.path(), b"hello");
        let other = minisign::KeyPair::generate_unencrypted_keypair()
            .expect("keypair")
            .pk
            .to_base64();
        assert!(matches!(
            load_file("t", &path, None, Some(&other)),
            Err(ToolError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn a_module_changed_after_signing_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (path, key) = signed(dir.path(), b"hello");
        std::fs::write(&path, b"hello!").expect("tamper");
        assert!(matches!(
            load_file("t", &path, None, Some(&key)),
            Err(ToolError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn a_module_without_a_signature_file_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (path, key) = signed(dir.path(), b"hello");
        std::fs::remove_file(signature_path(&path)).expect("remove sig");
        assert!(matches!(
            load_file("t", &path, None, Some(&key)),
            Err(ToolError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn a_malformed_public_key_is_a_configuration_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (path, _) = signed(dir.path(), b"hello");
        assert!(matches!(
            load_file("t", &path, None, Some("not a key")),
            Err(ToolError::InvalidConfig { .. })
        ));
    }

    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn write_hello(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("tool.wasm");
        std::fs::write(&path, b"hello").expect("write");
        path
    }

    #[test]
    fn matching_pin_loads_and_reports_the_digest() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write_hello(dir.path());
        let module = load_file("t", &path, Some(HELLO_SHA256), None).expect("loads");
        assert_eq!(module.digest, HELLO_SHA256);
        assert_eq!(module.bytes, b"hello");
    }

    #[test]
    fn pin_accepts_prefix_and_uppercase() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write_hello(dir.path());
        let pin = format!("sha256:{}", HELLO_SHA256.to_ascii_uppercase());
        assert!(load_file("t", &path, Some(&pin), None).is_ok());
    }

    #[test]
    fn mismatched_pin_is_refused_before_compilation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write_hello(dir.path());
        let wrong = "0".repeat(64);
        match load_file("t", &path, Some(&wrong), None) {
            Err(ToolError::IntegrityMismatch {
                expected, actual, ..
            }) => {
                assert_eq!(expected, wrong);
                assert_eq!(actual, HELLO_SHA256);
            }
            other => panic!("expected integrity mismatch, got {other:?}"),
        }
    }

    #[test]
    fn malformed_pin_is_a_configuration_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write_hello(dir.path());
        assert!(matches!(
            load_file("t", &path, Some("abc"), None),
            Err(ToolError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn missing_file_is_an_io_error_with_its_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("absent.wasm");
        assert!(matches!(
            load_file("t", &path, None, None),
            Err(ToolError::Io { .. })
        ));
    }
}
