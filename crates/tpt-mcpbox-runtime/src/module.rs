// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Module sources and digest pinning.
//!
//! The module's bytes are read once, hashed, and that same buffer is compiled.
//! Hashing and compiling separate reads would leave a window in which the file
//! could be replaced after the check, so the check and the compile share one
//! read.

use std::path::Path;

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
pub(crate) fn load_file(tool: &str, path: &Path, pin: Option<&str>) -> Result<Module, ToolError> {
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

    Ok(Module { bytes, digest })
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
        let module = load_file("t", &path, Some(HELLO_SHA256)).expect("loads");
        assert_eq!(module.digest, HELLO_SHA256);
        assert_eq!(module.bytes, b"hello");
    }

    #[test]
    fn pin_accepts_prefix_and_uppercase() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write_hello(dir.path());
        let pin = format!("sha256:{}", HELLO_SHA256.to_ascii_uppercase());
        assert!(load_file("t", &path, Some(&pin)).is_ok());
    }

    #[test]
    fn mismatched_pin_is_refused_before_compilation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write_hello(dir.path());
        let wrong = "0".repeat(64);
        match load_file("t", &path, Some(&wrong)) {
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
            load_file("t", &path, Some("abc")),
            Err(ToolError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn missing_file_is_an_io_error_with_its_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("absent.wasm");
        assert!(matches!(
            load_file("t", &path, None),
            Err(ToolError::Io { .. })
        ));
    }
}
