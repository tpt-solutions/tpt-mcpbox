// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! A content-addressed cache of module bytes, keyed by SHA-256.
//!
//! Entries are named by their digest and checked again on every read, so a
//! file edited on disk is discarded rather than loaded. Writes go to a temporary
//! file that is renamed into place, so a crash never leaves a partial entry
//! under a digest name.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::OciError;

/// Environment variable that overrides the cache location.
pub const CACHE_DIR_ENV: &str = "MCPBOX_CACHE_DIR";

/// A cache rooted at one directory.
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    /// A cache rooted at `root`. The directory is created on first write.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The cache's root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path an entry with this lowercase hex digest is stored at.
    #[must_use]
    pub fn path_for(&self, hex: &str) -> PathBuf {
        self.root.join("sha256").join(hex)
    }

    /// Returns the bytes cached under `hex`, if present and intact. An entry whose
    /// bytes no longer match its name is removed and reported as a miss.
    ///
    /// # Errors
    ///
    /// Returns [`OciError::Io`] for a read failure other than "not found".
    pub fn get(&self, hex: &str) -> Result<Option<Vec<u8>>, OciError> {
        let path = self.path_for(hex);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(OciError::Io { path, source }),
        };
        if sha256_hex(&bytes) == hex {
            Ok(Some(bytes))
        } else {
            tracing::warn!(path = %path.display(), "discarding cache entry that fails its digest");
            // Removal is best effort; a miss is returned either way.
            let _ = fs::remove_file(&path);
            Ok(None)
        }
    }

    /// Stores `bytes` under their own digest and returns that digest.
    ///
    /// # Errors
    ///
    /// Returns [`OciError::Io`] when the entry cannot be written.
    pub fn put(&self, bytes: &[u8]) -> Result<String, OciError> {
        let hex = sha256_hex(bytes);
        let path = self.path_for(&hex);
        let dir = path.parent().unwrap_or(&self.root);
        let io_error = |source| OciError::Io {
            path: path.clone(),
            source,
        };
        fs::create_dir_all(dir).map_err(io_error)?;
        // A unique temporary name, so concurrent pulls of one digest do not
        // write the same file.
        let temp = dir.join(format!(".{hex}.{}.tmp", std::process::id()));
        {
            let mut file = fs::File::create(&temp).map_err(io_error)?;
            file.write_all(bytes).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
        }
        fs::rename(&temp, &path).map_err(|source| {
            let _ = fs::remove_file(&temp);
            OciError::Io {
                path: path.clone(),
                source,
            }
        })?;
        Ok(hex)
    }
}

/// Lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The default cache directory, in order of preference:
///
/// 1. `MCPBOX_CACHE_DIR`,
/// 2. `%LOCALAPPDATA%\tpt-mcpbox\cache` on Windows,
/// 3. `$XDG_CACHE_HOME/tpt-mcpbox` or `~/.cache/tpt-mcpbox` elsewhere.
///
/// Falls back to a `tpt-mcpbox` directory under the system temporary directory
/// when no home is set.
#[must_use]
pub fn default_cache_dir() -> PathBuf {
    if let Some(dir) = env::var_os(CACHE_DIR_ENV) {
        return PathBuf::from(dir);
    }
    if cfg!(windows) {
        if let Some(local) = env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join("tpt-mcpbox").join("cache");
        }
    } else if let Some(xdg) = env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("tpt-mcpbox");
    }
    let home = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE"));
    match home {
        Some(home) if cfg!(windows) => PathBuf::from(home)
            .join("AppData")
            .join("Local")
            .join("tpt-mcpbox")
            .join("cache"),
        Some(home) => PathBuf::from(home).join(".cache").join("tpt-mcpbox"),
        None => env::temp_dir().join("tpt-mcpbox"),
    }
}

#[cfg(test)]
mod tests {
    use super::{Cache, sha256_hex};

    #[test]
    fn round_trips_and_names_entries_by_digest() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path());
        let hex = cache.put(b"module bytes").unwrap();
        assert_eq!(hex, sha256_hex(b"module bytes"));
        assert_eq!(
            cache.get(&hex).unwrap().as_deref(),
            Some(&b"module bytes"[..])
        );
        assert!(cache.get(&sha256_hex(b"other")).unwrap().is_none());
    }

    #[test]
    fn a_tampered_entry_is_removed_and_reported_as_a_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path());
        let hex = cache.put(b"genuine").unwrap();
        std::fs::write(cache.path_for(&hex), b"tampered").unwrap();
        assert!(cache.get(&hex).unwrap().is_none());
        assert!(!cache.path_for(&hex).exists());
    }
}
