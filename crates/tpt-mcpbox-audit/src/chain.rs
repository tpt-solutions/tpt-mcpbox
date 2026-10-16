// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Hash-chained, append-only audit log.
//!
//! The file holds one JSON object per line. Each entry's `hash` is the SHA-256
//! of its own fields together with the previous entry's hash, so changing,
//! removing or reordering any entry breaks every hash after it. The first
//! entry chains from [`GENESIS`].
//!
//! Limits: a truncation of the newest entries leaves a valid shorter chain and
//! is not detected here. Detecting it needs the head hash recorded somewhere
//! else, which is a later step.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// `prev` value of the first entry: 64 zero hex digits.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One recorded event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Position in the log, starting at 0.
    pub seq: u64,
    /// Unix time in milliseconds when the entry was written.
    pub ts_ms: u64,
    /// Hash of the previous entry, or [`GENESIS`].
    pub prev: String,
    /// Event kind, e.g. `tool_call`, `policy_decision`, `config_reload`.
    pub kind: String,
    /// Event details. Record secret names, never values.
    pub data: Value,
    /// SHA-256 over the fields above, lowercase hex.
    pub hash: String,
}

/// Failures reading or writing the log.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The file could not be read or written.
    #[error("audit log I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// An entry could not be encoded or decoded.
    #[error("audit entry is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Another process holds the log's lock file.
    #[error(
        "audit log is in use by another process (lock file {path}); if no tpt-mcpbox is running, delete that file"
    )]
    Locked {
        /// Path of the lock file.
        path: String,
    },
    /// The chain is broken at `seq`.
    #[error("audit chain broken at entry {seq}: {reason}")]
    Broken {
        /// Sequence number of the first bad entry.
        seq: u64,
        /// What failed.
        reason: &'static str,
    },
}

/// Result of a successful [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Number of entries checked.
    pub entries: u64,
    /// Hash of the last entry, or [`GENESIS`] for an empty log.
    pub head: String,
}

/// Writer for an audit log file.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    state: Mutex<Head>,
    _lock: LockFile,
}

/// Exclusive claim on a log file, released when the `AuditLog` is dropped.
///
/// Two writers on one file would interleave entries and break the chain, so a
/// second `open` is refused while the lock exists. The claim is a file created
/// with `create_new`, which is atomic on every platform. If a process is killed
/// without releasing it, the file stays and must be removed by hand.
#[derive(Debug)]
struct LockFile {
    path: PathBuf,
}

impl LockFile {
    fn acquire(log: &Path) -> Result<Self, AuditError> {
        let mut name = log.as_os_str().to_owned();
        name.push(".lock");
        let path = PathBuf::from(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                // The PID is only for the person who has to clear a stale lock.
                let _ = writeln!(file, "{}", std::process::id());
                Ok(Self { path })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(AuditError::Locked {
                    path: path.display().to_string(),
                })
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Debug)]
struct Head {
    file: File,
    next_seq: u64,
    prev: String,
}

impl AuditLog {
    /// Opens or creates the log at `path`.
    ///
    /// The existing chain is verified first. A broken log is refused rather than
    /// extended, because new entries would sit on top of tampered history.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Broken`] when the existing chain does not verify,
    /// or an I/O error when the file cannot be opened.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditError> {
        let path = path.into();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        // Claim the log before reading it, so no other writer can change the
        // chain between verification and the first append.
        let lock = LockFile::acquire(&path)?;
        let report = verify(&path)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(Head {
                file,
                next_seq: report.entries,
                prev: report.head,
            }),
            _lock: lock,
        })
    }

    /// Path of the log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one entry and syncs it to disk before returning.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the entry cannot be written or synced. The chain
    /// head is only advanced after a successful write.
    pub fn append(&self, kind: &str, data: Value) -> Result<Entry, AuditError> {
        let mut head = lock(&self.state);
        let ts_ms = now_ms();
        let hash = compute_hash(head.next_seq, ts_ms, &head.prev, kind, &data)?;
        let entry = Entry {
            seq: head.next_seq,
            ts_ms,
            prev: head.prev.clone(),
            kind: kind.to_owned(),
            data,
            hash: hash.clone(),
        };

        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');
        head.file.write_all(line.as_bytes())?;
        head.file.sync_data()?;

        head.next_seq += 1;
        head.prev = hash;
        Ok(entry)
    }
}

/// Checks every entry in the log at `path`.
///
/// A missing file counts as an empty log.
///
/// # Errors
///
/// Returns [`AuditError::Broken`] at the first entry whose sequence number,
/// link or hash does not match, or an I/O / decode error.
pub fn verify(path: &Path) -> Result<VerifyReport, AuditError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VerifyReport {
                entries: 0,
                head: GENESIS.to_owned(),
            });
        }
        Err(err) => return Err(err.into()),
    };

    let mut expected_seq = 0u64;
    let mut prev = GENESIS.to_owned();
    for line in BufReader::new(file).lines() {
        let line = line?;
        let entry: Entry = serde_json::from_str(&line)?;

        if entry.seq != expected_seq {
            return Err(AuditError::Broken {
                seq: entry.seq,
                reason: "sequence number out of order",
            });
        }
        if entry.prev != prev {
            return Err(AuditError::Broken {
                seq: entry.seq,
                reason: "previous hash does not match",
            });
        }
        let hash = compute_hash(
            entry.seq,
            entry.ts_ms,
            &entry.prev,
            &entry.kind,
            &entry.data,
        )?;
        if hash != entry.hash {
            return Err(AuditError::Broken {
                seq: entry.seq,
                reason: "entry hash does not match its contents",
            });
        }

        prev = entry.hash;
        expected_seq += 1;
    }

    Ok(VerifyReport {
        entries: expected_seq,
        head: prev,
    })
}

fn compute_hash(
    seq: u64,
    ts_ms: u64,
    prev: &str,
    kind: &str,
    data: &Value,
) -> Result<String, AuditError> {
    // Field order is fixed here, and `data` is hashed in canonical form, so the
    // digest never depends on how the caller built the JSON object.
    let mut hasher = Sha256::new();
    hasher.update(seq.to_be_bytes());
    hasher.update(ts_ms.to_be_bytes());
    hasher.update(prev.as_bytes());
    hasher.update([0u8]);
    hasher.update(kind.as_bytes());
    hasher.update([0u8]);
    hasher.update(serde_json::to_vec(&canonical(data))?);
    Ok(hex::encode(hasher.finalize()))
}

/// Rebuilds `value` with every object's keys sorted, at every depth.
///
/// `serde_json` keeps insertion order when its `preserve_order` feature is on,
/// so the sort is done here rather than left to the map type.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<&String, Value> =
                map.iter().map(|(k, v)| (k, canonical(v))).collect();
            Value::Object(sorted.into_iter().map(|(k, v)| (k.clone(), v)).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    fn write_three(path: &Path) {
        let log = AuditLog::open(path).unwrap();
        log.append("tool_call", json!({ "tool": "echo" })).unwrap();
        log.append("policy_decision", json!({ "effect": "allow" }))
            .unwrap();
        log.append("secret_injected", json!({ "name": "GITHUB_TOKEN" }))
            .unwrap();
    }

    #[test]
    fn empty_log_verifies_at_genesis() {
        let dir = tempdir().unwrap();
        let report = verify(&dir.path().join("missing.jsonl")).unwrap();
        assert_eq!(report.entries, 0);
        assert_eq!(report.head, GENESIS);
    }

    #[test]
    fn appended_entries_chain_and_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_three(&path);

        let report = verify(&path).unwrap();
        assert_eq!(report.entries, 3);
        assert_ne!(report.head, GENESIS);
    }

    #[test]
    fn reopening_continues_the_chain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_three(&path);

        let log = AuditLog::open(&path).unwrap();
        let entry = log.append("config_reload", json!({ "ok": true })).unwrap();
        assert_eq!(entry.seq, 3);
        assert_eq!(verify(&path).unwrap().entries, 4);
    }

    #[test]
    fn changed_data_is_detected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_three(&path);

        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replacen("\"echo\"", "\"rm\"", 1);
        std::fs::write(&path, tampered).unwrap();

        match verify(&path) {
            Err(AuditError::Broken { seq: 0, reason }) => {
                assert_eq!(reason, "entry hash does not match its contents");
            }
            other => panic!("expected broken entry 0, got {other:?}"),
        }
    }

    #[test]
    fn deleted_middle_entry_breaks_the_link() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_three(&path);

        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();

        assert!(matches!(
            verify(&path),
            Err(AuditError::Broken { seq: 2, .. })
        ));
    }

    #[test]
    fn open_refuses_a_broken_log() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_three(&path);

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replacen("\"allow\"", "\"deny\"", 1)).unwrap();

        assert!(matches!(
            AuditLog::open(&path),
            Err(AuditError::Broken { .. })
        ));
    }

    #[test]
    fn hash_does_not_depend_on_object_key_order() {
        let a = compute_hash(0, 1, GENESIS, "k", &json!({ "a": 1, "b": 2 })).unwrap();
        let b = compute_hash(0, 1, GENESIS, "k", &json!({ "b": 2, "a": 1 })).unwrap();
        assert_eq!(a, b);
    }
}

#[cfg(test)]
mod lock_tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn second_writer_is_refused_until_the_first_is_dropped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let first = AuditLog::open(&path).unwrap();
        assert!(matches!(
            AuditLog::open(&path),
            Err(AuditError::Locked { .. })
        ));

        drop(first);
        assert!(AuditLog::open(&path).is_ok());
    }

    #[test]
    fn lock_file_is_removed_on_drop() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        assert!(dir.path().join("audit.jsonl.lock").exists());
        drop(log);
        assert!(!dir.path().join("audit.jsonl.lock").exists());
    }
}
