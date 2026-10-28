// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Hash-chained, append-only audit log.
//!
//! The file holds one JSON object per line. Each entry's `hash` is the SHA-256
//! of its own fields together with the previous entry's hash, so changing,
//! removing or reordering any entry breaks every hash after it. The first
//! entry chains from [`GENESIS`].
//!
//! Keying: by default the hash is plain SHA-256, so anyone who can write the
//! file can recompute the whole chain. With a key ([`AuditLog::open_keyed`]) each
//! hash is HMAC-SHA256 under that key, and rebuilding the chain needs the key
//! too (SR-24). A keyed log cannot be verified without its key, and an unkeyed
//! one cannot be opened with one.
//!
//! Limits: a truncation of the newest entries leaves a valid shorter chain and
//! is not detected here. Detecting it needs the head hash recorded somewhere
//! else, which is a later step.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

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
    /// Another process holds the log's lock.
    #[error("audit log is in use by another process (lock file {path})")]
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

/// Exclusive OS-level lock on a log file, held for the life of the `AuditLog`.
///
/// Two writers on one file would interleave entries and break the chain, so a
/// second `open` is refused while the first holds the lock. The lock belongs to
/// the open file handle, so the operating system releases it when the process
/// exits for any reason, including a kill. The lock file itself is left in
/// place: its presence means nothing, only the lock does.
#[derive(Debug)]
struct LockFile {
    // Held, not read: dropping the handle releases the lock.
    _file: File,
}

impl LockFile {
    fn acquire(log: &Path) -> Result<Self, AuditError> {
        let mut name = log.as_os_str().to_owned();
        name.push(".lock");
        let path = PathBuf::from(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => {
                // The PID is only a hint for whoever inspects the file.
                let mut file = file;
                file.set_len(0)?;
                let _ = writeln!(file, "{}", std::process::id());
                Ok(Self { _file: file })
            }
            Err(fs4::TryLockError::WouldBlock) => Err(AuditError::Locked {
                path: path.display().to_string(),
            }),
            Err(fs4::TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

#[derive(Debug)]
struct Head {
    /// The live file. `None` only while a rotation has it closed, which Windows
    /// requires before the file can be renamed.
    file: Option<File>,
    next_seq: u64,
    prev: String,
    /// The key the chain is hashed under, or `None` for plain SHA-256.
    key: Option<Vec<u8>>,
    /// Roll to a new segment before the live file would exceed this many bytes.
    max_segment_bytes: Option<u64>,
}

impl Head {
    /// Whether `incoming` more bytes would push the live file past the limit. A
    /// file that is still empty is never rolled, so one oversized entry is
    /// written whole rather than looping.
    fn needs_rotation(&self, incoming: usize) -> Result<bool, AuditError> {
        let Some(max) = self.max_segment_bytes else {
            return Ok(false);
        };
        let file = self.file.as_ref().ok_or_else(closed)?;
        let len = file.metadata()?.len();
        Ok(len > 0 && len.saturating_add(incoming as u64) > max)
    }

    /// Closes the live file, renames it to the next numbered segment, and opens
    /// a fresh live file. The chain carries on: the next entry links to the last
    /// entry of the segment just closed.
    fn rotate(&mut self, path: &Path) -> Result<(), AuditError> {
        // Dropping the handle is what lets the rename happen on Windows.
        drop(self.file.take());
        let segment = segment_path(path, next_segment_number(path)?);
        if let Err(error) = std::fs::rename(path, &segment) {
            // Keep logging to the live file rather than losing the handle.
            self.file = Some(open_append(path)?);
            return Err(error.into());
        }
        self.file = Some(open_append(path)?);
        Ok(())
    }
}

fn closed() -> AuditError {
    AuditError::Io(std::io::Error::other(
        "audit log has no open file after a failed rotation",
    ))
}

fn open_append(path: &Path) -> Result<File, AuditError> {
    Ok(OpenOptions::new().create(true).append(true).open(path)?)
}

/// `path` with `.N` appended: the segment file holding the Nth rolled-over part.
fn segment_path(path: &Path, number: u64) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{number}"));
    PathBuf::from(name)
}

/// The rolled-over segments of the log at `path`, in order, with their numbers.
/// Only files named `<log>.<digits>` count, so the lock file is never one.
fn segments(path: &Path) -> Result<Vec<(u64, PathBuf)>, AuditError> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let Some(stem) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let prefix = format!("{stem}.");
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(digits) = name.strip_prefix(&prefix) else {
            continue;
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(number) = digits.parse::<u64>() {
            found.push((number, entry.path()));
        }
    }
    found.sort_by_key(|(number, _)| *number);
    Ok(found)
}

fn next_segment_number(path: &Path) -> Result<u64, AuditError> {
    Ok(segments(path)?.last().map_or(1, |(number, _)| number + 1))
}

impl AuditLog {
    /// Opens or creates the log at `path`, hashed with plain SHA-256.
    ///
    /// The existing chain is verified first. A broken log is refused rather than
    /// extended, because new entries would sit on top of tampered history.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Broken`] when the existing chain does not verify,
    /// or an I/O error when the file cannot be opened.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditError> {
        Self::open_with(path.into(), None)
    }

    /// Opens or creates the log at `path`, hashed under `key` (HMAC-SHA256).
    ///
    /// # Errors
    ///
    /// As [`AuditLog::open`]. An unkeyed log, or one written under another key,
    /// is refused as broken.
    pub fn open_keyed(path: impl Into<PathBuf>, key: &[u8]) -> Result<Self, AuditError> {
        Self::open_with(path.into(), Some(key.to_vec()))
    }

    fn open_with(path: PathBuf, key: Option<Vec<u8>>) -> Result<Self, AuditError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        // Claim the log before reading it, so no other writer can change the
        // chain between verification and the first append.
        let lock = LockFile::acquire(&path)?;
        let report = verify_with(&path, key.as_deref())?;
        let file = open_append(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(Head {
                file: Some(file),
                next_seq: report.entries,
                prev: report.head,
                key,
                max_segment_bytes: None,
            }),
            _lock: lock,
        })
    }

    /// Path of the log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rolls the log into a numbered segment (`<path>.1`, `<path>.2`, ...) once
    /// the live file would grow past `bytes`. The chain runs across segments, and
    /// [`verify`] reads them all in order.
    #[must_use]
    pub fn with_max_segment_bytes(self, bytes: u64) -> Self {
        lock(&self.state).max_segment_bytes = Some(bytes);
        self
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
        let hash = compute_hash(
            head.key.as_deref(),
            head.next_seq,
            ts_ms,
            &head.prev,
            kind,
            &data,
        )?;
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
        if head.needs_rotation(line.len())? {
            head.rotate(&self.path)?;
        }
        let file = head.file.as_mut().ok_or_else(closed)?;
        let before = file.metadata()?.len();
        if let Err(error) = file
            .write_all(line.as_bytes())
            .and_then(|()| file.sync_data())
        {
            // Cut off whatever part of the line reached the file. Otherwise the
            // next start reads a torn entry and refuses the whole log (SR-20).
            // The head was not advanced, so the chain is unchanged.
            let _ = file.set_len(before);
            return Err(error.into());
        }

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
    verify_with(path, None)
}

/// Checks every entry in the log at `path` under `key`, as written by
/// [`AuditLog::open_keyed`].
///
/// # Errors
///
/// As [`verify`]. A log written without the key, or under another key, fails
/// at its first entry.
pub fn verify_keyed(path: &Path, key: &[u8]) -> Result<VerifyReport, AuditError> {
    verify_with(path, Some(key))
}

fn verify_with(path: &Path, key: Option<&[u8]>) -> Result<VerifyReport, AuditError> {
    // Segments in order, then the live file: one chain across all of them.
    let mut files: Vec<PathBuf> = segments(path)?.into_iter().map(|(_, file)| file).collect();
    if path.is_file() {
        files.push(path.to_path_buf());
    }
    let mut chained: Box<dyn std::io::Read> = Box::new(std::io::empty());
    for file in files {
        chained = Box::new(std::io::Read::chain(chained, File::open(file)?));
    }

    let mut expected_seq = 0u64;
    let mut prev = GENESIS.to_owned();
    for line in BufReader::new(chained).lines() {
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
            key,
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
    key: Option<&[u8]>,
    seq: u64,
    ts_ms: u64,
    prev: &str,
    kind: &str,
    data: &Value,
) -> Result<String, AuditError> {
    // Field order is fixed here, and `data` is hashed in canonical form, so the
    // digest never depends on how the caller built the JSON object.
    let mut message = Vec::new();
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(&ts_ms.to_be_bytes());
    message.extend_from_slice(prev.as_bytes());
    message.push(0u8);
    message.extend_from_slice(kind.as_bytes());
    message.push(0u8);
    message.extend_from_slice(&serde_json::to_vec(&canonical(data))?);
    let digest = match key {
        None => Sha256::digest(&message).to_vec(),
        Some(key) => {
            // HMAC accepts a key of any length, so this cannot fail.
            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
    };
    Ok(hex::encode(digest))
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
    fn a_keyed_log_verifies_only_under_its_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let log = AuditLog::open_keyed(&path, b"key-one").unwrap();
            log.append("tool_call", json!({ "tool": "echo" })).unwrap();
        }
        assert_eq!(verify_keyed(&path, b"key-one").unwrap().entries, 1);
        assert!(verify(&path).is_err(), "no key must not verify");
        assert!(
            verify_keyed(&path, b"other").is_err(),
            "wrong key must not verify"
        );
    }

    #[test]
    fn an_unkeyed_log_is_refused_when_opened_with_a_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_three(&path);
        assert!(matches!(
            AuditLog::open_keyed(&path, b"key"),
            Err(AuditError::Broken { .. })
        ));
    }

    #[test]
    fn rebuilding_the_chain_without_the_key_is_detected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let log = AuditLog::open_keyed(&path, b"key").unwrap();
            log.append("tool_call", json!({ "tool": "echo" })).unwrap();
            log.append("policy_decision", json!({ "effect": "allow" }))
                .unwrap();
        }

        // Forge the first entry and rebuild every hash with plain SHA-256, as an
        // editor without the key could.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut entries: Vec<Entry> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        entries[0].data = json!({ "tool": "forged" });
        let mut prev = GENESIS.to_owned();
        for entry in &mut entries {
            entry.prev = prev.clone();
            entry.hash = compute_hash(
                None,
                entry.seq,
                entry.ts_ms,
                &entry.prev,
                &entry.kind,
                &entry.data,
            )
            .unwrap();
            prev = entry.hash.clone();
        }
        let forged: String = entries
            .iter()
            .map(|entry| {
                serde_json::to_string(entry).unwrap()
                    + "
"
            })
            .collect();
        std::fs::write(&path, forged).unwrap();

        assert!(
            verify(&path).is_ok(),
            "the plain rebuild is self-consistent"
        );
        assert!(matches!(
            verify_keyed(&path, b"key"),
            Err(AuditError::Broken { seq: 0, .. })
        ));
    }

    #[test]
    fn rolled_segments_verify_as_one_chain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let log = AuditLog::open(&path).unwrap().with_max_segment_bytes(300);
            for n in 0..12 {
                log.append("tool_call", json!({ "n": n })).unwrap();
            }
        }
        assert!(
            segment_path(&path, 1).is_file(),
            "the first segment is rolled"
        );
        assert_eq!(verify(&path).unwrap().entries, 12);

        // Reopening continues the chain in the live file.
        {
            let log = AuditLog::open(&path).unwrap().with_max_segment_bytes(300);
            log.append("tool_call", json!({ "n": 12 })).unwrap();
        }
        assert_eq!(verify(&path).unwrap().entries, 13);
    }

    #[test]
    fn a_tampered_rolled_segment_is_detected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let log = AuditLog::open(&path).unwrap().with_max_segment_bytes(300);
            for n in 0..12 {
                log.append("tool_call", json!({ "tool": format!("t{n}") }))
                    .unwrap();
            }
        }
        let first = segment_path(&path, 1);
        let text = std::fs::read_to_string(&first).unwrap();
        std::fs::write(&first, text.replace("t0", "rm")).unwrap();
        assert!(matches!(verify(&path), Err(AuditError::Broken { .. })));
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
        let a = compute_hash(None, 0, 1, GENESIS, "k", &json!({ "a": 1, "b": 2 })).unwrap();
        let b = compute_hash(None, 0, 1, GENESIS, "k", &json!({ "b": 2, "a": 1 })).unwrap();
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
    fn leftover_lock_file_without_a_holder_does_not_block_open() {
        // A crashed process leaves the file behind but no lock. Only the lock
        // counts, so the next start must succeed.
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(dir.path().join("audit.jsonl.lock"), "99999\n").unwrap();
        assert!(AuditLog::open(&path).is_ok());
    }
}
