// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Hot reload: watch the configuration file and swap it atomically.
//!
//! Reload safety is the point of this module, so the design is deliberately
//! boring:
//!
//! * **Polling, not filesystem events.** `notify`-style watchers behave
//!   differently on every platform and fail silently on network drives. Polling
//!   one file's modification time and size is portable and sufficient for a file
//!   that changes a few times a day.
//! * **Validate before swap.** A broken edit never replaces a working config:
//!   the previous one stays in force and the reason is reported.
//! * **Atomic swap.** Readers clone an `Arc`, so an in-flight request keeps the
//!   configuration it started with.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::watch;

use crate::load::{self, LoadError, LoadedConfig};
use crate::model::Config;
use crate::validate::{self, ValidationMode, ValidationReport};

/// Filesystem fingerprint used to detect edits.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    /// Last modification time, when the platform reports one.
    modified: Option<SystemTime>,
    /// File length in bytes; catches same-timestamp rewrites on coarse clocks.
    len: u64,
}

fn fingerprint(path: &Path) -> Fingerprint {
    match std::fs::metadata(path) {
        Ok(metadata) => Fingerprint {
            modified: metadata.modified().ok(),
            len: metadata.len(),
        },
        Err(_) => Fingerprint {
            modified: None,
            len: 0,
        },
    }
}

/// Why a reload was rejected.
///
/// Not `Clone`: a `LoadError` carries an I/O and a YAML error, and cloning them
/// would only be used to paper over a missed decision.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// The new document did not parse.
    #[error(transparent)]
    Load(#[from] LoadError),
    /// The document parsed but failed validation; the previous configuration
    /// stays in force.
    #[error("rejected: the new configuration has validation errors:\n{report}")]
    Invalid {
        /// Rendered validation report.
        report: String,
    },
}

/// Why the watcher woke up.
#[derive(Debug)]
pub enum ReloadEvent {
    /// The file changed and the new configuration is now in force.
    Reloaded,
    /// The file changed but the new configuration was rejected.
    Rejected(ReloadError),
}

impl ReloadEvent {
    /// Summary of this outcome, safe to store and compare.
    #[must_use]
    pub fn status(&self) -> ReloadStatus {
        match self {
            Self::Reloaded => ReloadStatus::Reloaded,
            Self::Rejected(error) => ReloadStatus::Rejected(error.to_string()),
        }
    }
}

/// A configuration snapshot plus the path it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigSnapshot {
    /// The validated configuration.
    pub config: Config,
    /// File it was loaded from.
    pub path: PathBuf,
    /// When this snapshot became current (informational).
    pub loaded_at: SystemTime,
}

/// A redaction-friendly view of the last reload outcome.
///
/// The full [`ReloadEvent`] carries an error type that is deliberately not
/// `Clone`, so handles expose this summary for comparisons and logging while
/// [`ReloadHandle::changed`] still hands over the real thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadStatus {
    /// Nothing has been reloaded yet; the initial config is in force.
    Initial,
    /// A new configuration is in force.
    Reloaded,
    /// The last edit was rejected; the previous configuration stands.
    Rejected(String),
}

impl ReloadStatus {
    /// `true` when a new configuration is in force.
    #[must_use]
    pub fn is_reloaded(&self) -> bool {
        matches!(self, Self::Reloaded)
    }

    /// `true` when the last edit was rejected.
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected(_))
    }
}

/// Handle to the live configuration.
#[derive(Debug, Clone)]
pub struct ReloadHandle {
    receiver: watch::Receiver<Arc<ConfigSnapshot>>,
    events: watch::Receiver<ReloadEvent>,
}

impl ReloadHandle {
    /// Current snapshot; cheap, because it clones an `Arc`.
    pub fn snapshot(&self) -> Arc<ConfigSnapshot> {
        self.receiver.borrow().clone()
    }

    /// Summary of the most recent reload outcome.
    #[must_use]
    pub fn status(&self) -> ReloadStatus {
        match &*self.events.borrow() {
            ReloadEvent::Reloaded => ReloadStatus::Reloaded,
            ReloadEvent::Rejected(error) => ReloadStatus::Rejected(error.to_string()),
        }
    }

    /// Wait for the next reload outcome.
    ///
    /// # Errors
    /// Returns [`watch::error::RecvError`] when the watcher stopped.
    pub async fn changed(&mut self) -> Result<ReloadEvent, watch::error::RecvError> {
        self.events
            .changed()
            .await
            .map(|()| match &*self.events.borrow() {
                ReloadEvent::Reloaded => ReloadEvent::Reloaded,
                ReloadEvent::Rejected(error) => ReloadEvent::Rejected(ReloadError::Invalid {
                    report: error.to_string(),
                }),
            })
    }

    /// Subscribe to reload outcomes.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<ReloadEvent> {
        self.events.clone()
    }

    /// Diagnostics for the current snapshot, recomputed on demand so a caller
    /// never sees a report for a document it did not read.
    pub async fn report(&self, mode: ValidationMode) -> ValidationReport {
        validate::validate(&self.snapshot().config, mode)
    }
}

/// Start watching `path`.
///
/// The initial configuration is loaded and validated once, so a caller always
/// receives a handle whose snapshot is usable.
///
/// # Errors
/// Propagates [`ReloadError`] when the initial load or validation fails.
pub async fn watch_config(
    path: impl Into<PathBuf>,
    mode: ValidationMode,
    poll_interval: Duration,
) -> Result<ReloadHandle, ReloadError> {
    let path = path.into();
    let loaded: LoadedConfig = load::load_file(&path)?;
    let report = validate::validate(&loaded.config, mode);
    if report.has_errors() {
        return Err(ReloadError::Invalid {
            report: report.to_string(),
        });
    }

    let snapshot = Arc::new(ConfigSnapshot {
        config: loaded.config,
        path: loaded.path.clone(),
        loaded_at: SystemTime::now(),
    });
    let (config_tx, config_rx) = watch::channel(snapshot);
    let (event_tx, event_rx) = watch::channel(ReloadEvent::Reloaded);

    // Both the primary file and the overlay are watched, whether or not the
    // overlay exists yet: a missing file fingerprints as (None, 0), so creating
    // it is a detectable change.
    let watched: Vec<PathBuf> = vec![
        loaded.path.clone(),
        loaded.path.with_file_name(load::LOCAL_CONFIG_FILENAME),
    ];
    let mut fingerprints: Vec<Fingerprint> = watched.iter().map(|file| fingerprint(file)).collect();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;

            let current: Vec<Fingerprint> = watched.iter().map(|file| fingerprint(file)).collect();
            if current == fingerprints {
                continue;
            }
            // Accept the change into the fingerprint set either way: on
            // rejection we retry only when the file changes again, rather than
            // spinning on a permanently broken document.
            fingerprints = current;

            let outcome = match load::load_file(&path) {
                Ok(loaded) => {
                    let report = validate::validate(&loaded.config, mode);
                    if report.has_errors() {
                        Err(ReloadError::Invalid {
                            report: report.to_string(),
                        })
                    } else {
                        Ok(loaded)
                    }
                }
                Err(error) => Err(ReloadError::Load(error)),
            };

            match outcome {
                Ok(loaded) => {
                    let snapshot = Arc::new(ConfigSnapshot {
                        config: loaded.config,
                        path: loaded.path,
                        loaded_at: SystemTime::now(),
                    });
                    if config_tx.send(snapshot).is_err() {
                        // Every handle was dropped: nothing left to notify.
                        return;
                    }
                    let _ = event_tx.send(ReloadEvent::Reloaded);
                }
                Err(error) => {
                    tracing::warn!(%error, "configuration reload rejected; keeping the previous config");
                    let _ = event_tx.send(ReloadEvent::Rejected(error));
                }
            }
        }
    });

    Ok(ReloadHandle {
        receiver: config_rx,
        events: event_rx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "tools:\n  - name: first\n    wasm_path: a.wasm\n";
    const VALID_UPDATED: &str = "tools:\n  - name: second\n    wasm_path: b.wasm\n";
    const INVALID: &str = "tools:\n  - name: broken\n";

    async fn settle(handle: &mut ReloadHandle, predicate: impl Fn(&Config) -> bool) -> bool {
        for _ in 0..200 {
            if predicate(&handle.snapshot().config) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    #[tokio::test]
    async fn the_initial_snapshot_is_validated_and_usable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tpt-mcpbox.yaml");
        std::fs::write(&path, VALID).expect("write");

        let handle = watch_config(&path, ValidationMode::Serve, Duration::from_millis(20))
            .await
            .expect("starts");
        assert_eq!(handle.snapshot().config.tools[0].name, "first");
        assert!(handle.status().is_reloaded());
    }

    #[tokio::test]
    async fn an_invalid_initial_config_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tpt-mcpbox.yaml");
        std::fs::write(&path, INVALID).expect("write");

        let error = watch_config(&path, ValidationMode::Serve, Duration::from_millis(20))
            .await
            .expect_err("must refuse");
        assert!(matches!(error, ReloadError::Invalid { .. }));
    }

    #[tokio::test]
    async fn a_good_edit_is_swapped_in() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tpt-mcpbox.yaml");
        std::fs::write(&path, VALID).expect("write");

        let mut handle = watch_config(&path, ValidationMode::Serve, Duration::from_millis(20))
            .await
            .expect("starts");

        tokio::time::sleep(Duration::from_millis(30)).await;
        std::fs::write(&path, VALID_UPDATED).expect("write");

        let swapped = settle(&mut handle, |config| config.tools[0].name == "second").await;
        assert!(swapped, "configuration was not reloaded");
    }

    #[tokio::test]
    async fn a_bad_edit_keeps_the_previous_config_in_force() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tpt-mcpbox.yaml");
        std::fs::write(&path, VALID).expect("write");

        let handle = watch_config(&path, ValidationMode::Serve, Duration::from_millis(20))
            .await
            .expect("starts");

        tokio::time::sleep(Duration::from_millis(30)).await;
        std::fs::write(&path, INVALID).expect("write");

        // Give the watcher time to observe and reject the edit.
        for _ in 0..40 {
            if handle.status().is_rejected() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert!(
            handle.status().is_rejected(),
            "unexpected event: {:?}",
            handle.status()
        );
        assert_eq!(
            handle.snapshot().config.tools[0].name,
            "first",
            "the previous configuration must stay in force"
        );
    }

    #[tokio::test]
    async fn an_overlay_appearing_triggers_a_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tpt-mcpbox.yaml");
        std::fs::write(&path, VALID).expect("write");

        let mut handle = watch_config(&path, ValidationMode::Serve, Duration::from_millis(20))
            .await
            .expect("starts");
        assert_eq!(handle.snapshot().config.tools.len(), 1);

        std::fs::write(
            dir.path().join("tpt-mcpbox.local.yaml"),
            "tools:\n  - name: extra\n    wasm_path: c.wasm\n",
        )
        .expect("write");

        assert!(
            settle(&mut handle, |config| config.tools.len() == 2).await,
            "overlay change was not picked up"
        );
    }

    #[test]
    fn a_missing_file_fingerprints_consistently() {
        let missing = fingerprint(Path::new("/definitely/not/here.yaml"));
        assert_eq!(
            missing,
            Fingerprint {
                modified: None,
                len: 0
            }
        );
        assert_eq!(missing, fingerprint(Path::new("/definitely/not/here.yaml")));
    }

    #[test]
    fn reload_errors_render_usefully() {
        let error = ReloadError::Invalid {
            report: "error: tools[0].name: duplicate tool name `a`".to_owned(),
        };
        assert!(error.to_string().contains("duplicate tool name"));
    }
}
