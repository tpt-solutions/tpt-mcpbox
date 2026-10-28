// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The WASI capability mapper.
//!
//! A tool's filesystem grants are globs, but WASI can only grant whole
//! directories. Each grant is therefore reduced to the fixed directory before its
//! first wildcard, and that directory is preopened. The guest sees it under a
//! relative name, never under its host path, so host layout does not leak.
//!
//! Precision caveat: a grant such as `workspace/*.md` preopens all of
//! `workspace/`, so the guest can reach files the glob does not name. Matching
//! within a preopened directory is not something WASI can express. The policy
//! engine still gates each call on its path, but a tool that bypasses the
//! policy layer is not stopped at the file level. This is recorded as a residual
//! risk in the security model.

use std::path::{Path, PathBuf};

use tpt_mcpbox_config::Capabilities;
use tpt_mcpbox_policy::normalize::normalize_path;
use wasmtime_wasi::{FsPerms, WasiCtx, WasiCtxBuilder};

use crate::error::ToolError;

/// Characters that make a path segment a pattern rather than a name.
const GLOB_META: &[char] = &['*', '?', '[', ']', '{', '}'];

/// One directory the guest may see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Preopen {
    /// Canonical host directory.
    pub(crate) host: PathBuf,
    /// Name the guest sees, relative and free of host layout.
    pub(crate) guest: String,
    /// Whether the guest may write into it.
    pub(crate) writable: bool,
}

/// Everything a sandbox is built from. Cheap to clone, so every pooled instance
/// gets its own `WasiCtx` built from the same plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WasiPlan {
    pub(crate) preopens: Vec<Preopen>,
    pub(crate) env: Vec<(String, String)>,
}

/// Turn a tool's capabilities into a sandbox plan, resolving grants against
/// `base`.
///
/// # Errors
///
/// Returns [`ToolError::InvalidConfig`] when a grant names no fixed directory,
/// when a granted directory does not exist, or when two grants collide on a guest
/// name.
pub(crate) fn plan(tool: &str, caps: &Capabilities, base: &Path) -> Result<WasiPlan, ToolError> {
    let invalid = |message: String| ToolError::InvalidConfig {
        tool: tool.to_owned(),
        message,
    };

    // guest name -> (host directory, writable)
    let mut grants: Vec<(String, PathBuf, bool)> = Vec::new();
    let mut add = |glob: &str, writable: bool| -> Result<(), ToolError> {
        let fixed = fixed_directory(glob).ok_or_else(|| {
            invalid(format!(
                "filesystem grant `{glob}` names no fixed directory"
            ))
        })?;
        // The preopen is the whole fixed directory, so a write grant with any
        // wildcard other than a trailing `/**` would make all of it writable
        // (SR-11). Such a grant is refused rather than widened silently.
        if writable && !is_directory_tree(glob) {
            return Err(invalid(format!(
                "write grant `{glob}` would make all of `{fixed}` writable; use a directory, or `{fixed}/**`"
            )));
        }
        let host = base.join(&fixed);
        let host = std::fs::canonicalize(&host).map_err(|e| {
            invalid(format!(
                "filesystem grant `{glob}` points at {}, which cannot be opened: {e}",
                host.display()
            ))
        })?;
        if !host.is_dir() {
            return Err(invalid(format!(
                "filesystem grant `{glob}` must name a directory, and {} is not one",
                host.display()
            )));
        }
        grants.push((guest_name(&fixed), host, writable));
        Ok(())
    };
    for glob in &caps.filesystem.read {
        add(glob, false)?;
    }
    for glob in &caps.filesystem.write {
        add(glob, true)?;
    }

    // One preopen per guest name. A write grant upgrades a read grant on the same
    // directory.
    let mut preopens: Vec<Preopen> = Vec::new();
    for (guest, host, writable) in grants {
        match preopens.iter_mut().find(|p| p.guest == guest) {
            Some(existing) if existing.host != host => {
                return Err(invalid(format!(
                    "filesystem grants collide on guest name `{guest}`"
                )));
            }
            Some(existing) => existing.writable |= writable,
            None => preopens.push(Preopen {
                host,
                guest,
                writable,
            }),
        }
    }
    preopens.sort_by(|a, b| a.guest.cmp(&b.guest));

    let env = caps
        .env
        .iter()
        .filter_map(|name| std::env::var(name).ok().map(|value| (name.clone(), value)))
        .collect();

    Ok(WasiPlan { preopens, env })
}

/// Build a fresh `WasiCtx` from a plan.
///
/// The context has no inherited stdio, no arguments, no environment beyond the
/// plan, and no raw sockets. Name lookup is off, because name resolution for
/// outbound HTTP happens in the host's `wasi:http` handler, where the allowlist
/// applies.
pub(crate) fn build_ctx(tool: &str, plan: &WasiPlan) -> Result<WasiCtx, ToolError> {
    let mut builder = WasiCtxBuilder::new();
    builder
        .allow_tcp(false)
        .allow_udp(false)
        .allow_ip_name_lookup(false);
    for (name, value) in &plan.env {
        builder.env(name, value);
    }
    for preopen in &plan.preopens {
        let perms = if preopen.writable {
            FsPerms::ReadWrite
        } else {
            FsPerms::ReadOnly
        };
        builder
            .preopened_dir(&preopen.host, &preopen.guest, perms)
            .map_err(|e| ToolError::InvalidConfig {
                tool: tool.to_owned(),
                message: format!("cannot preopen {}: {e}", preopen.host.display()),
            })?;
    }
    Ok(builder.build())
}

/// `true` when a glob names a directory and everything under it: no wildcard
/// before the trailing `/**`, or no wildcard at all.
fn is_directory_tree(glob: &str) -> bool {
    let Some(normalised) = normalize_path(glob) else {
        return false;
    };
    let stem = normalised.strip_suffix("/**").unwrap_or(&normalised);
    !stem.contains(GLOB_META)
}

/// The fixed directory a glob names: its segments before the first wildcard.
/// `None` when nothing is fixed, as with `**/*.md` or `./*`, because that would
/// grant the whole working directory.
pub(crate) fn fixed_directory(glob: &str) -> Option<String> {
    let normalised = normalize_path(glob)?;
    let mut fixed = Vec::new();
    for segment in normalised.split('/') {
        if segment.contains(GLOB_META) {
            break;
        }
        if !segment.is_empty() {
            fixed.push(segment);
        }
    }
    let joined = fixed.join("/");
    if joined.is_empty() || joined == "." {
        return None;
    }
    // A leading `/` in the normalised path makes the join absolute, which is what
    // the operator wrote.
    Some(if normalised.starts_with('/') {
        format!("/{joined}")
    } else {
        joined
    })
}

/// A guest-facing name for a fixed directory: relative, alphanumeric and
/// underscores only.
fn guest_name(fixed: &str) -> String {
    let trimmed = fixed.trim_start_matches('/');
    let name: String = trimmed
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if name.is_empty() {
        "root".to_owned()
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]

    use super::*;

    fn caps(read: &[&str], write: &[&str]) -> Capabilities {
        let mut caps = Capabilities::default();
        caps.filesystem.read = read.iter().map(|s| (*s).to_owned()).collect();
        caps.filesystem.write = write.iter().map(|s| (*s).to_owned()).collect();
        caps
    }

    #[test]
    fn fixed_directory_stops_at_the_first_wildcard() {
        assert_eq!(
            fixed_directory("./workspace/**").as_deref(),
            Some("workspace")
        );
        assert_eq!(
            fixed_directory("workspace/a/*.md").as_deref(),
            Some("workspace/a")
        );
        assert_eq!(
            fixed_directory("workspace/out").as_deref(),
            Some("workspace/out")
        );
    }

    #[test]
    fn write_grants_must_be_a_directory_tree() {
        assert!(is_directory_tree("workspace/output/**"));
        assert!(is_directory_tree("workspace/output"));
        assert!(is_directory_tree("workspace/**"));
        assert!(!is_directory_tree("workspace/*.log"));
        assert!(!is_directory_tree("workspace/**/*.md"));
        assert!(!is_directory_tree("**"));
    }

    #[test]
    fn grants_without_a_fixed_directory_are_refused() {
        assert_eq!(fixed_directory("**/*.md"), None);
        assert_eq!(fixed_directory("./*"), None);
        assert_eq!(fixed_directory("../escape/**"), None);
    }

    #[test]
    fn guest_names_hide_host_layout() {
        assert_eq!(guest_name("workspace/output"), "workspace_output");
        assert_eq!(guest_name("/etc"), "etc");
        assert_eq!(guest_name("C:/data"), "C__data");
    }

    #[test]
    fn read_and_write_grants_become_preopens_with_the_write_upgrade() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir_all(dir.path().join("workspace/output")).expect("mkdir");
        let plan = plan(
            "fs",
            &caps(&["./workspace/**"], &["workspace/output/**"]),
            dir.path(),
        )
        .expect("plans");

        assert_eq!(plan.preopens.len(), 2);
        let read = plan
            .preopens
            .iter()
            .find(|p| p.guest == "workspace")
            .expect("read");
        assert!(!read.writable);
        let write = plan
            .preopens
            .iter()
            .find(|p| p.guest == "workspace_output")
            .expect("write");
        assert!(write.writable);
    }

    #[test]
    fn a_grant_on_a_missing_directory_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let result = plan("fs", &caps(&["nowhere/**"], &[]), dir.path());
        assert!(matches!(result, Err(ToolError::InvalidConfig { .. })));
    }

    #[test]
    fn a_grant_on_a_file_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("file.txt"), b"x").expect("write");
        let result = plan("fs", &caps(&["file.txt"], &[]), dir.path());
        assert!(matches!(result, Err(ToolError::InvalidConfig { .. })));
    }

    #[test]
    fn only_granted_environment_variables_are_planned() {
        let mut caps = Capabilities::default();
        caps.env = vec!["TPT_TEST_SURELY_UNSET_VAR".to_owned()];
        let dir = tempfile::tempdir().expect("temp dir");
        let plan = plan("env", &caps, dir.path()).expect("plans");
        assert!(plan.env.is_empty(), "unset variables are not exposed");
        assert!(plan.preopens.is_empty());
    }

    #[test]
    fn the_context_builds_from_a_plan() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir_all(dir.path().join("workspace")).expect("mkdir");
        let plan = plan("fs", &caps(&["workspace"], &[]), dir.path()).expect("plans");
        assert!(build_ctx("fs", &plan).is_ok());
    }
}
