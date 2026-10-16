// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Canonicalisation of host names and filesystem paths before they are matched
//! against policy globs.
//!
//! Normalisation fails closed: an input that cannot be reduced to a single
//! unambiguous form yields `None`, and no `allow` rule that names hosts or paths
//! will match it.

/// Normalise a host name for allowlist matching.
///
/// Lowercases, strips a single trailing root dot, and rejects anything that is
/// not a bare DNS name. Ports, userinfo, paths, IPv6 literals and wildcards are
/// refused rather than guessed at, so `example.com:443@evil.test` can never be
/// read as `example.com`.
#[must_use]
pub(crate) fn normalize_host(raw: &str) -> Option<String> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let forbidden = |c: char| {
        c.is_control()
            || matches!(
                c,
                '/' | '\\' | '@' | ':' | '?' | '#' | '*' | ' ' | '[' | ']'
            )
    };
    if host.chars().any(forbidden) || host.starts_with('.') || host.contains("..") {
        return None;
    }
    Some(host)
}

/// Normalise a filesystem path for glob matching.
///
/// Backslashes become forward slashes, `.` and empty segments are dropped, and
/// `..` segments are resolved lexically. A `..` that would climb above the start
/// of the path (or above the root of an absolute path) returns `None`: such a
/// path is escaping whatever tree the policy was written for.
///
/// This does not touch the filesystem, so symlinks are not resolved here. The
/// runtime's preopen mapping is the layer that must enforce symlink containment.
#[must_use]
pub(crate) fn normalize_path(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.contains('\0') {
        return None;
    }
    let unified = raw.replace('\\', "/");
    let absolute = unified.starts_with('/');

    let mut parts: Vec<&str> = Vec::new();
    for segment in unified.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            name => parts.push(name),
        }
    }

    let joined = parts.join("/");
    if absolute {
        Some(format!("/{joined}"))
    } else if joined.is_empty() {
        Some(".".to_owned())
    } else {
        Some(joined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_lowercased_and_root_dot_stripped() {
        assert_eq!(
            normalize_host("API.GitHub.com.").as_deref(),
            Some("api.github.com")
        );
    }

    #[test]
    fn hosts_with_authority_tricks_are_refused() {
        for bad in [
            "example.com:443",
            "example.com@evil.test",
            "example.com/path",
            "*.example.com",
            "[::1]",
            "ex ample.com",
            "",
            ".",
            "a..b",
            ".leading.dot",
        ] {
            assert_eq!(normalize_host(bad), None, "{bad:?} should be refused");
        }
    }

    #[test]
    fn paths_collapse_dot_segments_and_separators() {
        assert_eq!(
            normalize_path("./workspace//notes/./a.txt").as_deref(),
            Some("workspace/notes/a.txt")
        );
        assert_eq!(
            normalize_path("workspace\\output\\x.bin").as_deref(),
            Some("workspace/output/x.bin")
        );
        assert_eq!(normalize_path("/etc/hosts").as_deref(), Some("/etc/hosts"));
        assert_eq!(normalize_path("./").as_deref(), Some("."));
    }

    #[test]
    fn dotdot_resolves_inside_the_tree() {
        assert_eq!(
            normalize_path("workspace/a/../b.txt").as_deref(),
            Some("workspace/b.txt")
        );
    }

    #[test]
    fn traversal_out_of_the_tree_is_refused() {
        for bad in [
            "../secret",
            "workspace/../../secret",
            "./../etc/passwd",
            "/../etc/passwd",
            "..\\..\\Windows",
            "a\0b",
            "",
        ] {
            assert_eq!(normalize_path(bad), None, "{bad:?} should be refused");
        }
    }
}
