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
    // Only ASCII is trimmed: a Unicode space or look-alike must not be quietly
    // stripped into a name that then matches an allow rule.
    let host = raw
        .trim_matches(|c: char| c.is_ascii_whitespace())
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    // Non-ASCII is refused outright. Internationalised names must be written in
    // their punycode (`xn--`) form, so that what the policy compares is what the
    // resolver will see.
    // Only letters, digits, `-`, `_` and `.` survive. Anything else (userinfo,
    // ports, paths, percent-encoding, IPv6 brackets, wildcards) is refused
    // rather than guessed at.
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    if !host.chars().all(allowed) || host.starts_with('.') || host.contains("..") {
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

/// Normalise a resource URI for glob matching.
///
/// Only `scheme://authority/path` URIs are accepted. The scheme and authority
/// are lowercased and the path is normalised as a filesystem path. Anything that
/// could make a URI name a different resource from the one it appears to name is
/// refused: percent-encoding (which could hide `..`), a query, a fragment, a
/// backslash in the authority, and a `..` that climbs out of the path.
#[must_use]
pub(crate) fn normalize_uri(raw: &str) -> Option<String> {
    if raw.contains(['%', '?', '#']) {
        return None;
    }
    let (scheme, rest) = raw.split_once("://")?;
    let scheme_ok = !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !scheme_ok {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    if authority.contains('\\') {
        return None;
    }
    let path = if path.is_empty() {
        String::new()
    } else {
        normalize_path(path)?
    };
    Some(format!(
        "{}://{}/{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase(),
        path.trim_start_matches('/'),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris_normalise_scheme_authority_and_dot_segments() {
        assert_eq!(
            normalize_uri("FILE://Host/srv/./docs//a.md").as_deref(),
            Some("file://host/srv/docs/a.md")
        );
        assert_eq!(
            normalize_uri("file:///srv/docs/sub/../a.md").as_deref(),
            Some("file:///srv/docs/a.md")
        );
    }

    #[test]
    fn dot_dot_in_a_uri_resolves_to_the_real_target() {
        // The resolved URI names what the request really reaches, so a rule for
        // the original tree cannot match it.
        assert_eq!(
            normalize_uri("file:///srv/docs/../../etc/passwd").as_deref(),
            Some("file:///etc/passwd")
        );
    }

    #[test]
    fn uris_that_could_hide_their_target_are_refused() {
        for bad in [
            "file:///srv/docs/%2e%2e/secret",
            "file:///srv/docs/a.md?x=1",
            "file:///srv/docs/a.md#frag",
            "file://evil\\host/x",
            "no-scheme/path",
            "://nothing",
            "",
        ] {
            assert_eq!(normalize_uri(bad), None, "{bad:?} should be refused");
        }
    }

    #[test]
    fn unicode_lookalike_hosts_are_refused() {
        for bad in [
            "ex\u{0430}mple.com",    // Cyrillic a
            "example\u{3002}com",    // ideographic full stop
            "example\u{FF0E}com",    // fullwidth full stop
            "\u{FF41}pi.github.com", // fullwidth a
            "example.com\u{200B}",   // zero-width space
        ] {
            assert_eq!(normalize_host(bad), None, "{bad:?} should be refused");
        }
    }

    /// Deterministic pseudo-random strings over an alphabet of separators and
    /// look-alikes. The normalisers must never hand back something that still
    /// carries an authority or traversal character.
    #[test]
    fn generated_inputs_never_yield_smuggling_characters() {
        const ALPHABET: &[char] = &[
            'a', 'b', 'z', '.', '/', '\\', ':', '@', '%', '?', '#', ' ', '*', '\u{0430}',
            '\u{FF0E}', '\0',
        ];
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..5_000 {
            let len = (next() % 12) as usize + 1;
            let raw: String = (0..len)
                .map(|_| ALPHABET[(next() % ALPHABET.len() as u64) as usize])
                .collect();

            if let Some(host) = normalize_host(&raw) {
                assert!(
                    !host.contains(['/', '\\', ':', '@', '%', '?', '#', '*', ' ']),
                    "host {raw:?} normalised to {host:?}"
                );
                assert!(
                    host.is_ascii(),
                    "host {raw:?} normalised to non-ASCII {host:?}"
                );
            }
            if let Some(path) = normalize_path(&raw) {
                assert!(
                    !path.contains('\\'),
                    "path {raw:?} kept a backslash: {path:?}"
                );
                assert!(
                    !path.split('/').any(|segment| segment == ".."),
                    "path {raw:?} kept a `..` segment: {path:?}"
                );
            }
            if let Some(uri) = normalize_uri(&raw) {
                assert!(
                    !uri.contains(['%', '?', '#']),
                    "uri {raw:?} normalised to {uri:?}"
                );
            }
        }
    }

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
