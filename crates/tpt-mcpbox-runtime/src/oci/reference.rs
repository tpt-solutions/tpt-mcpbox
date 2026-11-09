// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Parsing of `oci://` references such as `oci://ghcr.io/org/tool:1.0` or
//! `oci://ghcr.io/org/tool@sha256:<64 hex>`.
//!
//! The registry must be named explicitly (a host with a dot or a port, or
//! `localhost`). There is no implicit Docker Hub default, so a reference never
//! silently points somewhere the operator did not write.

use std::fmt;

use super::OciError;

/// Longest tag accepted, per the OCI distribution spec.
const MAX_TAG_LEN: usize = 128;

/// A parsed reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Registry host, with a port when one is given (e.g. `ghcr.io`).
    pub registry: String,
    /// Repository path under the registry (e.g. `org/tool`).
    pub repository: String,
    /// Tag, when the reference names one. A reference with neither a tag nor a
    /// digest means `latest`.
    pub tag: Option<String>,
    /// Manifest digest, in `sha256:<64 lowercase hex>` form.
    pub digest: Option<String>,
}

impl Reference {
    /// Parse a reference, with or without the `oci://` prefix.
    ///
    /// # Errors
    ///
    /// Returns [`OciError::Reference`] for a missing or implicit registry, an
    /// invalid repository, tag or digest, or a scheme other than `oci://`.
    pub fn parse(input: &str) -> Result<Self, OciError> {
        let rest = match input.split_once("://") {
            Some(("oci", rest)) => rest,
            Some((scheme, _)) => {
                return Err(reference_error(
                    input,
                    &format!("unsupported scheme `{scheme}`"),
                ));
            }
            None => input,
        };

        let (name, digest) = match rest.split_once('@') {
            Some((name, digest)) => {
                validate_digest(digest).map_err(|m| reference_error(input, &m))?;
                (name, Some(digest.to_owned()))
            }
            None => (rest, None),
        };

        let (registry, path) = name
            .split_once('/')
            .ok_or_else(|| reference_error(input, "expected `<registry>/<repository>`"))?;
        if !is_registry(registry) {
            return Err(reference_error(
                input,
                "name the registry explicitly, e.g. `ghcr.io/org/tool`",
            ));
        }

        let (repository, tag) = match path.rsplit_once(':') {
            Some((repository, tag)) => {
                validate_tag(tag).map_err(|m| reference_error(input, &m))?;
                (repository, Some(tag.to_owned()))
            }
            None => (path, None),
        };
        validate_repository(repository).map_err(|m| reference_error(input, &m))?;

        let tag = if tag.is_none() && digest.is_none() {
            Some("latest".to_owned())
        } else {
            tag
        };
        Ok(Self {
            registry: registry.to_owned(),
            repository: repository.to_owned(),
            tag,
            digest,
        })
    }

    /// What the manifest is requested by: the digest when one is given,
    /// otherwise the tag.
    #[must_use]
    pub fn manifest_reference(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or("latest")
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "oci://{}/{}", self.registry, self.repository)?;
        if let Some(tag) = &self.tag {
            write!(f, ":{tag}")?;
        }
        if let Some(digest) = &self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

fn reference_error(input: &str, message: &str) -> OciError {
    OciError::Reference(format!("`{input}`: {message}"))
}

/// A registry is a host name with a dot or a port, or `localhost`.
fn is_registry(registry: &str) -> bool {
    let (host, port) = match registry.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (registry, None),
    };
    let host_ok = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !host.starts_with(['.', '-'])
        && (host.contains('.') || host == "localhost");
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    host_ok && port_ok
}

fn validate_repository(repository: &str) -> Result<(), String> {
    if repository.is_empty() || repository.len() > 255 {
        return Err("the repository name is empty or too long".to_owned());
    }
    for segment in repository.split('/') {
        let valid = !segment.is_empty()
            && segment.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
            })
            && !segment.starts_with(['.', '_', '-'])
            && !segment.ends_with(['.', '_', '-']);
        if !valid {
            return Err(format!(
                "invalid repository segment `{segment}` (lowercase letters, digits and `._-`)"
            ));
        }
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), String> {
    let valid = !tag.is_empty()
        && tag.len() <= MAX_TAG_LEN
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        && !tag.starts_with(['.', '-']);
    if valid {
        Ok(())
    } else {
        Err(format!("invalid tag `{tag}`"))
    }
}

/// Accepts `sha256:<64 lowercase hex>` only. Other algorithms are refused.
pub(crate) fn validate_digest(digest: &str) -> Result<(), String> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("digest `{digest}` must be `sha256:<hex>`"))?;
    if hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(format!("digest `{digest}` is not 64 lowercase hex digits"))
    }
}

#[cfg(test)]
mod tests {
    use super::Reference;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn tagged_references_parse() {
        let r = Reference::parse("oci://ghcr.io/tpt-solutions/mcpbox-fs:1.0").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "tpt-solutions/mcpbox-fs");
        assert_eq!(r.tag.as_deref(), Some("1.0"));
        assert_eq!(r.digest, None);
        assert_eq!(r.manifest_reference(), "1.0");
    }

    #[test]
    fn the_scheme_is_optional_and_a_missing_tag_means_latest() {
        let r = Reference::parse("localhost:5000/tools/fs").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.tag.as_deref(), Some("latest"));
    }

    #[test]
    fn digest_references_parse_and_round_trip() {
        let text = format!("oci://ghcr.io/org/tool@sha256:{HEX}");
        let r = Reference::parse(&text).unwrap();
        assert_eq!(r.digest.as_deref(), Some(format!("sha256:{HEX}").as_str()));
        assert_eq!(r.tag, None);
        assert_eq!(r.to_string(), text);
    }

    #[test]
    fn implicit_or_unknown_registries_are_refused() {
        assert!(Reference::parse("oci://tool:1").is_err());
        assert!(Reference::parse("oci://org/tool:1").is_err());
        assert!(Reference::parse("oci://Ghcr.io/org/tool:1").is_ok());
    }

    #[test]
    fn bad_repositories_tags_and_digests_are_refused() {
        for bad in [
            "oci://ghcr.io/Org/tool:1",
            "oci://ghcr.io/org/../tool:1",
            "oci://ghcr.io/org//tool:1",
            "oci://ghcr.io/org/tool:-x",
            "oci://ghcr.io/org/tool:bad tag",
            "oci://ghcr.io/org/tool@md5:abc",
            "oci://ghcr.io/org/tool@sha256:ABC",
            "https://ghcr.io/org/tool:1",
        ] {
            assert!(Reference::parse(bad).is_err(), "accepted `{bad}`");
        }
    }
}
