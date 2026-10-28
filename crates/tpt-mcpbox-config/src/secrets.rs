// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Secret material: zeroizing storage, environment/`.env` sources, outbound
//! header injection, and the central redaction filter.
//!
//! Rules enforced here (they are the reason this module exists):
//!
//! 1. A secret's *value* is never rendered. `Debug`, `Display` and
//!    serialization all emit `[redacted]`, so a secret cannot reach a log line,
//!    an audit entry or a panic message by accident.
//! 2. A secret is zeroized when it is dropped.
//! 3. A secret reaches an outbound header only, never the Wasm guest.
//! 4. [`Redactor`] scrubs known secret values out of arbitrary text (error
//!    messages, tool output) before it is logged.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::model::SecretBinding;

/// Placeholder substituted for any secret material.
pub const REDACTED: &str = "[redacted]";

/// A secret value that redacts itself and wipes its memory on drop.
///
/// Equality is deliberately not derived: use [`SecretString::constant_time_eq`]
/// so a secret is never compared by accident in a conditional or a test.
///
/// Serialization emits the redaction placeholder, never the value: a secret in
/// an audit payload, a `/metrics` label or a `Debug` dump is a leak, and this
/// makes that leak impossible rather than merely discouraged.
#[derive(Clone, Deserialize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap a value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Wrap a known-constant placeholder such as `[redacted]`.
    ///
    /// Lets format strings be built uniformly without branching on `Option`.
    #[must_use]
    pub fn placeholder() -> Self {
        Self(REDACTED.to_owned())
    }

    /// Borrow the value. Every call site is a place a leak could start.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and take the value, zeroizing the wrapper.
    #[must_use]
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }

    /// Compare without an early exit. Only useful for presence checks.
    #[must_use]
    pub fn constant_time_eq(&self, other: &str) -> bool {
        let (a, b) = (self.0.as_bytes(), other.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }

    /// Length of the secret, which is safe to log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` when the secret is the empty string.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for SecretString {
    /// Always emits the redaction placeholder.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

/// Where a secret value came from, for diagnostics and audit entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// Present in the proxy's own environment.
    ProcessEnv,
    /// Loaded from a gitignored `.env` file.
    DotEnv,
    /// Supplied directly by the caller (tests, [`SecretStore::insert`]).
    Injected,
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl SourceKind {
    /// Stable label used in diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProcessEnv => "process environment",
            Self::DotEnv => ".env file",
            Self::Injected => "injected",
        }
    }
}

/// Failure while resolving a secret.
///
/// The field is named `location` rather than `source`: thiserror treats a field
/// called `source` as the error cause, and a "where we looked" value is not one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    /// The referenced environment variable is not set.
    #[error("secret `{name}` is not set in the {location}")]
    Missing {
        /// Environment variable name.
        name: String,
        /// Where we looked.
        location: SourceKind,
    },
    /// The variable is set but empty.
    #[error("secret `{name}` in the {location} is empty")]
    Empty {
        /// Environment variable name.
        name: String,
        /// Where we looked.
        location: SourceKind,
    },
}

/// Resolution of secret values from the environment and `.env` files.
///
/// Values are fetched once and cached: a secret must not change mid-session,
/// because the audit log records that a specific value was injected.
#[derive(Debug, Default, Clone)]
pub struct SecretStore {
    values: HashMap<String, SecretString>,
    sources: HashMap<String, SourceKind>,
}

impl SecretStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a store from a process environment lookup.
    ///
    /// `lookup` receives a variable name and returns its value; tests pass a map
    /// instead of touching the real process environment.
    ///
    /// # Errors
    /// Propagates [`SecretError`] when a referenced variable is unset or empty.
    pub fn from_env_lookup(
        bindings: impl IntoIterator<Item = SecretBinding>,
        mut lookup: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, SecretError> {
        let mut store = Self::new();
        for binding in bindings {
            let value = lookup(&binding.env).ok_or_else(|| SecretError::Missing {
                name: binding.env.clone(),
                location: SourceKind::ProcessEnv,
            })?;
            if value.is_empty() {
                return Err(SecretError::Empty {
                    name: binding.env.clone(),
                    location: SourceKind::ProcessEnv,
                });
            }
            store.insert(binding.env.clone(), value, SourceKind::ProcessEnv);
        }
        Ok(store)
    }

    /// Build a store from the real process environment.
    ///
    /// # Errors
    /// Propagates [`SecretError`] when a referenced variable is unset or empty.
    pub fn from_process_env(
        bindings: impl IntoIterator<Item = SecretBinding>,
    ) -> Result<Self, SecretError> {
        Self::from_env_lookup(bindings, |name| std::env::var(name).ok())
    }

    /// Load a gitignored `.env` file, then resolve the bindings.
    ///
    /// Precedence: the process environment wins over `.env`, so an operator can
    /// always override a file without editing it.
    ///
    /// # Errors
    /// Propagates [`SecretError`] when a referenced variable is unset in both.
    pub fn from_dotenv_file(
        bindings: impl IntoIterator<Item = SecretBinding>,
        path: &Path,
    ) -> Result<Self, SecretError> {
        let file_values = read_dotenv(path);
        Self::from_env_lookup(bindings, |name| {
            std::env::var(name)
                .ok()
                .or_else(|| file_values.get(name).cloned())
        })
    }

    /// Add a value directly.
    pub fn insert(&mut self, name: impl Into<String>, value: String, source: SourceKind) {
        let name = name.into();
        self.sources.insert(name.clone(), source);
        self.values.insert(name, SecretString::new(value));
    }

    /// Fetch a secret.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SecretString> {
        self.values.get(name)
    }

    /// Where a secret came from.
    #[must_use]
    pub fn source_of(&self, name: &str) -> Option<SourceKind> {
        self.sources.get(name).copied()
    }

    /// Number of resolved secrets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// `true` when nothing was resolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Names of every resolved secret (never values).
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.values.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Build the outbound headers for a set of bindings.
    ///
    /// The returned map is the *only* place a secret value becomes a header.
    /// Values are prefixed when configured (`Authorization: Bearer <token>`).
    ///
    /// # Errors
    /// Returns [`MissingSecret`] for any binding whose secret is absent.
    pub fn headers_for(
        &self,
        bindings: &[SecretBinding],
    ) -> Result<BTreeMap<String, String>, MissingSecret> {
        let mut headers = BTreeMap::new();
        for binding in bindings {
            let secret = self.get(&binding.env).ok_or_else(|| MissingSecret {
                name: binding.env.clone(),
            })?;
            let value = match &binding.prefix {
                Some(prefix) => format!("{} {}", prefix, secret.expose()),
                None => secret.expose().to_owned(),
            };
            headers.insert(binding.header.clone(), value);
        }
        Ok(headers)
    }

    /// Resolves each binding on its own, keeping its host scope. Unlike
    /// [`SecretStore::headers_for`], two bindings for one header name both stay.
    ///
    /// # Errors
    /// Returns [`MissingSecret`] for any binding whose secret is absent.
    pub fn resolve(
        &self,
        bindings: &[SecretBinding],
    ) -> Result<Vec<ResolvedHeader>, MissingSecret> {
        bindings
            .iter()
            .map(|binding| {
                let secret = self.get(&binding.env).ok_or_else(|| MissingSecret {
                    name: binding.env.clone(),
                })?;
                let value = match &binding.prefix {
                    Some(prefix) => format!("{} {}", prefix, secret.expose()),
                    None => secret.expose().to_owned(),
                };
                Ok(ResolvedHeader {
                    name: binding.header.clone(),
                    value: SecretString::new(value),
                    hosts: binding.hosts.clone(),
                })
            })
            .collect()
    }
}

/// A secret binding resolved to the header it sets.
#[derive(Debug)]
pub struct ResolvedHeader {
    /// Header name to set, e.g. `Authorization`.
    pub name: String,
    /// Full header value, prefix included.
    pub value: SecretString,
    /// Host globs the header may go to. Empty means every host the tool may reach.
    pub hosts: Vec<String>,
}

/// A binding referenced a secret that the store does not hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("secret `{name}` is not available in the secret store")]
pub struct MissingSecret {
    /// Environment variable name.
    pub name: String,
}

/// Read a `.env` file into a map; a missing file yields an empty map.
#[must_use]
pub fn read_dotenv(path: &Path) -> BTreeMap<String, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => parse_dotenv(&contents),
        Err(_) => BTreeMap::new(),
    }
}

/// Parse `.env` text into a map.
///
/// Supports `KEY=value`, `export KEY=value`, `#` comments, blank lines and
/// quoted values. A malformed line is skipped rather than aborting: a stray
/// character in a developer machine's `.env` must not stop the hub from starting
/// with the variables that did parse.
#[must_use]
pub fn parse_dotenv(contents: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let value = value.trim();
        let value = match value.strip_prefix('"') {
            Some(rest) => rest.strip_suffix('"').unwrap_or(rest).to_owned(),
            None => match value.strip_prefix('\'') {
                Some(rest) => rest.strip_suffix('\'').unwrap_or(rest).to_owned(),
                // Unquoted values stop at an inline comment.
                None => value.split(" #").next().unwrap_or(value).trim().to_owned(),
            },
        };
        values.insert(key.to_owned(), value);
    }
    values
}

/// Scrubs known secret values out of arbitrary text.
///
/// Installed as a global filter for log output and applied to tool results,
/// error messages and audit payloads. Longest values are replaced first, so a
/// secret that is a prefix of another cannot leave a tail behind.
#[derive(Debug, Default, Clone)]
pub struct Redactor {
    needles: Vec<String>,
}

impl Redactor {
    /// An empty redactor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a redactor from a secret store.
    #[must_use]
    pub fn from_store(store: &SecretStore) -> Self {
        let mut redactor = Self::new();
        for name in store.names() {
            if let Some(secret) = store.get(name) {
                redactor.add(secret.expose());
            }
        }
        redactor
    }

    /// Register a literal to scrub. Very short values are ignored: replacing
    /// every `a` in every log line is not redaction.
    pub fn add(&mut self, needle: &str) {
        // 8 characters is below the entropy of any real credential and above
        // the length of common filler words.
        if needle.len() >= 8 && !self.needles.iter().any(|known| known == needle) {
            self.needles.push(needle.to_owned());
        }
    }

    /// Number of registered literals.
    #[must_use]
    pub fn len(&self) -> usize {
        self.needles.len()
    }

    /// `true` when nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    /// Replace every registered literal in `text`.
    #[must_use]
    pub fn scrub(&self, text: &str) -> String {
        if self.needles.is_empty() {
            return text.to_owned();
        }
        let mut ordered: Vec<&String> = self.needles.iter().collect();
        ordered.sort_by_key(|needle| std::cmp::Reverse(needle.len()));

        let mut output = text.to_owned();
        for needle in ordered {
            if output.contains(needle.as_str()) {
                output = output.replace(needle.as_str(), REDACTED);
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn binding(env: &str, header: &str, prefix: Option<&str>) -> SecretBinding {
        SecretBinding {
            env: env.to_owned(),
            header: header.to_owned(),
            prefix: prefix.map(str::to_owned),
            hosts: Vec::new(),
        }
    }

    fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn secrets_never_render_their_value() {
        let secret = SecretString::new("ghp_0123456789abcdef");
        assert_eq!(format!("{secret}"), REDACTED);
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(
            serde_json::to_string(&secret).expect("serializes"),
            format!("\"{REDACTED}\"")
        );
        // Length is safe to log; the value is not.
        assert_eq!(secret.len(), "ghp_0123456789abcdef".len());
        assert!(!format!("{secret:?}").contains("ghp_"));
    }

    #[test]
    fn exposing_and_consuming_a_secret() {
        let secret = SecretString::new("token-value-1234");
        assert_eq!(secret.expose(), "token-value-1234");
        assert!(secret.constant_time_eq("token-value-1234"));
        assert!(!secret.constant_time_eq("token-value-1235"));
        assert_eq!(secret.clone().into_inner(), "token-value-1234");
        assert_eq!(SecretString::placeholder().expose(), REDACTED);
    }

    #[test]
    fn store_resolves_from_an_injected_environment() {
        let env = env_map(&[("GITHUB_TOKEN", "ghp_0123456789abcdef")]);
        let store = SecretStore::from_env_lookup(
            [binding("GITHUB_TOKEN", "Authorization", None)],
            |name| env.get(name).cloned(),
        )
        .expect("resolves");

        assert_eq!(store.len(), 1);
        assert_eq!(store.names(), vec!["GITHUB_TOKEN"]);
        assert_eq!(
            store.source_of("GITHUB_TOKEN"),
            Some(SourceKind::ProcessEnv)
        );
    }

    #[test]
    fn missing_and_empty_secrets_are_errors() {
        let env = env_map(&[("EMPTY_TOKEN", "")]);
        let error = SecretStore::from_env_lookup([binding("MISSING", "X", None)], |name| {
            env.get(name).cloned()
        })
        .expect_err("missing must fail");
        assert!(matches!(error, SecretError::Missing { .. }));

        let error = SecretStore::from_env_lookup([binding("EMPTY_TOKEN", "X", None)], |name| {
            env.get(name).cloned()
        })
        .expect_err("empty must fail");
        assert!(matches!(error, SecretError::Empty { .. }));
    }

    #[test]
    fn headers_are_built_with_the_configured_prefix() {
        let env = env_map(&[("GITHUB_TOKEN", "ghp_0123456789abcdef")]);
        let store = SecretStore::from_env_lookup(
            [binding("GITHUB_TOKEN", "Authorization", Some("Bearer"))],
            |name| env.get(name).cloned(),
        )
        .expect("resolves");

        let headers = store
            .headers_for(&[binding("GITHUB_TOKEN", "Authorization", Some("Bearer"))])
            .expect("headers built");
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer ghp_0123456789abcdef")
        );
    }

    #[test]
    fn missing_secret_blocks_header_injection() {
        let store = SecretStore::new();
        let error = store
            .headers_for(&[binding("GITHUB_TOKEN", "Authorization", None)])
            .expect_err("must fail closed");
        assert_eq!(error.name, "GITHUB_TOKEN");
    }

    #[test]
    fn dotenv_parsing_handles_the_usual_shapes() {
        let parsed = parse_dotenv(
            "# comment\n\nGITHUB_TOKEN=ghp_plain\nexport QUOTED=\"with spaces\"\nSINGLE='literal # not a comment'\nTRAILING=value # trailing comment\nINVALID LINE\nBAD-KEY=nope\n",
        );
        assert_eq!(
            parsed.get("GITHUB_TOKEN").map(String::as_str),
            Some("ghp_plain")
        );
        assert_eq!(
            parsed.get("QUOTED").map(String::as_str),
            Some("with spaces")
        );
        assert_eq!(
            parsed.get("SINGLE").map(String::as_str),
            Some("literal # not a comment")
        );
        assert_eq!(parsed.get("TRAILING").map(String::as_str), Some("value"));
        assert!(!parsed.contains_key("INVALID LINE"));
        assert!(!parsed.contains_key("BAD-KEY"));
    }

    #[test]
    fn redactor_scrubs_known_values() {
        let mut redactor = Redactor::new();
        redactor.add("ghp_0123456789abcdef");
        redactor.add("short");
        assert_eq!(redactor.len(), 1, "short values are ignored");

        let scrubbed = redactor.scrub("request failed with token ghp_0123456789abcdef");
        assert_eq!(scrubbed, "request failed with token [redacted]");
        assert!(!scrubbed.contains("ghp_"));
    }

    #[test]
    fn redactor_prefers_the_longest_match() {
        let mut redactor = Redactor::new();
        redactor.add("abcdefgh");
        redactor.add("abcdefghijkl");
        assert_eq!(redactor.scrub("value=abcdefghijkl"), "value=[redacted]");
    }

    #[test]
    fn redactor_is_a_no_op_when_empty() {
        let redactor = Redactor::new();
        assert!(redactor.is_empty());
        assert_eq!(redactor.scrub("nothing to hide"), "nothing to hide");
    }

    #[test]
    fn redactor_from_store_covers_every_secret() {
        let env = env_map(&[("A_TOKEN", "aaaaaaaaaaaa"), ("B_TOKEN", "bbbbbbbbbbbb")]);
        let store = SecretStore::from_env_lookup(
            [binding("A_TOKEN", "X", None), binding("B_TOKEN", "Y", None)],
            |name| env.get(name).cloned(),
        )
        .expect("resolves");

        let redactor = Redactor::from_store(&store);
        assert_eq!(redactor.len(), 2);
        assert_eq!(
            redactor.scrub("leak aaaaaaaaaaaa and bbbbbbbbbbbb"),
            "leak [redacted] and [redacted]"
        );
    }
}
