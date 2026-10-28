// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Finding, layering and parsing `tpt-mcpbox.yaml`.
//!
//! Discovery order (first hit wins), matching how operators expect a
//! local-first tool to behave:
//!
//! 1. an explicit `--config <path>` argument,
//! 2. `$MCPBOX_CONFIG`,
//! 3. `./tpt-mcpbox.yaml` in the working directory,
//! 4. the user config directory (`$XDG_CONFIG_HOME/tpt-mcpbox/tpt-mcpbox.yaml`,
//!    else `%APPDATA%\tpt-mcpbox\tpt-mcpbox.yaml`).
//!
//! Layering is additive: a `tpt-mcpbox.local.yaml` next to the primary file
//! contributes tools and upstreams but can never rewrite the primary policy,
//! audit or logging settings. The checked-in policy stays authoritative.

use std::path::{Path, PathBuf};

use crate::model::Config;

/// Default configuration filename.
pub const DEFAULT_CONFIG_FILENAME: &str = "tpt-mcpbox.yaml";

/// Optional per-developer overlay, merged on top of the primary document.
pub const LOCAL_CONFIG_FILENAME: &str = "tpt-mcpbox.local.yaml";

/// Environment variable pointing at an explicit configuration file.
pub const CONFIG_PATH_ENV: &str = "MCPBOX_CONFIG";

/// Failure while locating or reading configuration.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// No configuration file was found in any discovery location.
    #[error(
        "no configuration file found: looked for `{DEFAULT_CONFIG_FILENAME}` in the working directory and the user config directory (set --config or ${CONFIG_PATH_ENV})"
    )]
    NotFound,

    /// The file exists but could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },

    /// The file is not valid YAML, or does not match the schema.
    #[error("invalid configuration in {path}: {source}")]
    Parse {
        /// Path that failed.
        path: PathBuf,
        /// Underlying serde error.
        source: serde_norway::Error,
    },

    /// The document declares a schema version this build does not implement.
    #[error(
        "configuration {path} requires schema version {found}, but this build supports up to {supported}"
    )]
    UnsupportedVersion {
        /// Path that failed.
        path: PathBuf,
        /// Version found in the document.
        found: u32,
        /// Highest version this build understands.
        supported: u32,
    },
}

/// Where a configuration file came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// Supplied explicitly by the caller.
    Explicit,
    /// Taken from `$MCPBOX_CONFIG`.
    Environment,
    /// Found in the working directory.
    WorkingDirectory,
    /// Found in the user config directory.
    UserConfigDir,
}

impl SourceKind {
    /// Stable label used in diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Explicit => "explicit path",
            Self::Environment => "MCPBOX_CONFIG",
            Self::WorkingDirectory => "working directory",
            Self::UserConfigDir => "user config directory",
        }
    }
}

/// A discovered configuration file and its merge result.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedConfig {
    /// Primary configuration with any overlay applied.
    pub config: Config,
    /// Primary file path.
    pub path: PathBuf,
    /// How the primary file was found.
    pub source: SourceKind,
    /// Overlay file that was merged in, if any.
    pub overlay: Option<PathBuf>,
}

/// A primary document plus the optional overlay merged into it.
#[derive(Debug, Clone, PartialEq)]
pub struct LayeredConfig {
    /// Merged result.
    pub config: Config,
    /// Files that contributed, in merge order.
    pub files: Vec<PathBuf>,
}

/// Parse a configuration document from a string.
///
/// `origin` is used only for error messages.
///
/// # Errors
/// Returns [`LoadError::Parse`] when the YAML does not match the schema, and
/// [`LoadError::UnsupportedVersion`] for a document from the future.
pub fn load_str(yaml: &str, origin: &str) -> Result<Config, LoadError> {
    let config: Config = serde_norway::from_str(yaml).map_err(|source| LoadError::Parse {
        path: PathBuf::from(origin),
        source,
    })?;

    // A future document may add fields this build would silently ignore, which
    // for a security tool means quietly missing a capability restriction.
    if let Some(version) = config.version
        && version > crate::model::CONFIG_VERSION
    {
        return Err(LoadError::UnsupportedVersion {
            path: PathBuf::from(origin),
            found: version,
            supported: crate::model::CONFIG_VERSION,
        });
    }
    Ok(config)
}

/// Parse a configuration file, merging the sibling overlay when present.
///
/// # Errors
/// Propagates [`LoadError`] from the primary document and from the overlay.
pub fn load_file(path: impl AsRef<Path>) -> Result<LoadedConfig, LoadError> {
    let path = path.as_ref();
    let mut config = read_config(path)?;

    // The Rego module is part of the policy, so a relative path is found next to
    // the file that names it. Resolving it against the working directory would
    // let a `policy.rego` planted wherever the hub is started replace it.
    if let Some(rego) = &config.policy.rego
        && rego.is_relative()
    {
        let base = path.parent().unwrap_or(Path::new(""));
        config.policy.rego = Some(base.join(rego));
    }

    let overlay_path = path.with_file_name(LOCAL_CONFIG_FILENAME);
    let (config, overlay) = if overlay_path.is_file() {
        let overlay_config = read_config(&overlay_path)?;
        (merge(config, overlay_config), Some(overlay_path))
    } else {
        (config, None)
    };

    Ok(LoadedConfig {
        config,
        path: path.to_path_buf(),
        source: SourceKind::Explicit,
        overlay,
    })
}

fn read_config(path: &Path) -> Result<Config, LoadError> {
    let contents = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    load_str(&contents, &path.display().to_string())
}

/// Merge an overlay into a primary document.
///
/// Only additive sections come from the overlay (`tools`, `upstreams`, and the
/// server transport list). `policy`, `audit`, `metrics` and `logging` stay with
/// the primary document so a local file cannot relax enforcement.
#[must_use]
pub fn merge(primary: Config, overlay: Config) -> Config {
    let mut merged = primary;
    merged.version = merged.version.or(overlay.version);
    merged.server.transports.extend(overlay.server.transports);
    if merged.server.http.is_none() {
        merged.server.http = overlay.server.http;
    }
    for tool in overlay.tools {
        if !merged
            .tools
            .iter()
            .any(|existing| existing.name == tool.name)
        {
            merged.tools.push(tool);
        }
    }
    for upstream in overlay.upstreams {
        if !merged
            .upstreams
            .iter()
            .any(|existing| existing.name == upstream.name)
        {
            merged.upstreams.push(upstream);
        }
    }
    merged
}

/// Locate the configuration file.
///
/// `explicit` is the `--config` value, `env_vars` looks up environment
/// variables, and `cwd` is probed for `./tpt-mcpbox.yaml`.
///
/// # Errors
/// Returns [`LoadError::NotFound`] when no candidate exists, or
/// [`LoadError::Io`] when `$MCPBOX_CONFIG` points at a missing file (a silent
/// fallback there would run with the wrong policy).
pub fn discover(
    explicit: Option<&Path>,
    env_vars: &dyn Fn(&str) -> Option<String>,
    cwd: &Path,
) -> Result<(PathBuf, SourceKind), LoadError> {
    if let Some(path) = explicit {
        return Ok((path.to_path_buf(), SourceKind::Explicit));
    }

    if let Some(raw) = env_vars(CONFIG_PATH_ENV) {
        let path = PathBuf::from(raw);
        if path.is_file() {
            return Ok((path, SourceKind::Environment));
        }
        return Err(LoadError::Io {
            path,
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("${CONFIG_PATH_ENV} points at a file that does not exist"),
            ),
        });
    }

    let local = cwd.join(DEFAULT_CONFIG_FILENAME);
    if local.is_file() {
        return Ok((local, SourceKind::WorkingDirectory));
    }

    if let Some(dir) = user_config_dir(env_vars) {
        let candidate = dir.join("tpt-mcpbox").join(DEFAULT_CONFIG_FILENAME);
        if candidate.is_file() {
            return Ok((candidate, SourceKind::UserConfigDir));
        }
    }

    Err(LoadError::NotFound)
}

/// The user configuration directory, when the platform provides one.
#[must_use]
pub fn user_config_dir(env_vars: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(xdg) = env_vars("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(xdg));
    }
    if let Some(appdata) = env_vars("APPDATA").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(appdata));
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::model::Effect;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn empty_document_is_the_deny_everything_default() {
        let config = load_str("", "empty.yaml").expect("parses");
        assert!(config.policy.is_deny_by_default());
        assert!(config.tools.is_empty());
        assert!(config.audit.enabled);
    }

    #[test]
    fn future_schema_versions_are_refused() {
        let error = load_str("version: 99", "future.yaml").expect_err("must refuse");
        assert!(matches!(
            error,
            LoadError::UnsupportedVersion { found: 99, .. }
        ));
    }

    #[test]
    fn current_schema_version_is_accepted() {
        let config = load_str("version: 1", "current.yaml").expect("parses");
        assert_eq!(config.version, Some(1));
    }

    #[test]
    fn discovery_prefers_an_explicit_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let explicit = dir.path().join("custom.yaml");
        std::fs::write(&explicit, "tools: []").expect("write");
        let (path, source) = discover(Some(&explicit), &env_of(&[]), dir.path()).expect("found");
        assert_eq!(path, explicit);
        assert_eq!(source, SourceKind::Explicit);
    }

    #[test]
    fn discovery_falls_back_to_the_working_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let local = dir.path().join(DEFAULT_CONFIG_FILENAME);
        std::fs::write(&local, "tools: []").expect("write");

        let (path, source) = discover(None, &env_of(&[]), dir.path()).expect("found");
        assert_eq!(path, local);
        assert_eq!(source, SourceKind::WorkingDirectory);
    }

    #[test]
    fn discovery_uses_the_environment_variable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let env_dir = tempfile::tempdir().expect("tempdir");
        let from_env = env_dir.path().join("from-env.yaml");
        std::fs::write(&from_env, "tools: []").expect("write");

        let (path, source) = discover(
            None,
            &env_of(&[(CONFIG_PATH_ENV, from_env.to_str().expect("utf8"))]),
            dir.path(),
        )
        .expect("found");
        assert_eq!(path, from_env);
        assert_eq!(source, SourceKind::Environment);
    }

    #[test]
    fn a_dangling_config_env_var_fails_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = discover(
            None,
            &env_of(&[(CONFIG_PATH_ENV, "/nonexistent/tpt-mcpbox.yaml")]),
            dir.path(),
        )
        .expect_err("must not silently fall back");
        assert!(matches!(error, LoadError::Io { .. }));
    }

    #[test]
    fn discovery_uses_the_user_config_directory() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let xdg = tempfile::tempdir().expect("tempdir");
        let dir = xdg.path().join("tpt-mcpbox");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join(DEFAULT_CONFIG_FILENAME);
        std::fs::write(&file, "tools: []").expect("write");

        let (path, source) = discover(
            None,
            &env_of(&[("XDG_CONFIG_HOME", xdg.path().to_str().expect("utf8"))]),
            cwd.path(),
        )
        .expect("found");
        assert_eq!(path, file);
        assert_eq!(source, SourceKind::UserConfigDir);
    }

    #[test]
    fn missing_configuration_is_reported_with_guidance() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let error = discover(None, &env_of(&[]), cwd.path()).expect_err("not found");
        assert!(error.to_string().contains("--config"));
    }

    #[test]
    fn overlays_add_tools_but_cannot_rewrite_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILENAME),
            "policy:\n  default: deny\ntools:\n  - name: primary\n    wasm_path: a.wasm\n",
        )
        .expect("write");
        std::fs::write(
            dir.path().join(LOCAL_CONFIG_FILENAME),
            "policy:\n  default: allow\ntools:\n  - name: local\n    wasm_path: b.wasm\n",
        )
        .expect("write");

        let loaded = load_file(dir.path().join(DEFAULT_CONFIG_FILENAME)).expect("loads");
        assert!(loaded.overlay.is_some());
        let names: Vec<&str> = loaded
            .config
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();
        assert_eq!(names, vec!["primary", "local"]);
        assert_eq!(
            loaded.config.policy.default,
            Effect::Deny,
            "overlay must not relax policy"
        );
    }

    #[test]
    fn a_relative_rego_path_resolves_against_the_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILENAME),
            "policy:
  rego: rules/policy.rego
",
        )
        .expect("write");

        let loaded = load_file(dir.path().join(DEFAULT_CONFIG_FILENAME)).expect("loads");
        assert_eq!(
            loaded.config.policy.rego,
            Some(dir.path().join("rules/policy.rego"))
        );
    }

    #[test]
    fn overlays_never_replace_an_existing_tool() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILENAME),
            "tools:\n  - name: dup\n    wasm_path: trusted.wasm\n    capabilities:\n      network: []\n",
        )
        .expect("write");
        std::fs::write(
            dir.path().join(LOCAL_CONFIG_FILENAME),
            "tools:\n  - name: dup\n    wasm_path: attacker.wasm\n    capabilities:\n      network: ['*']\n",
        )
        .expect("write");

        let loaded = load_file(dir.path().join(DEFAULT_CONFIG_FILENAME)).expect("loads");
        assert_eq!(loaded.config.tools.len(), 1);
        assert!(loaded.config.tools[0].capabilities.network.is_empty());
    }

    #[test]
    fn overlay_is_optional() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(DEFAULT_CONFIG_FILENAME), "tools: []").expect("write");
        let loaded = load_file(dir.path().join(DEFAULT_CONFIG_FILENAME)).expect("loads");
        assert!(loaded.overlay.is_none());
    }

    #[test]
    fn invalid_yaml_names_the_offending_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(DEFAULT_CONFIG_FILENAME);
        std::fs::write(&path, "tools: [oops\n").expect("write");
        let error = load_file(&path).expect_err("must fail");
        let message = error.to_string();
        assert!(message.contains("tpt-mcpbox.yaml"), "unexpected: {message}");
    }
}
