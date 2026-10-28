// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Configuration, validation and secret handling for tpt-mcpbox (Phase 2).
//!
//! The crate is deliberately split so that *parsing* never implies *trust*:
//!
//! * [`model`] - the `tpt-mcpbox.yaml` data model. Unknown fields are rejected,
//!   so a typo in a capability grant fails instead of silently widening it.
//! * [`units`] - human-friendly byte sizes (`"64MB"`) and durations (`"500ms"`).
//! * [`load`] - discovery, layering and parsing into [`model::Config`].
//! * [`validate`] - semantic checks with actionable diagnostics, plus the
//!   [`validate::ValidationMode`] switch that forbids `policy.default: allow`
//!   outside dry-run runs.
//! * [`secrets`] - [`secrets::SecretString`] (zeroizing, redacted), the
//!   environment/`.env` sources, header injection and the central
//!   [`secrets::Redactor`].
//! * [`schema`] - JSON Schema emission for editor completion and CI checks.
//! * [`reload`] - a polling watcher plus an atomic swap handle.
//!
//! # Example
//!
//! ```
//! use tpt_mcpbox_config::{load_str, validate, ValidationMode};
//!
//! let yaml = r#"
//! tools:
//!   - name: fs_read
//!     wasm_path: ./tools/fs.wasm
//!     capabilities:
//!       filesystem:
//!         read: ["./workspace/**"]
//! "#;
//!
//! let config = load_str(yaml, "tpt-mcpbox.yaml").expect("parses");
//! let report = validate(&config, ValidationMode::Serve);
//! assert!(report.is_ok(), "unexpected diagnostics: {report:?}");
//! assert_eq!(
//!     config.tools[0].capabilities.filesystem.read,
//!     vec!["./workspace/**"]
//! );
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod load;
pub mod model;
pub mod reload;
pub mod schema;
pub mod secrets;
pub mod units;
pub mod validate;

pub use load::{
    DEFAULT_CONFIG_FILENAME, LayeredConfig, LoadedConfig, SourceKind, discover, load_file, load_str,
};
pub use model::{
    AuditConfig, CONFIG_VERSION, Capabilities, Config, Effect, FilesystemCapabilities,
    HttpServerConfig, HttpUpstream, Limits, LogLevel, LoggingConfig, MetricsConfig, PolicyConfig,
    PromptFilter, Quota, RateLimit, ResourceFilter, Rule, RuleConstraints, ScanAction, ScanRule,
    SecretBinding, ServerConfig, StdioUpstream, ToolConfig, ToolOverrides, Transport,
    UpstreamConfig, UpstreamTransport,
};
pub use schema::json_schema;
pub use secrets::{Redactor, SecretStore, SecretString};
pub use units::{UnitError, format_byte_size, format_duration, parse_byte_size, parse_duration};
pub use validate::{Diagnostic, Severity, ValidationMode, ValidationReport, validate};

/// Crate version, surfaced by `tpt-mcpbox --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
