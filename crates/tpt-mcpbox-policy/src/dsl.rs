// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The YAML DSL evaluator.
//!
//! Rules are evaluated in order and the first match decides. A rule matches when
//! every constraint it states holds; constraints it leaves out are not checked.
//! When nothing matches, `policy.default` applies, and that is `deny` unless the
//! configuration says otherwise.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, PoisonError};

use globset::{GlobBuilder, GlobMatcher};
use serde::Serialize;
use serde_json::Value;
use tpt_mcpbox_config::{Effect, PolicyConfig, Rule};

use crate::decision::{Decision, PolicyInput};
use crate::error::PolicyError;
use crate::normalize::{normalize_host, normalize_path};

/// Maximum cached decisions before the cache is flushed.
const CACHE_LIMIT: usize = 1024;

/// A rule with its globs compiled, ready to match.
#[derive(Debug)]
struct CompiledRule {
    id: String,
    effect: Effect,
    tool: Option<GlobMatcher>,
    method: Option<String>,
    args: BTreeMap<String, Value>,
    hosts: Vec<GlobMatcher>,
    paths: Vec<GlobMatcher>,
}

/// The request as the rules see it, after normalisation.
struct Context<'a> {
    method: &'a str,
    tool: Option<&'a str>,
    arguments: &'a Value,
    host: Option<&'a str>,
    fs_path: Option<&'a str>,
}

/// Key for the decision cache. Built from normalised values, so two spellings
/// of the same host or path share one entry.
#[derive(Serialize)]
struct CacheKey<'a> {
    method: &'a str,
    tool: Option<&'a str>,
    arguments: &'a Value,
    host: Option<&'a str>,
    fs_path: Option<&'a str>,
}

/// Compiled YAML DSL policy.
///
/// An engine is immutable apart from its decision cache. A config reload builds
/// a new engine, which starts with an empty cache, so cached decisions never
/// outlive the rules that produced them.
#[derive(Debug)]
pub struct Engine {
    default: Effect,
    dry_run: bool,
    rules: Vec<CompiledRule>,
    cache: Mutex<HashMap<String, Decision>>,
}

impl Engine {
    /// Compile the `policy` section of a configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::RegoNotSupported`] when `policy.rego` is set, since
    /// that evaluator is not built yet. Silently ignoring it would run without
    /// the intended policy. Also returns an error for a duplicate rule id or a
    /// glob that does not compile.
    pub fn from_config(config: &PolicyConfig) -> Result<Self, PolicyError> {
        if config.rego.is_some() {
            return Err(PolicyError::RegoNotSupported);
        }

        let mut seen = std::collections::HashSet::new();
        let mut rules = Vec::with_capacity(config.rules.len());
        for rule in &config.rules {
            if !seen.insert(rule.id.as_str()) {
                return Err(PolicyError::DuplicateRuleId(rule.id.clone()));
            }
            rules.push(compile(rule)?);
        }

        Ok(Self {
            default: config.default,
            dry_run: config.dry_run,
            rules,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Evaluate one request.
    ///
    /// Results are cached on the normalised input, so repeated identical calls
    /// skip matching. The cache is flushed once it reaches [`CACHE_LIMIT`]
    /// entries.
    #[must_use]
    pub fn evaluate(&self, input: &PolicyInput) -> Decision {
        let host = input.host.as_deref().and_then(normalize_host);
        let fs_path = input.fs_path.as_deref().and_then(normalize_path);

        let key = serde_json::to_string(&CacheKey {
            method: &input.method,
            tool: input.tool.as_deref(),
            arguments: &input.arguments,
            host: host.as_deref(),
            fs_path: fs_path.as_deref(),
        })
        // Serialising plain strings and JSON values cannot fail.
        .unwrap_or_default();

        if let Some(hit) = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return hit.clone();
        }

        let ctx = Context {
            method: &input.method,
            tool: input.tool.as_deref(),
            arguments: &input.arguments,
            host: host.as_deref(),
            fs_path: fs_path.as_deref(),
        };
        let decision = self.decide(&ctx);

        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(key, decision.clone());
        decision
    }

    fn decide(&self, ctx: &Context<'_>) -> Decision {
        let (would_be, rule_id, reason) = match self.rules.iter().find(|r| matches(r, ctx)) {
            Some(rule) => (
                rule.effect,
                Some(rule.id.clone()),
                format!("matched rule `{}`", rule.id),
            ),
            None => (
                self.default,
                None,
                format!(
                    "no rule matched; policy.default is {}",
                    effect_name(self.default)
                ),
            ),
        };

        if self.dry_run && would_be == Effect::Deny {
            return Decision {
                effect: Effect::Allow,
                would_be,
                rule_id,
                reason: format!("dry-run: would deny; {reason}"),
            };
        }
        Decision {
            effect: would_be,
            would_be,
            rule_id,
            reason,
        }
    }
}

fn compile(rule: &Rule) -> Result<CompiledRule, PolicyError> {
    let glob = |pattern: &str| -> Result<GlobMatcher, PolicyError> {
        Ok(GlobBuilder::new(pattern)
            .build()
            .map_err(|source| PolicyError::InvalidGlob {
                rule: rule.id.clone(),
                pattern: pattern.to_owned(),
                source,
            })?
            .compile_matcher())
    };
    // Paths use `/` as a literal separator so `*` never crosses a directory,
    // and are case-insensitive on Windows, where `C:\Secret` and `c:\secret`
    // name the same file.
    let path_glob = |pattern: &str| -> Result<GlobMatcher, PolicyError> {
        Ok(GlobBuilder::new(pattern)
            .literal_separator(true)
            .case_insensitive(cfg!(windows))
            .build()
            .map_err(|source| PolicyError::InvalidGlob {
                rule: rule.id.clone(),
                pattern: pattern.to_owned(),
                source,
            })?
            .compile_matcher())
    };

    Ok(CompiledRule {
        id: rule.id.clone(),
        effect: rule.effect,
        tool: rule.tool.as_deref().map(glob).transpose()?,
        method: rule.method.clone(),
        args: rule.args.clone(),
        hosts: rule
            .hosts
            .iter()
            .map(|h| glob(&h.to_ascii_lowercase()))
            .collect::<Result<_, _>>()?,
        paths: rule
            .paths
            .iter()
            .map(|p| path_glob(p.replace('\\', "/").trim_start_matches("./")))
            .collect::<Result<_, _>>()?,
    })
}

fn matches(rule: &CompiledRule, ctx: &Context<'_>) -> bool {
    if let Some(tool_glob) = &rule.tool {
        match ctx.tool {
            Some(tool) if tool_glob.is_match(tool) => {}
            _ => return false,
        }
    }
    if let Some(method) = &rule.method {
        if method != ctx.method {
            return false;
        }
    }
    for (key, expected) in &rule.args {
        if ctx.arguments.get(key) != Some(expected) {
            return false;
        }
    }
    if !rule.hosts.is_empty() {
        match ctx.host {
            Some(host) if rule.hosts.iter().any(|g| g.is_match(host)) => {}
            _ => return false,
        }
    }
    if !rule.paths.is_empty() {
        match ctx.fs_path {
            Some(path) if rule.paths.iter().any(|g| g.is_match(path)) => {}
            _ => return false,
        }
    }
    true
}

fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
    }
}

#[cfg(test)]
mod tests;
