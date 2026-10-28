// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The YAML DSL evaluator.
//!
//! Rules are evaluated in order and the first match decides. A rule matches when
//! every constraint it states holds; constraints it leaves out are not checked.
//! An allow rule with a `quota` consumes one slot of its per-caller budget for
//! every call it admits; once the budget is spent, the call is refused.
//!
//! [`Engine::evaluate`] applies `policy.default` when nothing matches. The
//! composed [`crate::Policy`] uses [`Engine::outcome`] instead, so that a
//! missing DSL match can defer to another evaluator.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use globset::{GlobBuilder, GlobMatcher};
use serde::Serialize;
use serde_json::Value;
use tpt_mcpbox_config::{Effect, PolicyConfig, Quota, Rule, RuleConstraints, format_duration};

use crate::decision::{Decision, PolicyInput};
use crate::error::PolicyError;
use crate::normalize::{normalize_host, normalize_path, normalize_uri};

/// Maximum cached decisions before the cache is flushed.
const CACHE_LIMIT: usize = 1024;

/// Maximum distinct quota buckets before idle buckets are dropped.
const QUOTA_BUCKET_LIMIT: usize = 4096;

/// A rule with its globs compiled, ready to match.
#[derive(Debug)]
struct CompiledRule {
    id: String,
    effect: Effect,
    tool: Option<GlobMatcher>,
    prompt: Option<GlobMatcher>,
    method: Option<String>,
    args: BTreeMap<String, Value>,
    hosts: Vec<GlobMatcher>,
    paths: Vec<GlobMatcher>,
    caller: Option<GlobMatcher>,
    uris: Vec<GlobMatcher>,
    constraints: Option<RuleConstraints>,
}

impl CompiledRule {
    fn quota(&self) -> Option<&Quota> {
        self.constraints.as_ref()?.quota.as_ref()
    }
}

/// The request as the rules see it, after normalisation.
struct Context<'a> {
    method: &'a str,
    caller: Option<&'a str>,
    tool: Option<&'a str>,
    prompt: Option<&'a str>,
    arguments: &'a Value,
    host: Field<'a>,
    fs_path: Field<'a>,
    /// `None` marks a URI that could not be normalised. Such a URI is covered
    /// by no allow rule and by every deny rule.
    uris: &'a [Option<String>],
}

/// Key for the decision cache. Built from normalised values, so two spellings
/// of the same host, path or URI share one entry.
#[derive(Serialize)]
struct CacheKey<'a> {
    method: &'a str,
    caller: Option<&'a str>,
    tool: Option<&'a str>,
    prompt: Option<&'a str>,
    arguments: &'a Value,
    host: Field<'a>,
    fs_path: Field<'a>,
    uris: &'a [Option<String>],
}

/// A host or path from the request, after normalisation.
///
/// A value that is present but cannot be normalised (a port on a host, a path
/// that climbs above its root) is kept apart from an absent one: it is covered
/// by no allow rule and by every deny rule that names the field, so a spelling
/// the normaliser refuses cannot be used to step around a deny.
#[derive(Debug, Clone, Copy, Serialize)]
enum Field<'a> {
    Absent,
    Invalid,
    Valid(&'a str),
}

impl<'a> Field<'a> {
    fn of(normalized: &'a Option<Option<String>>) -> Self {
        match normalized {
            None => Self::Absent,
            Some(None) => Self::Invalid,
            Some(Some(value)) => Self::Valid(value),
        }
    }

    fn covered_by(self, effect: Effect, globs: &[GlobMatcher]) -> bool {
        match self {
            Self::Absent => false,
            Self::Invalid => effect == Effect::Deny,
            Self::Valid(value) => globs.iter().any(|glob| glob.is_match(value)),
        }
    }
}

/// What the DSL said about one request.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DslOutcome {
    /// A rule matched, or a quota refused a matched rule.
    Matched(Verdict),
    /// No rule matched.
    NoMatch,
}

/// The matched rule's effect and the explanation to record.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Verdict {
    pub(crate) effect: Effect,
    pub(crate) rule_id: String,
    pub(crate) reason: String,
    pub(crate) constraints: Option<RuleConstraints>,
}

/// Calls admitted inside one quota window for one rule and caller.
#[derive(Debug, Clone)]
struct Bucket {
    window: Duration,
    admitted: VecDeque<Instant>,
}

impl Bucket {
    /// Drop admissions that have left the window, then admit this call if the
    /// budget allows it.
    fn admit(&mut self, quota: &Quota, now: Instant) -> bool {
        self.window = quota.window;
        while let Some(&oldest) = self.admitted.front() {
            if now.saturating_duration_since(oldest) < quota.window {
                break;
            }
            self.admitted.pop_front();
        }
        if self.admitted.len() >= quota.max_calls as usize {
            return false;
        }
        self.admitted.push_back(now);
        true
    }

    /// `true` while at least one admission is still inside the window.
    fn is_live(&self, now: Instant) -> bool {
        self.admitted
            .back()
            .is_some_and(|last| now.saturating_duration_since(*last) < self.window)
    }
}

/// Compiled YAML DSL policy.
///
/// An engine is immutable apart from its decision cache and quota counters. A
/// config reload builds a new engine, which starts with an empty cache; quota
/// counters are carried over with [`Engine::inherit_quotas`] so that a reload
/// does not reset anyone's budget.
#[derive(Debug)]
pub struct Engine {
    default: Effect,
    dry_run: bool,
    rules: Vec<CompiledRule>,
    cache: Mutex<HashMap<String, DslOutcome>>,
    quotas: Mutex<HashMap<(String, String), Bucket>>,
}

impl Engine {
    /// Compile the `policy` section of a configuration into a DSL-only engine.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::RegoInDslOnly`] when `policy.rego` is set: a DSL
    /// engine would silently ignore that module. Use [`crate::Policy`] to
    /// compose both. Also returns an error for a duplicate rule id or a glob
    /// that does not compile.
    pub fn from_config(config: &PolicyConfig) -> Result<Self, PolicyError> {
        if config.rego.is_some() {
            return Err(PolicyError::RegoInDslOnly);
        }
        Self::compile(config)
    }

    /// Compile the DSL rules, ignoring any Rego module. Used by [`crate::Policy`],
    /// which evaluates the module itself.
    pub(crate) fn compile(config: &PolicyConfig) -> Result<Self, PolicyError> {
        let mut seen = HashSet::new();
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
            quotas: Mutex::new(HashMap::new()),
        })
    }

    /// Evaluate one request, applying `policy.default` when nothing matches.
    #[must_use]
    pub fn evaluate(&self, input: &PolicyInput) -> Decision {
        self.evaluate_at(input, Instant::now())
    }

    /// Evaluate one request as of `now`. Exists so quota windows can be tested
    /// without sleeping.
    pub(crate) fn evaluate_at(&self, input: &PolicyInput, now: Instant) -> Decision {
        match self.outcome(input, now, true) {
            DslOutcome::Matched(verdict) => enforce(
                self.dry_run,
                verdict.effect,
                Some(verdict.rule_id),
                verdict.reason,
                verdict.constraints,
            ),
            DslOutcome::NoMatch => enforce(
                self.dry_run,
                self.default,
                None,
                format!(
                    "no rule matched; policy.default is {}",
                    effect_name(self.default)
                ),
                None,
            ),
        }
    }

    /// The effect applied when no rule matches.
    pub(crate) fn default_effect(&self) -> Effect {
        self.default
    }

    /// Find the first matching rule and account for its quota.
    ///
    /// Outcomes are cached on the normalised input, except outcomes that touched
    /// a quota: those depend on the budget at the time of the call.
    ///
    /// With `charge` false, an allow rule's quota is not spent, and such an
    /// outcome is never cached. See [`crate::Policy::evaluate_recheck`].
    pub(crate) fn outcome(&self, input: &PolicyInput, now: Instant, charge: bool) -> DslOutcome {
        let host = input.host.as_deref().map(normalize_host);
        let fs_path = input.fs_path.as_deref().map(normalize_path);
        let uris: Vec<Option<String>> = input.uris.iter().map(|uri| normalize_uri(uri)).collect();

        let key = serde_json::to_string(&CacheKey {
            method: &input.method,
            caller: input.caller.as_deref(),
            tool: input.tool.as_deref(),
            prompt: input.prompt.as_deref(),
            arguments: &input.arguments,
            host: Field::of(&host),
            fs_path: Field::of(&fs_path),
            uris: &uris,
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
            caller: input.caller.as_deref(),
            tool: input.tool.as_deref(),
            prompt: input.prompt.as_deref(),
            arguments: &input.arguments,
            host: Field::of(&host),
            fs_path: Field::of(&fs_path),
            uris: &uris,
        };

        let (outcome, cacheable) = match self.rules.iter().find(|rule| matches(rule, &ctx)) {
            None => (DslOutcome::NoMatch, true),
            Some(rule) => match rule.quota() {
                Some(quota) if rule.effect == Effect::Allow => {
                    let admitted = !charge || self.admit(rule, quota, input.caller.as_deref(), now);
                    let verdict = if admitted {
                        Verdict {
                            effect: Effect::Allow,
                            rule_id: rule.id.clone(),
                            reason: format!("matched rule `{}`", rule.id),
                            constraints: rule.constraints.clone(),
                        }
                    } else {
                        Verdict {
                            effect: Effect::Deny,
                            rule_id: rule.id.clone(),
                            reason: format!(
                                "rule `{}` refused: quota of {} call(s) per {} exhausted for this caller",
                                rule.id,
                                quota.max_calls,
                                format_duration(quota.window),
                            ),
                            constraints: None,
                        }
                    };
                    (DslOutcome::Matched(verdict), false)
                }
                _ => (
                    DslOutcome::Matched(Verdict {
                        effect: rule.effect,
                        rule_id: rule.id.clone(),
                        reason: format!("matched rule `{}`", rule.id),
                        constraints: rule.constraints.clone(),
                    }),
                    true,
                ),
            },
        };

        if cacheable {
            let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            if cache.len() >= CACHE_LIMIT {
                cache.clear();
            }
            cache.insert(key, outcome.clone());
        }
        outcome
    }

    /// Charge one call against a rule's quota for this caller.
    fn admit(
        &self,
        rule: &CompiledRule,
        quota: &Quota,
        caller: Option<&str>,
        now: Instant,
    ) -> bool {
        let mut buckets = self.quotas.lock().unwrap_or_else(PoisonError::into_inner);
        // A shared budget ignores the caller, so a new session cannot reset it.
        let owner = if quota.shared {
            ""
        } else {
            caller.unwrap_or_default()
        };
        let bucket_key = (rule.id.clone(), owner.to_owned());
        if !buckets.contains_key(&bucket_key) && buckets.len() >= QUOTA_BUCKET_LIMIT {
            // Drop buckets with no admission left inside their window.
            buckets.retain(|_, bucket| bucket.is_live(now));
        }
        buckets
            .entry(bucket_key)
            .or_insert_with(|| Bucket {
                window: quota.window,
                admitted: VecDeque::new(),
            })
            .admit(quota, now)
    }

    /// Carry quota counters over from the engine this one replaces, for every
    /// rule id that still carries a quota. Counters of other rules are dropped.
    pub(crate) fn inherit_quotas(&self, previous: &Engine) {
        let previous_buckets = previous
            .quotas
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut buckets = self.quotas.lock().unwrap_or_else(PoisonError::into_inner);
        for ((rule_id, caller), bucket) in previous_buckets.iter() {
            let still_has_quota = self
                .rules
                .iter()
                .any(|rule| &rule.id == rule_id && rule.quota().is_some());
            if still_has_quota {
                buckets.insert((rule_id.clone(), caller.clone()), bucket.clone());
            }
        }
    }

    /// Number of quota buckets currently held.
    #[cfg(test)]
    pub(crate) fn quota_bucket_count(&self) -> usize {
        self.quotas
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Apply dry-run to a decided effect. In dry-run mode a deny is reported as an
/// allow, with the original effect kept in `would_be`.
pub(crate) fn enforce(
    dry_run: bool,
    would_be: Effect,
    rule_id: Option<String>,
    reason: String,
    constraints: Option<RuleConstraints>,
) -> Decision {
    if dry_run && would_be == Effect::Deny {
        return Decision {
            effect: Effect::Allow,
            would_be,
            rule_id,
            reason: format!("dry-run: would deny; {reason}"),
            constraints: None,
        };
    }
    Decision {
        effect: would_be,
        would_be,
        rule_id,
        reason,
        constraints,
    }
}

fn compile(rule: &Rule) -> Result<CompiledRule, PolicyError> {
    let invalid = |pattern: &str, source: globset::Error| PolicyError::InvalidGlob {
        rule: rule.id.clone(),
        pattern: pattern.to_owned(),
        source,
    };
    let glob = |pattern: &str| -> Result<GlobMatcher, PolicyError> {
        Ok(GlobBuilder::new(pattern)
            .build()
            .map_err(|source| invalid(pattern, source))?
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
            .map_err(|source| invalid(pattern, source))?
            .compile_matcher())
    };
    // URI globs keep `*` within one path segment, as paths do.
    let uri_glob = |pattern: &str| -> Result<GlobMatcher, PolicyError> {
        Ok(GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|source| invalid(pattern, source))?
            .compile_matcher())
    };

    Ok(CompiledRule {
        id: rule.id.clone(),
        effect: rule.effect,
        tool: rule.tool.as_deref().map(glob).transpose()?,
        prompt: rule.prompt.as_deref().map(glob).transpose()?,
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
        caller: rule.caller.as_deref().map(glob).transpose()?,
        uris: rule
            .uris
            .iter()
            .map(|u| uri_glob(u))
            .collect::<Result<_, _>>()?,
        constraints: rule.constraints.clone(),
    })
}

fn matches(rule: &CompiledRule, ctx: &Context<'_>) -> bool {
    if let Some(tool_glob) = &rule.tool {
        match ctx.tool {
            Some(tool) if tool_glob.is_match(tool) => {}
            _ => return false,
        }
    }
    if let Some(prompt_glob) = &rule.prompt {
        match ctx.prompt {
            Some(prompt) if prompt_glob.is_match(prompt) => {}
            _ => return false,
        }
    }
    if let Some(method) = &rule.method
        && method != ctx.method
    {
        return false;
    }
    if let Some(caller_glob) = &rule.caller {
        match ctx.caller {
            Some(caller) if caller_glob.is_match(caller) => {}
            _ => return false,
        }
    }
    for (key, expected) in &rule.args {
        if ctx.arguments.get(key) != Some(expected) {
            return false;
        }
    }
    if !rule.hosts.is_empty() && !ctx.host.covered_by(rule.effect, &rule.hosts) {
        return false;
    }
    if !rule.paths.is_empty() && !ctx.fs_path.covered_by(rule.effect, &rule.paths) {
        return false;
    }
    if !rule.uris.is_empty() && !uris_match(rule, ctx.uris) {
        return false;
    }
    true
}

/// Whether a rule's URI globs cover the request's URIs.
///
/// An allow rule must cover every requested URI, so one allowed URI cannot
/// smuggle in another. A deny rule need only cover one, so that any request
/// touching a refused URI is refused. A URI that failed normalisation is never
/// covered by an allow rule and always covered by a deny rule.
fn uris_match(rule: &CompiledRule, uris: &[Option<String>]) -> bool {
    if uris.is_empty() {
        return false;
    }
    let covered = |uri: &Option<String>| match uri {
        Some(uri) => rule.uris.iter().any(|glob| glob.is_match(uri)),
        None => rule.effect == Effect::Deny,
    };
    match rule.effect {
        Effect::Allow => uris.iter().all(covered),
        Effect::Deny => uris.iter().any(covered),
    }
}

fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
    }
}

#[cfg(test)]
mod tests;
