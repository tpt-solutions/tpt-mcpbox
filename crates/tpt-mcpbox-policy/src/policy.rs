// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Composition of the YAML DSL and the optional Rego module.
//!
//! Each evaluator gives an opinion on a request:
//!
//! - the DSL allows or denies when one of its rules matches, and has no opinion
//!   otherwise;
//! - a Rego module always has an opinion: it allows or denies.
//!
//! The opinions are combined conservatively, in a fixed order (DSL rules in file
//! order, then Rego):
//!
//! 1. any deny wins; the first deny in that order is reported;
//! 2. otherwise, any allow admits the call, and the limits of every allow are
//!    merged, keeping the tighter of each;
//! 3. with no opinion at all, `policy.default` applies.
//!
//! So an allow needs an explicit allow and no explicit deny, and a missing rule
//! can never open the gate on its own.

use std::time::Instant;

use tpt_mcpbox_config::{Effect, PolicyConfig, RuleConstraints};

use crate::decision::{Decision, PolicyInput};
use crate::dsl::{DslOutcome, Engine, enforce};
use crate::error::PolicyError;
use crate::rego::RegoEngine;

/// Rule id recorded for decisions made by the Rego module.
const REGO_RULE_ID: &str = "rego";

/// One evaluator's view of a request.
#[derive(Debug, Clone)]
struct Opinion {
    effect: Effect,
    rule_id: Option<String>,
    reason: String,
    constraints: Option<RuleConstraints>,
}

/// The whole `policy` section, compiled and ready to evaluate.
#[derive(Debug)]
pub struct Policy {
    dsl: Engine,
    rego: Option<RegoEngine>,
    dry_run: bool,
}

impl Policy {
    /// Compile the `policy` section, reading the Rego module if one is set.
    ///
    /// # Errors
    ///
    /// Returns an error if a DSL rule is invalid, a glob does not compile, or
    /// the Rego module cannot be read or compiled. A policy that cannot be fully
    /// built is never partially applied.
    pub fn from_config(config: &PolicyConfig) -> Result<Self, PolicyError> {
        let dsl = Engine::compile(config)?;
        let rego = config.rego.as_deref().map(RegoEngine::load).transpose()?;
        Ok(Self {
            dsl,
            rego,
            dry_run: config.dry_run,
        })
    }

    /// Compile a policy whose Rego module is given as source rather than a path.
    /// `module_name` appears in diagnostics only.
    ///
    /// # Errors
    ///
    /// As [`Policy::from_config`], except that `config.rego` is ignored and
    /// `rego_source` is compiled in its place.
    pub fn from_config_with_rego(
        config: &PolicyConfig,
        module_name: &str,
        rego_source: &str,
    ) -> Result<Self, PolicyError> {
        let dsl = Engine::compile(config)?;
        let rego = RegoEngine::from_source(module_name, rego_source.to_owned())?;
        Ok(Self {
            dsl,
            rego: Some(rego),
            dry_run: config.dry_run,
        })
    }

    /// Evaluate one request.
    #[must_use]
    pub fn evaluate(&self, input: &PolicyInput) -> Decision {
        self.evaluate_at(input, Instant::now(), true)
    }

    /// The id of an explicit DSL deny rule that refuses an outbound request a
    /// call has already been admitted for, or `None` when the request may go.
    ///
    /// Only DSL deny rules count. Allow rules, Rego and `policy.default` do not
    /// apply here: the call was admitted when it was made, and the sandbox's
    /// host allowlist governs outbound access. Dry-run never refuses.
    #[must_use]
    pub fn outbound_denial(&self, input: &PolicyInput) -> Option<String> {
        if self.dry_run {
            return None;
        }
        match self.dsl.outcome(input, Instant::now(), false) {
            DslOutcome::Matched(verdict) if verdict.effect == Effect::Deny => Some(verdict.rule_id),
            _ => None,
        }
    }

    /// Like [`Policy::evaluate`], but a quota is not spent. Use it to re-check a
    /// request that an earlier `evaluate` already admitted, such as each
    /// outbound network request of a tool call, so that one call is counted
    /// once against its quota.
    #[must_use]
    pub fn evaluate_recheck(&self, input: &PolicyInput) -> Decision {
        self.evaluate_at(input, Instant::now(), false)
    }

    /// Evaluate one request as of `now`. Exists so quota windows can be tested
    /// without sleeping. `charge` says whether a matched quota is spent.
    pub(crate) fn evaluate_at(&self, input: &PolicyInput, now: Instant, charge: bool) -> Decision {
        let mut opinions = Vec::with_capacity(2);
        if let DslOutcome::Matched(verdict) = self.dsl.outcome(input, now, charge) {
            opinions.push(Opinion {
                effect: verdict.effect,
                rule_id: Some(verdict.rule_id),
                reason: verdict.reason,
                constraints: verdict.constraints,
            });
        }
        if let Some(rego) = &self.rego {
            opinions.push(rego_opinion(rego, input));
        }

        let decided = combine(opinions).unwrap_or_else(|| Opinion {
            effect: self.dsl.default_effect(),
            rule_id: None,
            reason: format!(
                "no rule matched; policy.default is {}",
                match self.dsl.default_effect() {
                    Effect::Allow => "allow",
                    Effect::Deny => "deny",
                }
            ),
            constraints: None,
        });

        let decision = enforce(
            self.dry_run,
            decided.effect,
            decided.rule_id,
            decided.reason,
            decided.constraints,
        );
        tracing::debug!(
            method = %input.method,
            effect = ?decision.effect,
            would_be = ?decision.would_be,
            rule = decision.rule_id.as_deref().unwrap_or("<default>"),
            "policy decision",
        );
        decision
    }

    /// Build the policy for a reloaded configuration.
    ///
    /// The new policy starts with an empty decision cache, and it inherits the
    /// quota counters of `self` for every rule that still carries a quota, so a
    /// reload cannot be used to reset a caller's budget.
    ///
    /// # Errors
    ///
    /// As [`Policy::from_config`]. On error the current policy is untouched,
    /// because the caller keeps using `self`.
    pub fn reload(&self, config: &PolicyConfig) -> Result<Self, PolicyError> {
        let next = Self::from_config(config)?;
        next.dsl.inherit_quotas(&self.dsl);
        Ok(next)
    }
}

/// Ask the Rego module for its opinion. An evaluation error counts as a deny.
fn rego_opinion(rego: &RegoEngine, input: &PolicyInput) -> Opinion {
    match rego.allows(input) {
        Ok(true) => Opinion {
            effect: Effect::Allow,
            rule_id: Some(REGO_RULE_ID.to_owned()),
            reason: "Rego module allowed the request".to_owned(),
            constraints: None,
        },
        Ok(false) => Opinion {
            effect: Effect::Deny,
            rule_id: Some(REGO_RULE_ID.to_owned()),
            reason: "Rego module did not allow the request".to_owned(),
            constraints: None,
        },
        Err(message) => Opinion {
            effect: Effect::Deny,
            rule_id: Some(REGO_RULE_ID.to_owned()),
            reason: format!("Rego evaluation failed, refusing the request: {message}"),
            constraints: None,
        },
    }
}

/// Combine opinions in order. Returns `None` when there were none.
fn combine(opinions: Vec<Opinion>) -> Option<Opinion> {
    if let Some(deny) = opinions.iter().find(|o| o.effect == Effect::Deny) {
        return Some(deny.clone());
    }
    let allows: Vec<Opinion> = opinions
        .into_iter()
        .filter(|o| o.effect == Effect::Allow)
        .collect();
    let first = allows.first()?.clone();
    // Every allow's limits apply, so the call runs under the tightest of them.
    let mut constraints = None;
    for allow in &allows {
        if let Some(limits) = &allow.constraints {
            tighten(&mut constraints, limits);
        }
    }
    Some(Opinion {
        constraints,
        ..first
    })
}

/// Tighten `into` by `other`: the smaller memory and time limits win, and an
/// existing quota is kept (only the DSL produces quotas, so there is no second
/// one to merge).
fn tighten(into: &mut Option<RuleConstraints>, other: &RuleConstraints) {
    let current = into.get_or_insert_with(RuleConstraints::default);
    current.memory_limit = min_option(current.memory_limit, other.memory_limit);
    current.time_limit = min_option(current.time_limit, other.time_limit);
    if current.quota.is_none() {
        current.quota.clone_from(&other.quota);
    }
}

fn min_option<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
mod tests;
