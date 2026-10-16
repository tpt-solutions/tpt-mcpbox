// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Input and output types shared by every policy evaluator.

use serde::{Deserialize, Serialize};
use tpt_mcpbox_config::{Effect, RuleConstraints};

/// Everything a policy rule may look at for one request.
///
/// Fields a request does not carry are left empty. A rule that constrains a
/// field the input does not have never matches, so an absent value cannot
/// satisfy an allow rule.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyInput {
    /// MCP method, e.g. `tools/call`.
    pub method: String,
    /// Identity of the calling client or session, when the transport knows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    /// Tool name for `tools/call`, taken from `params.name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Tool arguments, i.e. `params.arguments`. `null` when absent.
    #[serde(default)]
    pub arguments: serde_json::Value,
    /// Outbound target host, when the request reaches the network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Filesystem path the request touches, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_path: Option<String>,
    /// Resource URIs the request reads or subscribes to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uris: Vec<String>,
}

/// The result of evaluating one [`PolicyInput`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    /// What the proxy enforces. In dry-run mode this is always `Allow`.
    pub effect: Effect,
    /// What the policy would have enforced without dry-run. Equal to
    /// [`Decision::effect`] outside dry-run mode.
    pub would_be: Effect,
    /// Id of the rule that decided, or `None` when the default applied.
    pub rule_id: Option<String>,
    /// Human-readable explanation, recorded in the audit log.
    pub reason: String,
    /// Limits the runtime must enforce for an allowed call. `None` for denials
    /// and for allows that carry no constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<RuleConstraints>,
}

impl Decision {
    /// `true` when the call may proceed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.effect == Effect::Allow
    }

    /// `true` when a non-dry-run engine would have refused the call.
    #[must_use]
    pub fn is_dry_run_override(&self) -> bool {
        self.effect != self.would_be
    }
}
