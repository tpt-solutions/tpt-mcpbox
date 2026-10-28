// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::json;
use tpt_mcpbox_config::{Effect, PolicyConfig, Quota, Rule, RuleConstraints};

use super::*;

/// Module that allows `fs_read` and nothing else.
const ALLOW_FS_READ: &str = r#"
package tpt.mcpbox

default allow := false

allow if {
    input.method == "tools/call"
    input.tool == "fs_read"
}
"#;

/// Module that allows everything, so tests can isolate the DSL's effect.
const ALLOW_ALL: &str = r#"
package tpt.mcpbox

default allow := true
"#;

/// Module with no default, so `allow` is undefined for most inputs. Undefined
/// must count as a refusal.
const NO_DEFAULT: &str = r#"
package tpt.mcpbox

allow if {
    input.tool == "fs_read"
}
"#;

fn rule(id: &str, effect: Effect) -> Rule {
    Rule {
        id: id.to_owned(),
        description: None,
        effect,
        tool: None,
        method: None,
        args: BTreeMap::new(),
        hosts: Vec::new(),
        paths: Vec::new(),
        caller: None,
        uris: Vec::new(),
        constraints: None,
    }
}

fn tool_rule(id: &str, effect: Effect, tool: &str) -> Rule {
    let mut r = rule(id, effect);
    r.tool = Some(tool.to_owned());
    r
}

fn call(tool: &str) -> PolicyInput {
    PolicyInput {
        method: "tools/call".to_owned(),
        tool: Some(tool.to_owned()),
        ..PolicyInput::default()
    }
}

fn dsl_only(rules: Vec<Rule>) -> PolicyConfig {
    PolicyConfig {
        rules,
        ..PolicyConfig::default()
    }
}

fn with_rego(rules: Vec<Rule>, source: &str) -> Policy {
    Policy::from_config_with_rego(&dsl_only(rules), "test.rego", source).expect("policy compiles")
}

#[test]
fn dsl_alone_decides_when_there_is_no_rego() {
    let policy = Policy::from_config(&dsl_only(vec![tool_rule("read", Effect::Allow, "fs_read")]))
        .expect("policy compiles");

    let decision = policy.evaluate(&call("fs_read"));
    assert!(decision.is_allowed());
    assert_eq!(decision.rule_id.as_deref(), Some("read"));
    assert!(!policy.evaluate(&call("fs_write")).is_allowed());
}

#[test]
fn rego_decides_when_the_dsl_has_no_opinion() {
    let policy = with_rego(vec![], ALLOW_FS_READ);

    let allowed = policy.evaluate(&call("fs_read"));
    assert!(allowed.is_allowed());
    assert_eq!(allowed.rule_id.as_deref(), Some("rego"));

    let refused = policy.evaluate(&call("fs_write"));
    assert!(!refused.is_allowed());
    assert_eq!(refused.rule_id.as_deref(), Some("rego"));
}

#[test]
fn dsl_allow_needs_rego_to_agree() {
    let policy = with_rego(
        vec![tool_rule("everything", Effect::Allow, "fs_write")],
        ALLOW_FS_READ,
    );

    let decision = policy.evaluate(&call("fs_write"));
    assert!(
        !decision.is_allowed(),
        "rego said no, so the call is refused"
    );
    assert_eq!(decision.rule_id.as_deref(), Some("rego"));
}

#[test]
fn dsl_deny_overrides_a_rego_allow() {
    let policy = with_rego(
        vec![tool_rule("freeze", Effect::Deny, "fs_read")],
        ALLOW_ALL,
    );

    let decision = policy.evaluate(&call("fs_read"));
    assert!(!decision.is_allowed());
    assert_eq!(decision.rule_id.as_deref(), Some("freeze"));
}

#[test]
fn undefined_rego_allow_is_a_refusal() {
    let policy = with_rego(vec![], NO_DEFAULT);

    let decision = policy.evaluate(&call("fs_write"));
    assert!(!decision.is_allowed());
    assert!(decision.reason.contains("Rego evaluation failed"));
}

#[test]
fn no_opinion_anywhere_applies_the_default() {
    let policy = Policy::from_config(&dsl_only(vec![])).expect("policy compiles");

    let decision = policy.evaluate(&call("anything"));
    assert!(!decision.is_allowed());
    assert_eq!(decision.rule_id, None);
    assert!(decision.reason.contains("policy.default is deny"));
}

#[test]
fn rego_module_is_read_from_the_configured_path() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("policy.rego");
    std::fs::write(&path, ALLOW_FS_READ).expect("write module");
    let config = PolicyConfig {
        rego: Some(path),
        ..PolicyConfig::default()
    };

    let policy = Policy::from_config(&config).expect("policy compiles");
    assert!(policy.evaluate(&call("fs_read")).is_allowed());
}

#[test]
fn missing_rego_module_is_a_compile_error() {
    let config = PolicyConfig {
        rego: Some("does-not-exist.rego".into()),
        ..PolicyConfig::default()
    };
    assert!(matches!(
        Policy::from_config(&config),
        Err(PolicyError::RegoRead { .. })
    ));
}

#[test]
fn malformed_rego_module_is_a_compile_error() {
    let result = Policy::from_config_with_rego(
        &dsl_only(vec![]),
        "bad.rego",
        "package tpt.mcpbox\nallow if {",
    );
    assert!(matches!(result, Err(PolicyError::RegoCompile { .. })));
}

#[test]
fn rego_sees_the_caller_and_uris_in_its_input() {
    const CALLER_MODULE: &str = r#"
package tpt.mcpbox

default allow := false

allow if {
    input.caller == "alice"
    input.uris[0] == "file:///srv/docs/a.md"
}
"#;
    let policy = with_rego(vec![], CALLER_MODULE);
    let mut input = call("read");
    input.caller = Some("alice".to_owned());
    input.uris = vec!["file:///srv/docs/a.md".to_owned()];
    assert!(policy.evaluate(&input).is_allowed());

    input.caller = Some("mallory".to_owned());
    assert!(!policy.evaluate(&input).is_allowed());
}

#[test]
fn rego_sees_normalised_hosts_and_paths() {
    const MODULE: &str = r#"
package tpt.mcpbox

default allow := false

allow if {
    input.host == "api.github.com"
    not startswith(input.fs_path, "secret/")
}
"#;
    let policy = with_rego(vec![], MODULE);
    let mut input = call("fetch");
    input.host = Some("API.GitHub.com.".to_owned());
    input.fs_path = Some("notes/./a.md".to_owned());
    assert!(policy.evaluate(&input).is_allowed());

    input.fs_path = Some("notes/../secret/key.pem".to_owned());
    assert!(!policy.evaluate(&input).is_allowed());
}

#[test]
fn rego_refuses_a_request_it_cannot_normalise() {
    const MODULE: &str = r#"
package tpt.mcpbox

default allow := false

allow if not startswith(input.fs_path, "secret/")
"#;
    let policy = with_rego(vec![], MODULE);
    let mut input = call("fetch");
    input.fs_path = Some("../secret/key.pem".to_owned());
    let decision = policy.evaluate(&input);
    assert!(!decision.is_allowed());
    assert!(
        decision.reason.contains("cannot be normalised"),
        "{}",
        decision.reason
    );
    assert!(!decision.reason.contains("key.pem"));
}

#[test]
fn dry_run_reports_a_rego_refusal_as_would_be_deny() {
    let mut config = dsl_only(vec![]);
    config.dry_run = true;
    let policy =
        Policy::from_config_with_rego(&config, "test.rego", ALLOW_FS_READ).expect("compiles");

    let decision = policy.evaluate(&call("fs_write"));
    assert!(decision.is_allowed(), "dry-run enforces allow");
    assert_eq!(decision.would_be, Effect::Deny);
    assert!(decision.is_dry_run_override());
}

#[test]
fn combine_denies_when_any_opinion_denies() {
    let opinions = vec![
        Opinion {
            effect: Effect::Allow,
            rule_id: Some("a".to_owned()),
            reason: "a".to_owned(),
            constraints: None,
        },
        Opinion {
            effect: Effect::Deny,
            rule_id: Some("b".to_owned()),
            reason: "b".to_owned(),
            constraints: None,
        },
    ];
    let decided = combine(opinions).expect("has opinions");
    assert_eq!(decided.effect, Effect::Deny);
    assert_eq!(decided.rule_id.as_deref(), Some("b"));
}

#[test]
fn combine_keeps_the_tighter_limit_of_each_allow() {
    let loose = RuleConstraints {
        quota: None,
        memory_limit: Some(64_000_000),
        time_limit: None,
    };
    let tight = RuleConstraints {
        quota: None,
        memory_limit: Some(16_000_000),
        time_limit: Some(Duration::from_secs(1)),
    };
    let allow = |constraints| Opinion {
        effect: Effect::Allow,
        rule_id: Some("x".to_owned()),
        reason: "x".to_owned(),
        constraints: Some(constraints),
    };

    let decided = combine(vec![allow(loose), allow(tight)]).expect("has opinions");
    let merged = decided.constraints.expect("merged limits");
    assert_eq!(merged.memory_limit, Some(16_000_000));
    assert_eq!(merged.time_limit, Some(Duration::from_secs(1)));
}

#[test]
fn reload_keeps_quota_counters_for_surviving_rules() {
    let mut quota = tool_rule("search", Effect::Allow, "search");
    quota.constraints = Some(RuleConstraints {
        quota: Some(Quota {
            max_calls: 1,
            window: Duration::from_secs(3600),
        }),
        ..RuleConstraints::default()
    });
    let config = dsl_only(vec![quota]);
    let policy = Policy::from_config(&config).expect("policy compiles");
    let base = Instant::now();

    assert!(policy.evaluate_at(&call("search"), base).is_allowed());

    let reloaded = policy.reload(&config).expect("reload compiles");
    assert!(
        !reloaded.evaluate_at(&call("search"), base).is_allowed(),
        "a reload must not reset the budget"
    );
}

#[test]
fn reload_drops_counters_of_removed_rules() {
    let mut quota = tool_rule("search", Effect::Allow, "search");
    quota.constraints = Some(RuleConstraints {
        quota: Some(Quota {
            max_calls: 1,
            window: Duration::from_secs(3600),
        }),
        ..RuleConstraints::default()
    });
    let policy = Policy::from_config(&dsl_only(vec![quota])).expect("policy compiles");
    let base = Instant::now();
    assert!(policy.evaluate_at(&call("search"), base).is_allowed());

    let reloaded = policy
        .reload(&dsl_only(vec![tool_rule("other", Effect::Allow, "search")]))
        .expect("reload compiles");
    assert_eq!(reloaded.dsl.quota_bucket_count(), 0);
}

#[test]
fn reload_that_fails_to_compile_is_an_error_and_keeps_the_old_policy() {
    let policy = Policy::from_config(&dsl_only(vec![tool_rule("read", Effect::Allow, "fs_read")]))
        .expect("policy compiles");
    let broken = PolicyConfig {
        rego: Some("missing.rego".into()),
        ..PolicyConfig::default()
    };

    assert!(policy.reload(&broken).is_err());
    assert!(policy.evaluate(&call("fs_read")).is_allowed());
}

#[test]
fn rego_input_document_is_stable() {
    let mut input = call("fs_read");
    input.caller = Some("alice".to_owned());
    input.uris = vec!["file:///a".to_owned()];
    let value = serde_json::to_value(&input).expect("serialises");

    assert_eq!(
        value,
        json!({
            "method": "tools/call",
            "caller": "alice",
            "tool": "fs_read",
            "arguments": null,
            "uris": ["file:///a"],
        })
    );
}
