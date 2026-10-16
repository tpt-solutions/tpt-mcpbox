// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

use serde_json::json;

use super::*;

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
    }
}

fn config(rules: Vec<Rule>) -> PolicyConfig {
    PolicyConfig {
        rules,
        ..PolicyConfig::default()
    }
}

fn engine(rules: Vec<Rule>) -> Engine {
    Engine::from_config(&config(rules)).expect("policy compiles")
}

fn call(tool: &str) -> PolicyInput {
    PolicyInput {
        method: "tools/call".to_owned(),
        tool: Some(tool.to_owned()),
        ..PolicyInput::default()
    }
}

fn fs_read(path: &str) -> PolicyInput {
    PolicyInput {
        method: "tools/call".to_owned(),
        tool: Some("fs_read".to_owned()),
        fs_path: Some(path.to_owned()),
        ..PolicyInput::default()
    }
}

fn net(host: &str) -> PolicyInput {
    PolicyInput {
        method: "tools/call".to_owned(),
        tool: Some("github_search".to_owned()),
        host: Some(host.to_owned()),
        ..PolicyInput::default()
    }
}

fn cache_len(engine: &Engine) -> usize {
    engine
        .cache
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .len()
}

#[test]
fn no_rules_denies_by_default() {
    let decision = engine(vec![]).evaluate(&call("anything"));
    assert!(!decision.is_allowed());
    assert_eq!(decision.rule_id, None);
}

#[test]
fn first_matching_rule_wins() {
    let mut deny = rule("deny-search", Effect::Deny);
    deny.tool = Some("github_*".to_owned());
    let mut allow = rule("allow-all", Effect::Allow);
    allow.tool = Some("*".to_owned());
    let engine = engine(vec![deny, allow]);

    let decision = engine.evaluate(&call("github_search"));
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.rule_id.as_deref(), Some("deny-search"));

    let decision = engine.evaluate(&call("fs_read"));
    assert!(decision.is_allowed());
    assert_eq!(decision.rule_id.as_deref(), Some("allow-all"));
}

#[test]
fn method_and_argument_constraints_must_all_hold() {
    let mut rule = rule("exact-path", Effect::Allow);
    rule.method = Some("tools/call".to_owned());
    rule.args
        .insert("path".to_owned(), json!("./workspace/notes.txt"));
    let engine = engine(vec![rule]);

    let mut input = call("fs_read");
    input.arguments = json!({ "path": "./workspace/notes.txt", "extra": true });
    assert!(engine.evaluate(&input).is_allowed());

    input.arguments = json!({ "path": "./workspace/other.txt" });
    assert!(!engine.evaluate(&input).is_allowed());

    // A missing argument cannot satisfy a constraint on it.
    input.arguments = json!({});
    assert!(!engine.evaluate(&input).is_allowed());

    // A different method does not match.
    input.method = "resources/read".to_owned();
    input.arguments = json!({ "path": "./workspace/notes.txt" });
    assert!(!engine.evaluate(&input).is_allowed());
}

#[test]
fn host_allowlist_matches_case_insensitively_and_strips_root_dot() {
    let mut rule = rule("github", Effect::Allow);
    rule.hosts = vec!["api.github.com".to_owned()];
    let engine = engine(vec![rule]);

    assert!(engine.evaluate(&net("API.GitHub.com")).is_allowed());
    assert!(engine.evaluate(&net("api.github.com.")).is_allowed());
    assert!(
        !engine
            .evaluate(&net("api.github.com.evil.test"))
            .is_allowed()
    );
    assert!(!engine.evaluate(&net("evilgithub.com")).is_allowed());
}

#[test]
fn host_authority_tricks_never_match_an_allow_rule() {
    let mut rule = rule("github", Effect::Allow);
    rule.hosts = vec!["*".to_owned(), "*.github.com".to_owned()];
    let engine = engine(vec![rule]);

    for tricky in [
        "api.github.com:443@evil.test",
        "evil.test/api.github.com",
        "api.github.com:443",
        "*",
        "",
    ] {
        assert!(
            !engine.evaluate(&net(tricky)).is_allowed(),
            "{tricky:?} must not match"
        );
    }
}

#[test]
fn wildcard_host_glob_matches_subdomains_only() {
    let mut rule = rule("cdn", Effect::Allow);
    rule.hosts = vec!["*.githubusercontent.com".to_owned()];
    let engine = engine(vec![rule]);
    assert!(
        engine
            .evaluate(&net("raw.githubusercontent.com"))
            .is_allowed()
    );
    assert!(
        !engine
            .evaluate(&net("githubusercontent.com.evil.test"))
            .is_allowed()
    );
}

#[test]
fn path_star_does_not_cross_directories() {
    let mut rule = rule("workspace", Effect::Allow);
    rule.paths = vec!["./workspace/*".to_owned()];
    let engine = engine(vec![rule]);

    assert!(engine.evaluate(&fs_read("workspace/a.txt")).is_allowed());
    assert!(
        !engine
            .evaluate(&fs_read("workspace/sub/a.txt"))
            .is_allowed()
    );
}

#[test]
fn double_star_matches_nested_paths() {
    let mut deny = rule("no-ssh", Effect::Deny);
    deny.paths = vec!["**/.ssh/**".to_owned()];
    let mut allow = rule("home", Effect::Allow);
    allow.paths = vec!["home/**".to_owned()];
    let engine = engine(vec![deny, allow]);

    assert!(
        !engine
            .evaluate(&fs_read("home/user/.ssh/id_ed25519"))
            .is_allowed()
    );
    assert!(engine.evaluate(&fs_read("home/user/notes.md")).is_allowed());
}

#[test]
fn traversal_cannot_reach_an_allowed_tree() {
    let mut allow = rule("workspace", Effect::Allow);
    allow.paths = vec!["workspace/**".to_owned()];
    let engine = engine(vec![allow]);

    for escape in [
        "workspace/../secret.txt",
        "workspace/../../etc/passwd",
        "../workspace/x",
        "workspace\\..\\..\\secret",
    ] {
        assert!(
            !engine.evaluate(&fs_read(escape)).is_allowed(),
            "{escape:?} must not be allowed"
        );
    }
}

#[test]
fn dotdot_that_stays_inside_the_tree_is_allowed() {
    let mut allow = rule("workspace", Effect::Allow);
    allow.paths = vec!["workspace/**".to_owned()];
    let engine = engine(vec![allow]);
    assert!(
        engine
            .evaluate(&fs_read("workspace/a/../b.txt"))
            .is_allowed()
    );
}

#[test]
fn backslash_and_dot_prefixed_patterns_are_normalised() {
    let mut allow = rule("output", Effect::Allow);
    allow.paths = vec!["./workspace\\output/**".to_owned()];
    let engine = engine(vec![allow]);
    assert!(
        engine
            .evaluate(&fs_read("./workspace/output/x.bin"))
            .is_allowed()
    );
    assert!(
        !engine
            .evaluate(&fs_read("workspace/input/x.bin"))
            .is_allowed()
    );
}

#[test]
fn path_rule_does_not_match_when_request_has_no_path() {
    let mut allow = rule("everything", Effect::Allow);
    allow.paths = vec!["**".to_owned()];
    let engine = engine(vec![allow]);
    assert!(!engine.evaluate(&call("fs_read")).is_allowed());
}

#[cfg(windows)]
#[test]
fn path_matching_is_case_insensitive_on_windows() {
    let mut deny = rule("no-secret", Effect::Deny);
    deny.paths = vec!["C:/Secret/**".to_owned()];
    let mut allow = rule("all", Effect::Allow);
    allow.paths = vec!["**".to_owned()];
    let engine = engine(vec![deny, allow]);
    assert!(!engine.evaluate(&fs_read("c:\\secret\\key")).is_allowed());
}

#[test]
fn dry_run_allows_but_reports_what_would_be_denied() {
    let mut deny = rule("no-ssh", Effect::Deny);
    deny.paths = vec!["**/.ssh/**".to_owned()];
    let cfg = PolicyConfig {
        rules: vec![deny],
        dry_run: true,
        ..PolicyConfig::default()
    };
    let engine = Engine::from_config(&cfg).expect("compiles");

    let decision = engine.evaluate(&fs_read("home/.ssh/id"));
    assert!(decision.is_allowed());
    assert_eq!(decision.would_be, Effect::Deny);
    assert!(decision.is_dry_run_override());
    assert_eq!(decision.rule_id.as_deref(), Some("no-ssh"));
    assert!(decision.reason.starts_with("dry-run: would deny"));

    // Default-deny is also reported, not enforced.
    let decision = engine.evaluate(&call("unlisted"));
    assert!(decision.is_allowed());
    assert_eq!(decision.would_be, Effect::Deny);
}

#[test]
fn enforcing_mode_reports_no_override() {
    let decision = engine(vec![]).evaluate(&call("unlisted"));
    assert!(!decision.is_dry_run_override());
    assert_eq!(decision.effect, decision.would_be);
}

#[test]
fn duplicate_rule_ids_are_rejected() {
    let err = Engine::from_config(&config(vec![
        rule("same", Effect::Allow),
        rule("same", Effect::Deny),
    ]))
    .expect_err("duplicate ids must fail");
    assert!(matches!(err, PolicyError::DuplicateRuleId(id) if id == "same"));
}

#[test]
fn invalid_glob_is_rejected_with_rule_context() {
    let mut bad = rule("broken", Effect::Allow);
    bad.paths = vec!["workspace/[unclosed".to_owned()];
    let err = Engine::from_config(&config(vec![bad])).expect_err("bad glob must fail");
    assert!(matches!(
        err,
        PolicyError::InvalidGlob { ref rule, .. } if rule == "broken"
    ));
}

#[test]
fn rego_is_refused_rather_than_silently_ignored() {
    let cfg = PolicyConfig {
        rego: Some("policy.rego".into()),
        ..PolicyConfig::default()
    };
    assert!(matches!(
        Engine::from_config(&cfg),
        Err(PolicyError::RegoNotSupported)
    ));
}

#[test]
fn repeated_evaluation_is_served_from_cache_with_same_result() {
    let mut allow = rule("github", Effect::Allow);
    allow.hosts = vec!["api.github.com".to_owned()];
    let engine = engine(vec![allow]);

    let first = engine.evaluate(&net("API.github.com"));
    let second = engine.evaluate(&net("api.github.com."));
    assert_eq!(first, second);
    assert_eq!(cache_len(&engine), 1);
}

#[test]
fn cache_is_flushed_at_its_limit() {
    let engine = engine(vec![]);
    for i in 0..=CACHE_LIMIT {
        let _ = engine.evaluate(&call(&format!("tool_{i}")));
    }
    assert!(cache_len(&engine) <= CACHE_LIMIT);
}
