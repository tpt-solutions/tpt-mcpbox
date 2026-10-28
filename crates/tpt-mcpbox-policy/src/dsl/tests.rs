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
        caller: None,
        uris: Vec::new(),
        constraints: None,
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
fn traversal_spellings_never_satisfy_an_exact_argument_rule() {
    // Argument predicates are exact JSON equality, not globs, so no spelling of
    // a traversal can stand in for the allowed path.
    let mut rule = rule("exact-path", Effect::Allow);
    rule.method = Some("tools/call".to_owned());
    rule.args
        .insert("path".to_owned(), json!("./workspace/notes.txt"));
    let engine = engine(vec![rule]);

    let mut input = call("fs_read");
    for spelling in [
        "./workspace/../etc/passwd",
        "./workspace/./../secret",
        "./workspace//notes.txt/../../x",
        "/abs/workspace/notes.txt",
        "./workspace/notes.txt ",
    ] {
        input.arguments = json!({ "path": spelling });
        assert!(
            !engine.evaluate(&input).is_allowed(),
            "{spelling:?} must not match"
        );
    }
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
        Err(PolicyError::RegoInDslOnly)
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

fn with_caller(mut input: PolicyInput, caller: &str) -> PolicyInput {
    input.caller = Some(caller.to_owned());
    input
}

fn with_uris(mut input: PolicyInput, uris: &[&str]) -> PolicyInput {
    input.uris = uris.iter().map(|u| (*u).to_owned()).collect();
    input
}

fn quota_rule(id: &str, max_calls: u32, window: Duration) -> Rule {
    let mut allow = rule(id, Effect::Allow);
    allow.tool = Some("search".to_owned());
    allow.constraints = Some(RuleConstraints {
        quota: Some(Quota { max_calls, window }),
        ..RuleConstraints::default()
    });
    allow
}

#[test]
fn caller_glob_requires_a_known_caller() {
    let mut allow = rule("sessions", Effect::Allow);
    allow.caller = Some("session-*".to_owned());
    let engine = engine(vec![allow]);

    assert!(
        engine
            .evaluate(&with_caller(call("t"), "session-7"))
            .is_allowed()
    );
    assert!(
        !engine
            .evaluate(&with_caller(call("t"), "intruder"))
            .is_allowed()
    );
    assert!(!engine.evaluate(&call("t")).is_allowed());
}

#[test]
fn allow_uri_rule_must_cover_every_requested_uri() {
    let mut allow = rule("docs", Effect::Allow);
    allow.uris = vec!["file:///srv/docs/**".to_owned()];
    let engine = engine(vec![allow]);

    let inside = with_uris(
        call("read"),
        &["file:///srv/docs/a.md", "file:///srv/docs/b/c.md"],
    );
    assert!(engine.evaluate(&inside).is_allowed());

    let smuggled = with_uris(
        call("read"),
        &["file:///srv/docs/a.md", "file:///srv/secret.txt"],
    );
    assert!(!engine.evaluate(&smuggled).is_allowed());
}

#[test]
fn deny_uri_rule_needs_only_one_covered_uri() {
    let mut deny = rule("secrets", Effect::Deny);
    deny.uris = vec!["file:///srv/secrets/**".to_owned()];
    let mut allow = rule("all-files", Effect::Allow);
    allow.uris = vec!["file:///**".to_owned()];
    let engine = engine(vec![deny, allow]);

    let mixed = with_uris(
        call("read"),
        &["file:///srv/public.md", "file:///srv/secrets/key"],
    );
    let decision = engine.evaluate(&mixed);
    assert!(!decision.is_allowed());
    assert_eq!(decision.rule_id.as_deref(), Some("secrets"));
}

#[test]
fn uri_that_cannot_be_normalised_is_never_allowed() {
    let mut allow = rule("docs", Effect::Allow);
    allow.uris = vec!["file:///srv/docs/**".to_owned()];
    let engine = engine(vec![allow]);

    let encoded = with_uris(call("read"), &["file:///srv/docs/%2e%2e/secret"]);
    assert!(!engine.evaluate(&encoded).is_allowed());
    let escaping = with_uris(call("read"), &["file:///srv/docs/../../etc/passwd"]);
    assert!(!engine.evaluate(&escaping).is_allowed());
}

#[test]
fn quota_admits_up_to_its_budget_then_refuses() {
    let engine = engine(vec![quota_rule("search", 2, Duration::from_secs(60))]);
    let base = Instant::now();
    let input = with_caller(call("search"), "alice");

    assert!(engine.evaluate_at(&input, base).is_allowed());
    assert!(
        engine
            .evaluate_at(&input, base + Duration::from_secs(1))
            .is_allowed()
    );
    let refused = engine.evaluate_at(&input, base + Duration::from_secs(2));
    assert!(!refused.is_allowed());
    assert_eq!(refused.rule_id.as_deref(), Some("search"));
    assert!(refused.reason.contains("quota"));
}

#[test]
fn quota_budget_recovers_as_the_window_slides() {
    let engine = engine(vec![quota_rule("search", 1, Duration::from_secs(60))]);
    let base = Instant::now();
    let input = with_caller(call("search"), "alice");

    assert!(engine.evaluate_at(&input, base).is_allowed());
    assert!(
        !engine
            .evaluate_at(&input, base + Duration::from_secs(59))
            .is_allowed()
    );
    assert!(
        engine
            .evaluate_at(&input, base + Duration::from_secs(60))
            .is_allowed()
    );
}

#[test]
fn quota_is_counted_per_caller() {
    let engine = engine(vec![quota_rule("search", 1, Duration::from_secs(60))]);
    let base = Instant::now();

    let alice = with_caller(call("search"), "alice");
    let bob = with_caller(call("search"), "bob");
    assert!(engine.evaluate_at(&alice, base).is_allowed());
    assert!(!engine.evaluate_at(&alice, base).is_allowed());
    assert!(engine.evaluate_at(&bob, base).is_allowed());
}

#[test]
fn quota_outcomes_are_never_cached() {
    let engine = engine(vec![quota_rule("search", 1, Duration::from_secs(60))]);
    let base = Instant::now();
    let input = with_caller(call("search"), "alice");

    assert!(engine.evaluate_at(&input, base).is_allowed());
    assert!(!engine.evaluate_at(&input, base).is_allowed());
    assert_eq!(cache_len(&engine), 0);
}

#[test]
fn allow_with_constraints_reports_its_limits() {
    let mut allow = rule("bounded", Effect::Allow);
    allow.tool = Some("fs_read".to_owned());
    allow.constraints = Some(RuleConstraints {
        quota: None,
        memory_limit: Some(32_000_000),
        time_limit: Some(Duration::from_secs(2)),
    });
    let engine = engine(vec![allow]);

    let decision = engine.evaluate(&call("fs_read"));
    assert!(decision.is_allowed());
    let limits = decision.constraints.expect("constraints reported");
    assert_eq!(limits.memory_limit, Some(32_000_000));
    assert_eq!(limits.time_limit, Some(Duration::from_secs(2)));
    assert!(engine.evaluate(&call("other")).constraints.is_none());
}

#[test]
fn dry_run_does_not_spend_quota_on_refused_calls_it_reports_as_allowed() {
    let mut cfg = config(vec![quota_rule("search", 1, Duration::from_secs(60))]);
    cfg.dry_run = true;
    let engine = Engine::from_config(&cfg).expect("policy compiles");
    let base = Instant::now();
    let input = with_caller(call("search"), "alice");

    assert!(engine.evaluate_at(&input, base).is_allowed());
    let second = engine.evaluate_at(&input, base);
    assert!(second.is_allowed(), "dry-run reports allow");
    assert!(
        second.is_dry_run_override(),
        "but records the would-be refusal"
    );
    assert_eq!(second.would_be, Effect::Deny);
}
