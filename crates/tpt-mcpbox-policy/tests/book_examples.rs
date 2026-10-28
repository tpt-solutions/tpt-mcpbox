// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! The YAML and Rego examples in the documentation must stay valid.
//!
//! Every fenced `yaml` block in `docs/` and `docs/book/src/` is parsed as a
//! configuration document, validated in serve mode and its policy compiled.
//! Every fenced `rego` block is compiled and evaluated once. A snippet that
//! sets `policy.rego` is pointed at the book's own Rego example, so the two
//! halves of the policy guide are checked together.

use std::path::{Path, PathBuf};

use tpt_mcpbox_config::{Severity, ValidationMode, load_str, validate};
use tpt_mcpbox_policy::{Policy, PolicyInput};

/// One fenced code block.
#[derive(Debug)]
struct Snippet {
    file: PathBuf,
    line: usize,
    lang: String,
    body: String,
}

impl Snippet {
    fn origin(&self) -> String {
        format!("{}:{}", self.file.display(), self.line)
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

fn markdown_files() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut files = Vec::new();
    for dir in [root.join("docs"), root.join("docs/book/src")] {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()));
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.extension().is_some_and(|ext| ext == "md") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Extract fenced blocks. Only backtick fences at the start of a line are
/// recognised, which is the only style the docs use.
fn snippets(file: &Path) -> Vec<Snippet> {
    let text = std::fs::read_to_string(file)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", file.display()));
    let mut found = Vec::new();
    let mut open: Option<(usize, String, String)> = None;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_end();
        match open.take() {
            None => {
                if let Some(info) = trimmed.strip_prefix("```") {
                    let lang = info.split_whitespace().next().unwrap_or("").to_owned();
                    open = Some((index + 1, lang, String::new()));
                }
            }
            Some((start, lang, mut body)) => {
                if trimmed == "```" {
                    found.push(Snippet {
                        file: file.to_path_buf(),
                        line: start,
                        lang,
                        body,
                    });
                } else {
                    body.push_str(line);
                    body.push('\n');
                    open = Some((start, lang, body));
                }
            }
        }
    }
    assert!(
        open.is_none(),
        "{} has an unclosed code fence",
        file.display()
    );
    found
}

fn all_snippets(lang: &str) -> Vec<Snippet> {
    markdown_files()
        .iter()
        .flat_map(|file| snippets(file))
        .filter(|snippet| snippet.lang == lang)
        .collect()
}

#[test]
fn fence_extraction_handles_languages_and_bodies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sample.md");
    std::fs::write(
        &path,
        "intro\n\n```yaml\na: 1\n```\n\n```\nplain\n```\n\n```rego title\npackage x\n```\n",
    )
    .expect("write");

    let found = snippets(&path);
    let langs: Vec<&str> = found.iter().map(|s| s.lang.as_str()).collect();
    assert_eq!(langs, ["yaml", "", "rego"]);
    assert_eq!(found[0].body, "a: 1\n");
    assert_eq!(found[0].line, 3);
    assert_eq!(found[2].body, "package x\n");
}

#[test]
fn rego_examples_compile_and_evaluate() {
    let rego = all_snippets("rego");
    assert!(!rego.is_empty(), "no rego examples found in the docs");

    for snippet in &rego {
        let policy =
            Policy::from_config_with_rego(&Default::default(), &snippet.origin(), &snippet.body)
                .unwrap_or_else(|error| panic!("{} does not compile: {error}", snippet.origin()));

        let decision = policy.evaluate(&PolicyInput {
            method: "tools/call".to_owned(),
            tool: Some("example".to_owned()),
            ..PolicyInput::default()
        });
        assert!(
            !decision.reason.contains("evaluation failed"),
            "{} fails to evaluate: {}",
            snippet.origin(),
            decision.reason
        );
    }
}

#[test]
fn yaml_examples_are_valid_configuration() {
    let yaml = all_snippets("yaml");
    // The configuration reference alone has six; a lower count means the
    // extraction broke, not that the docs got shorter.
    assert!(
        yaml.len() >= 6,
        "found only {} yaml examples in the docs",
        yaml.len()
    );

    let rego = all_snippets("rego");
    let dir = tempfile::tempdir().expect("tempdir");
    let rego_path = dir.path().join("policy.rego");
    std::fs::write(
        &rego_path,
        &rego
            .first()
            .expect("the policy guide has a rego example")
            .body,
    )
    .expect("write rego");

    for snippet in &yaml {
        let origin = snippet.origin();
        let mut config = load_str(&snippet.body, &origin)
            .unwrap_or_else(|error| panic!("{origin} does not parse: {error}"));
        if config.policy.rego.is_some() {
            config.policy.rego = Some(rego_path.clone());
        }

        let report = validate(&config, ValidationMode::Serve);
        let errors = report.of_severity(Severity::Error);
        assert!(errors.is_empty(), "{origin} fails validation: {errors:?}");

        Policy::from_config(&config.policy)
            .unwrap_or_else(|error| panic!("{origin}: policy does not compile: {error}"));
    }
}
