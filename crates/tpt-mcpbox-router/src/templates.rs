// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Matching of concrete resource URIs against upstream URI templates.
//!
//! An agent that sees `logs://{app}/{date}` expands it itself and reads
//! `logs://web/2026-10-28`, so the router has to route that URI to the upstream
//! that owns the template. Only the two RFC 6570 forms that matter for matching
//! are supported: `{name}`, which matches text without a `/`, and `{+name}`,
//! which matches any text. Other operators (`{?x}`, `{#x}`, lists) are refused,
//! because guessing at them could route a URI to the wrong upstream.

use std::sync::Arc;

use tpt_mcpbox_protocol::resources::ResourceTemplate;
use tpt_mcpbox_proxy::PolicyGate;

/// One piece of a parsed template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    /// Text that must appear exactly.
    Literal(String),
    /// A variable. `reserved` is the `+` form, which may contain `/`.
    Variable { reserved: bool },
}

/// A parsed URI template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pattern {
    parts: Vec<Part>,
}

impl Pattern {
    /// Parses `template`, or returns `None` when it uses an unsupported form.
    pub(crate) fn parse(template: &str) -> Option<Self> {
        let mut parts = Vec::new();
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            if open > 0 {
                parts.push(Part::Literal(rest[..open].to_owned()));
            }
            let close = rest[open..].find('}')? + open;
            let expression = &rest[open + 1..close];
            let (reserved, name) = match expression.strip_prefix('+') {
                Some(name) => (true, name),
                None => (false, expression),
            };
            let name_ok = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
            if !name_ok {
                return None;
            }
            parts.push(Part::Variable { reserved });
            rest = &rest[close + 1..];
        }
        if rest.contains('}') {
            return None;
        }
        if !rest.is_empty() {
            parts.push(Part::Literal(rest.to_owned()));
        }
        Some(Self { parts })
    }

    /// `true` when `uri` is one expansion of this template.
    pub(crate) fn matches(&self, uri: &str) -> bool {
        matches_from(&self.parts, uri)
    }
}

/// Backtracking match. Templates are short, so the worst case stays small.
fn matches_from(parts: &[Part], uri: &str) -> bool {
    match parts.split_first() {
        None => uri.is_empty(),
        Some((Part::Literal(text), rest)) => uri
            .strip_prefix(text.as_str())
            .is_some_and(|tail| matches_from(rest, tail)),
        Some((Part::Variable { reserved }, rest)) => {
            let longest = if *reserved {
                uri.len()
            } else {
                uri.find('/').unwrap_or(uri.len())
            };
            (1..=longest)
                .filter(|&end| uri.is_char_boundary(end))
                .any(|end| matches_from(rest, &uri[end..]))
        }
    }
}

/// A template an upstream serves, with its parsed form and the upstream gate.
#[derive(Debug)]
pub(crate) struct TemplateRoute {
    pub(crate) template: ResourceTemplate,
    pub(crate) pattern: Pattern,
    pub(crate) gate: Arc<PolicyGate>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(template: &str, uri: &str) -> bool {
        Pattern::parse(template)
            .expect("template parses")
            .matches(uri)
    }

    #[test]
    fn simple_variables_do_not_cross_a_slash() {
        assert!(matches("logs://{app}/{date}", "logs://web/2026-10-28"));
        assert!(!matches("logs://{app}/{date}", "logs://web/a/b"));
        assert!(!matches("logs://{app}/{date}", "logs://web/"));
        assert!(!matches("logs://{app}/{date}", "logs:///2026"));
    }

    #[test]
    fn reserved_variables_may_contain_slashes() {
        assert!(matches("file:///{+path}", "file:///srv/docs/a.md"));
        assert!(!matches("file:///{path}", "file:///srv/docs/a.md"));
    }

    #[test]
    fn literals_must_match_exactly() {
        assert!(matches("notes://{id}", "notes://42"));
        assert!(!matches("notes://{id}", "other://42"));
        assert!(!matches("notes://{id}", "notes://42/extra"));
        assert!(matches("static/resource", "static/resource"));
        assert!(!matches("static/resource", "static/resource/more"));
    }

    #[test]
    fn dot_segments_can_match_a_variable() {
        // Routing matches the URI as given, and `..` is a valid variable value.
        // That is safe because the policy normalises a URI before its URI rules
        // decide, so an escape out of the tree is refused there.
        assert!(matches("file:///srv/{name}/x", "file:///srv/../x"));
        assert!(!matches("file:///srv/{name}", "file:///srv/../etc"));
    }

    #[test]
    fn unsupported_forms_are_refused() {
        for template in [
            "x://{?q}",
            "x://{#frag}",
            "x://{a,b}",
            "x://{}",
            "x://{open",
        ] {
            assert!(
                Pattern::parse(template).is_none(),
                "{template} should be refused"
            );
        }
    }

    #[test]
    fn multibyte_text_is_matched_on_character_boundaries() {
        assert!(matches("n://{name}", "n://café"));
        assert!(matches("n://{+rest}", "n://日本/語"));
    }
}
