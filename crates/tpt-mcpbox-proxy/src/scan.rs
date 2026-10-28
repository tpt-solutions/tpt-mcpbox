//! Pattern scan of upstream responses, configured per upstream by its `scan`
//! list. Each rule either redacts its matches or refuses the whole response.
//!
//! Only text is scanned: tool text blocks, text resource bodies, and every
//! string inside `structuredContent`. Binary bodies and links are passed
//! through unchanged. Matched text is never reported, only the rule's name.

use std::borrow::Cow;

use regex::{NoExpand, Regex};
use serde_json::Value;
use tpt_mcpbox_config::{ScanAction, ScanRule};
use tpt_mcpbox_protocol::content::{Content, ResourceContents};
use tpt_mcpbox_protocol::prompts::GetPromptResult;
use tpt_mcpbox_protocol::resources::ReadResourceResult;
use tpt_mcpbox_protocol::tools::CallToolResult;

/// A `refuse` rule matched a response, so the response is withheld.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// Name of the rule that matched.
    pub rule: String,
}

/// Compiled scan rules for one upstream. An empty scanner passes everything.
#[derive(Debug, Default)]
pub struct ResponseScanner {
    rules: Vec<Compiled>,
}

#[derive(Debug)]
struct Compiled {
    name: String,
    regex: Regex,
    action: ScanAction,
}

impl ResponseScanner {
    /// Compiles the rules, keeping their order.
    ///
    /// # Errors
    ///
    /// Returns the regex error for the first pattern that does not compile.
    /// Configuration validation catches this earlier.
    pub fn new(rules: &[ScanRule]) -> Result<Self, regex::Error> {
        let rules = rules
            .iter()
            .map(|rule| {
                Ok(Compiled {
                    name: rule.name.clone(),
                    regex: Regex::new(&rule.pattern)?,
                    action: rule.action,
                })
            })
            .collect::<Result<_, regex::Error>>()?;
        Ok(Self { rules })
    }

    /// Scans a tool result in place.
    ///
    /// # Errors
    ///
    /// Returns [`Refused`] when a `refuse` rule matches. `result` may already
    /// be partly rewritten in that case, so callers must drop it.
    pub fn scan_tool_result(&self, result: &mut CallToolResult) -> Result<(), Refused> {
        if self.rules.is_empty() {
            return Ok(());
        }
        for content in &mut result.content {
            self.scan_content(content)?;
        }
        if let Some(structured) = &mut result.structured_content {
            self.scan_value(structured)?;
        }
        Ok(())
    }

    /// Scans a `prompts/get` result in place: the description and every message.
    /// Same rules as [`ResponseScanner::scan_tool_result`].
    ///
    /// # Errors
    ///
    /// Returns [`Refused`] when a `refuse` rule matches.
    pub fn scan_prompt_result(&self, result: &mut GetPromptResult) -> Result<(), Refused> {
        if self.rules.is_empty() {
            return Ok(());
        }
        if let Some(description) = &mut result.description {
            *description = self.scan_str(description)?.into_owned();
        }
        for message in &mut result.messages {
            self.scan_content(&mut message.content)?;
        }
        Ok(())
    }

    /// Scans the text carried by one content block: its text, its embedded
    /// text resource, and a resource link's title and description.
    fn scan_content(&self, content: &mut Content) -> Result<(), Refused> {
        match content {
            Content::Text(text) => text.text = self.scan_str(&text.text)?.into_owned(),
            Content::Resource(ResourceContents::Text(body)) => {
                body.text = self.scan_str(&body.text)?.into_owned();
            }
            Content::ResourceLink(link) => {
                if let Some(title) = &mut link.title {
                    *title = self.scan_str(title)?.into_owned();
                }
                if let Some(description) = &mut link.description {
                    *description = self.scan_str(description)?.into_owned();
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Scans a `resources/read` result in place. Same rules as
    /// [`ResponseScanner::scan_tool_result`].
    ///
    /// # Errors
    ///
    /// Returns [`Refused`] when a `refuse` rule matches.
    pub fn scan_read_result(&self, result: &mut ReadResourceResult) -> Result<(), Refused> {
        if self.rules.is_empty() {
            return Ok(());
        }
        for contents in &mut result.contents {
            if let ResourceContents::Text(body) = contents {
                body.text = self.scan_str(&body.text)?.into_owned();
            }
        }
        Ok(())
    }

    fn scan_value(&self, value: &mut Value) -> Result<(), Refused> {
        match value {
            Value::String(text) => *text = self.scan_str(text)?.into_owned(),
            Value::Array(items) => {
                for item in items {
                    self.scan_value(item)?;
                }
            }
            Value::Object(fields) => {
                for field in fields.values_mut() {
                    self.scan_value(field)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn scan_str<'a>(&self, text: &'a str) -> Result<Cow<'a, str>, Refused> {
        let mut out = Cow::Borrowed(text);
        for rule in &self.rules {
            if !rule.regex.is_match(&out) {
                continue;
            }
            match rule.action {
                ScanAction::Refuse => {
                    return Err(Refused {
                        rule: rule.name.clone(),
                    });
                }
                ScanAction::Redact => {
                    let placeholder = format!("[redacted:{}]", rule.name);
                    let replaced = rule
                        .regex
                        .replace_all(&out, NoExpand(&placeholder))
                        .into_owned();
                    out = Cow::Owned(replaced);
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tpt_mcpbox_protocol::Role;
    use tpt_mcpbox_protocol::prompts::PromptMessage;

    use super::*;

    fn rule(name: &str, pattern: &str, action: ScanAction) -> ScanRule {
        ScanRule {
            name: name.to_owned(),
            pattern: pattern.to_owned(),
            action,
        }
    }

    #[test]
    fn prompt_messages_and_resource_links_are_scanned() {
        let scanner =
            ResponseScanner::new(&[rule("aws_key", "AKIA[0-9A-Z]{16}", ScanAction::Redact)])
                .unwrap();
        let key = "AKIAABCDEFGHIJKLMNOP";

        let mut prompt = GetPromptResult {
            description: Some(format!("uses {key}")),
            messages: vec![PromptMessage::text(Role::User, format!("key {key}"))],
        };
        scanner.scan_prompt_result(&mut prompt).unwrap();
        let Content::Text(text) = &prompt.messages[0].content else {
            panic!("a text message");
        };
        assert!(!text.text.contains(key));
        assert!(prompt.description.unwrap().contains("[redacted:aws_key]"));

        let mut result: CallToolResult = serde_json::from_value(json!({
            "content": [{
                "type": "resource_link",
                "uri": "file:///x",
                "name": "x",
                "description": format!("holds {key}")
            }]
        }))
        .unwrap();
        scanner.scan_tool_result(&mut result).unwrap();
        let Content::ResourceLink(link) = &result.content[0] else {
            panic!("still a resource link");
        };
        assert!(!link.description.as_deref().unwrap().contains(key));
    }

    fn text_result(text: &str) -> CallToolResult {
        serde_json::from_value(json!({
            "content": [{ "type": "text", "text": text }]
        }))
        .unwrap()
    }

    fn first_text(result: &CallToolResult) -> &str {
        match &result.content[0] {
            Content::Text(text) => &text.text,
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn redact_replaces_only_the_match() {
        let scanner =
            ResponseScanner::new(&[rule("aws_key", "AKIA[0-9A-Z]{16}", ScanAction::Redact)])
                .unwrap();
        let mut result = text_result("key AKIAABCDEFGHIJKLMNOP is set");
        scanner.scan_tool_result(&mut result).unwrap();
        assert_eq!(first_text(&result), "key [redacted:aws_key] is set");
    }

    #[test]
    fn refuse_names_the_rule_and_not_the_match() {
        let scanner =
            ResponseScanner::new(&[rule("card", r"\d{4}-\d{4}", ScanAction::Refuse)]).unwrap();
        let mut result = text_result("card 1234-5678");
        let refused = scanner.scan_tool_result(&mut result).unwrap_err();
        assert_eq!(refused.rule, "card");
        assert!(!format!("{refused:?}").contains("1234"));
    }

    #[test]
    fn structured_content_strings_are_scanned_at_any_depth() {
        let scanner =
            ResponseScanner::new(&[rule("token", "tok_[a-z]+", ScanAction::Redact)]).unwrap();
        let mut result: CallToolResult = serde_json::from_value(json!({
            "content": [],
            "structuredContent": { "a": [{ "b": "tok_secret" }], "n": 3 }
        }))
        .unwrap();
        scanner.scan_tool_result(&mut result).unwrap();
        assert_eq!(
            result.structured_content.unwrap(),
            json!({ "a": [{ "b": "[redacted:token]" }], "n": 3 })
        );
    }

    #[test]
    fn resource_text_is_scanned_and_binary_is_not() {
        let scanner = ResponseScanner::new(&[rule("pw", "hunter2", ScanAction::Refuse)]).unwrap();
        let mut ok: ReadResourceResult = serde_json::from_value(json!({
            "contents": [{ "uri": "x://a", "blob": "aHVudGVyMg==" }]
        }))
        .unwrap();
        scanner.scan_read_result(&mut ok).unwrap();

        let mut bad: ReadResourceResult = serde_json::from_value(json!({
            "contents": [{ "uri": "x://a", "text": "password hunter2" }]
        }))
        .unwrap();
        assert_eq!(scanner.scan_read_result(&mut bad).unwrap_err().rule, "pw");
    }

    #[test]
    fn empty_scanner_passes_everything_through() {
        let scanner = ResponseScanner::default();
        let mut result = text_result("AKIAABCDEFGHIJKLMNOP");
        scanner.scan_tool_result(&mut result).unwrap();
        assert_eq!(first_text(&result), "AKIAABCDEFGHIJKLMNOP");
    }

    #[test]
    fn rules_run_in_order() {
        // The first rule rewrites the text, so the second no longer matches.
        let scanner = ResponseScanner::new(&[
            rule("first", "secret", ScanAction::Redact),
            rule("second", "secret", ScanAction::Refuse),
        ])
        .unwrap();
        let mut result = text_result("secret");
        scanner.scan_tool_result(&mut result).unwrap();
        assert_eq!(first_text(&result), "[redacted:first]");
    }
}
