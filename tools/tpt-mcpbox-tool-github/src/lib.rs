// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Example tool: searches GitHub repositories.
//!
//! This component never sees a credential. The configuration binds the
//! `GITHUB_TOKEN` secret to the `Authorization` header for `api.github.com`,
//! and the host adds it to the outbound request. The tool sends only the
//! headers that identify it.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use tpt_mcpbox_sdk::{Tool, ToolError, ToolResult, export_tools, http};

const SEARCH_URL: &str = "https://api.github.com/search/repositories";

#[derive(Deserialize, JsonSchema)]
struct SearchArgs {
    /// GitHub search query, for example `language:rust mcp`.
    query: String,
    /// How many repositories to return, from 1 to 20. Defaults to 5.
    #[serde(default)]
    limit: Option<u8>,
}

struct SearchRepos;

impl Tool for SearchRepos {
    type Args = SearchArgs;
    const NAME: &'static str = "search_repos";
    const DESCRIPTION: &'static str =
        "Searches GitHub repositories and returns each one's name, URL, description and star count";

    fn run(args: SearchArgs) -> Result<ToolResult, ToolError> {
        let query = args.query.trim();
        if query.is_empty() {
            return Err(ToolError::new("query must not be empty"));
        }
        let limit = args.limit.unwrap_or(5).clamp(1, 20);
        let url = format!("{SEARCH_URL}?q={}&per_page={limit}", percent_encode(query));
        let body = http::get_json_with_headers(
            &url,
            &[
                ("User-Agent", "tpt-mcpbox-tool-github"),
                ("Accept", "application/vnd.github+json"),
            ],
        )?;

        let repositories: Vec<Value> = body["items"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .take(usize::from(limit))
            .map(|repo| {
                json!({
                    "full_name": repo["full_name"],
                    "url": repo["html_url"],
                    "description": repo["description"],
                    "stars": repo["stargazers_count"],
                })
            })
            .collect();

        ToolResult::json(&json!({
            "total_count": body["total_count"],
            "repositories": repositories,
        }))
    }
}

/// Percent-encodes everything outside the RFC 3986 unreserved set.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

export_tools!(SearchRepos);
