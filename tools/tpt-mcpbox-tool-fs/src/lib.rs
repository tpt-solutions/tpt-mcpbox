// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Example tool: files under a read root and a write root.
//!
//! The configuration grants `./workspace/**` for reading and
//! `./workspace/output/**` for writing. The host preopens those directories
//! under the guest names `/workspace` and `/workspace_output`, and the sandbox
//! refuses anything outside them, whatever this code does. The checks below
//! only give the agent a clear error for a bad path before the host sees it.

use std::path::Path;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use tpt_mcpbox_sdk::{Tool, ToolError, ToolResult, export_tools};

/// Guest name the host gives the read grant `./workspace/**`.
const READ_ROOT: &str = "/workspace";
/// Guest name the host gives the write grant `./workspace/output/**`.
const WRITE_ROOT: &str = "/workspace_output";

/// Accepts only a relative path with no `..` segment, so a path cannot name
/// anything above the root it is joined to.
fn checked(path: &str) -> Result<&str, ToolError> {
    let escapes = path.split(['/', '\\']).any(|segment| segment == "..");
    if path.is_empty() || path.starts_with('/') || path.contains('\0') || escapes {
        return Err(ToolError::new(format!(
            "path `{path}` must be relative to the workspace and must not contain `..`"
        )));
    }
    Ok(path)
}

#[derive(Deserialize, JsonSchema)]
struct ReadArgs {
    /// File to read, relative to the workspace, e.g. `notes/todo.md`.
    path: String,
}

struct ReadFile;

impl Tool for ReadFile {
    type Args = ReadArgs;
    const NAME: &'static str = "read_file";
    const DESCRIPTION: &'static str = "Reads a UTF-8 text file from the workspace";

    fn run(args: ReadArgs) -> Result<ToolResult, ToolError> {
        let path = checked(&args.path)?;
        std::fs::read_to_string(format!("{READ_ROOT}/{path}"))
            .map(ToolResult::text)
            .map_err(|error| ToolError::new(format!("cannot read `{path}`: {error}")))
    }
}

#[derive(Deserialize, JsonSchema)]
struct ListArgs {
    /// Directory to list, relative to the workspace. Empty for the top level.
    #[serde(default)]
    path: String,
}

struct ListDir;

impl Tool for ListDir {
    type Args = ListArgs;
    const NAME: &'static str = "list_dir";
    const DESCRIPTION: &'static str =
        "Lists the entries of a workspace directory; directories end with a slash";

    fn run(args: ListArgs) -> Result<ToolResult, ToolError> {
        let directory = if args.path.is_empty() {
            READ_ROOT.to_owned()
        } else {
            format!("{READ_ROOT}/{}", checked(&args.path)?)
        };
        let mut names: Vec<String> = std::fs::read_dir(&directory)
            .map_err(|error| ToolError::new(format!("cannot list `{}`: {error}", args.path)))?
            .filter_map(Result::ok)
            .map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                if entry.path().is_dir() {
                    format!("{name}/")
                } else {
                    name
                }
            })
            .collect();
        names.sort();
        ToolResult::json(&json!({ "entries": names }))
    }
}

#[derive(Deserialize, JsonSchema)]
struct WriteArgs {
    /// File to write, relative to the output directory, e.g. `report.md`.
    path: String,
    /// Full new contents of the file. Existing contents are replaced.
    content: String,
}

struct WriteFile;

impl Tool for WriteFile {
    type Args = WriteArgs;
    const NAME: &'static str = "write_file";
    const DESCRIPTION: &'static str =
        "Writes a text file into the output directory, replacing any existing file";

    fn run(args: WriteArgs) -> Result<ToolResult, ToolError> {
        let path = checked(&args.path)?;
        let target = format!("{WRITE_ROOT}/{path}");
        if let Some(parent) = Path::new(&target).parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                ToolError::new(format!("cannot create folders for `{path}`: {error}"))
            })?;
        }
        std::fs::write(&target, args.content.as_bytes())
            .map_err(|error| ToolError::new(format!("cannot write `{path}`: {error}")))?;
        ToolResult::json(&json!({ "written": path, "bytes": args.content.len() }))
    }
}

export_tools!(ReadFile, ListDir, WriteFile);
