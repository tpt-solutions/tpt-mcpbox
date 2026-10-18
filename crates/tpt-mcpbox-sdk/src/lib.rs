// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Guest SDK for tpt-mcpbox tool components.
//!
//! A tool is a type that implements [`Tool`]. Its argument type derives
//! `Deserialize` and `JsonSchema`, and the schema advertised to the agent is
//! generated from it. [`export_tools!`] turns a list of tools into the
//! component's `describe` and `call` exports:
//!
//! ```ignore
//! use tpt_mcpbox_sdk::{Tool, ToolError, ToolResult, export_tools};
//!
//! #[derive(serde::Deserialize, schemars::JsonSchema)]
//! struct GreetArgs {
//!     /// Who to greet.
//!     name: String,
//! }
//!
//! struct Greet;
//!
//! impl Tool for Greet {
//!     type Args = GreetArgs;
//!     const NAME: &'static str = "greet";
//!     const DESCRIPTION: &'static str = "Greets someone by name";
//!
//!     fn run(args: GreetArgs) -> Result<ToolResult, ToolError> {
//!         Ok(ToolResult::text(format!("Hello, {}!", args.name)))
//!     }
//! }
//!
//! export_tools!(Greet);
//! ```
//!
//! Errors returned from [`Tool::run`] reach the agent as a tool error
//! (`isError: true`), not as a protocol error, so the agent can read the reason
//! and retry.

#![forbid(unsafe_code)]

pub mod http;

#[doc(hidden)]
pub mod __bindings {
    wit_bindgen::generate!({
        path: "../tpt-mcpbox-runtime/wit",
        world: "tool",
        pub_export_macro: true,
        default_bindings_module: "tpt_mcpbox_sdk::__bindings",
    });
}

#[doc(hidden)]
pub use schemars as __schemars;
#[doc(hidden)]
pub use serde_json as __serde_json;

use std::fmt;

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// One tool the component provides.
pub trait Tool {
    /// Arguments the agent sends. Its JSON schema is advertised to the agent.
    type Args: DeserializeOwned + JsonSchema;
    /// Name the agent calls the tool by. Unique within the component.
    const NAME: &'static str;
    /// What the tool does, in words the agent can use to choose it.
    const DESCRIPTION: &'static str;

    /// Runs the tool with validated arguments.
    ///
    /// # Errors
    ///
    /// Return a [`ToolError`] for anything the agent should see as a failure.
    fn run(args: Self::Args) -> Result<ToolResult, ToolError>;
}

/// Text returned to the agent for a successful call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    text: String,
}

impl ToolResult {
    /// A plain-text result.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }

    /// A JSON result, rendered as compact JSON text.
    ///
    /// # Errors
    ///
    /// Returns a [`ToolError`] if the value cannot be serialised.
    pub fn json(value: &impl serde::Serialize) -> Result<Self, ToolError> {
        serde_json::to_string(value)
            .map(Self::text)
            .map_err(|error| ToolError::new(format!("cannot encode result: {error}")))
    }

    /// The text that will be returned to the agent.
    #[must_use]
    pub fn as_text(&self) -> &str {
        &self.text
    }
}

/// A failure the agent should see and may act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError {
    message: String,
}

impl ToolError {
    /// A failure with the given message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The message that will be returned to the agent.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ToolError {}

impl From<String> for ToolError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for ToolError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

/// One registered tool, as the export macro sees it.
#[doc(hidden)]
pub struct Entry {
    pub name: &'static str,
    pub descriptor: fn() -> Value,
    pub call: fn(&str) -> Result<String, String>,
}

/// Builds the registry entry for `T`.
#[doc(hidden)]
#[must_use]
pub fn entry<T: Tool>() -> Entry {
    Entry {
        name: T::NAME,
        descriptor: descriptor::<T>,
        call: call::<T>,
    }
}

fn descriptor<T: Tool>() -> Value {
    let schema = schemars::schema_for!(T::Args);
    json!({
        "name": T::NAME,
        "description": T::DESCRIPTION,
        "input_schema": serde_json::to_value(schema).unwrap_or(Value::Null),
    })
}

fn call<T: Tool>(arguments: &str) -> Result<String, String> {
    let source = if arguments.trim().is_empty() {
        "{}"
    } else {
        arguments
    };
    let args: T::Args = serde_json::from_str(source)
        .map_err(|error| format!("invalid arguments for `{}`: {error}", T::NAME))?;
    T::run(args)
        .map(|result| result.text)
        .map_err(|error| error.message)
}

/// JSON array the component reports from `describe`.
#[doc(hidden)]
#[must_use]
pub fn describe(entries: &[Entry]) -> String {
    let array: Vec<Value> = entries.iter().map(|entry| (entry.descriptor)()).collect();
    Value::Array(array).to_string()
}

/// Routes a `call` to the tool with `name`.
///
/// # Errors
///
/// Returns the tool's error message, or an error naming an unknown tool.
#[doc(hidden)]
pub fn dispatch(entries: &[Entry], name: &str, arguments: &str) -> Result<String, String> {
    match entries.iter().find(|entry| entry.name == name) {
        Some(entry) => (entry.call)(arguments),
        None => Err(format!("unknown tool `{name}`")),
    }
}

/// Exports the listed [`Tool`] types as this component's tools.
///
/// Expands to a `describe` and a `call` export. Use it once per component,
/// in the crate that builds the `cdylib`.
#[macro_export]
macro_rules! export_tools {
    ($($tool:ty),+ $(,)?) => {
        struct __TptMcpboxComponent;

        impl $crate::__bindings::Guest for __TptMcpboxComponent {
            fn describe() -> ::std::string::String {
                $crate::describe(&[$($crate::entry::<$tool>()),+])
            }

            fn call(
                name: ::std::string::String,
                arguments: ::std::string::String,
            ) -> ::core::result::Result<::std::string::String, ::std::string::String> {
                $crate::dispatch(&[$($crate::entry::<$tool>()),+], &name, &arguments)
            }
        }

        $crate::__bindings::export!(__TptMcpboxComponent with_types_in $crate::__bindings);
    };
}

/// Arguments type for tools that take no input.
#[derive(Debug, Default, serde::Deserialize, JsonSchema)]
pub struct NoArgs {}

