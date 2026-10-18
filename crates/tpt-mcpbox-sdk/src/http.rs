// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! HTTP helpers over `wasi:http`.
//!
//! Requests go through the host's outbound handler, so they are subject to the
//! tool's network grants and to the host's allowlist. A request the host refuses
//! surfaces here as a [`ToolError`], not as a panic.

use serde::Serialize;
use serde_json::Value;

use crate::ToolError;

/// `GET` a URL and parse the response body as JSON.
///
/// # Errors
///
/// Returns a [`ToolError`] if the request is refused, the status is not 2xx, or
/// the body is not JSON.
pub fn get_json(url: &str) -> Result<Value, ToolError> {
    let response = waki::Client::new()
        .get(url)
        .send()
        .map_err(|error| ToolError::new(format!("GET {url} failed: {error:?}")))?;
    read_json(url, response)
}

/// `POST` a JSON body to a URL and parse the response body as JSON.
///
/// # Errors
///
/// Returns a [`ToolError`] if the body cannot be encoded, the request is refused,
/// the status is not 2xx, or the response is not JSON.
pub fn post_json(url: &str, body: &impl Serialize) -> Result<Value, ToolError> {
    let response = waki::Client::new()
        .post(url)
        .json(body)
        .send()
        .map_err(|error| ToolError::new(format!("POST {url} failed: {error:?}")))?;
    read_json(url, response)
}

fn read_json(url: &str, response: waki::Response) -> Result<Value, ToolError> {
    let status = response.status_code();
    let bytes = response
        .body()
        .map_err(|error| ToolError::new(format!("reading {url} failed: {error:?}")))?;
    if !(200..300).contains(&status) {
        let snippet = String::from_utf8_lossy(&bytes);
        let snippet: String = snippet.chars().take(200).collect();
        return Err(ToolError::new(format!(
            "{url} returned HTTP {status}: {snippet}"
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| ToolError::new(format!("{url} did not return JSON: {error}")))
}
