// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Error types for protocol encoding/decoding and session handling.
//!
//! Every fallible operation in this crate returns [`Result`], whose error is a
//! [`ProtocolError`]. [`ProtocolError::to_json_rpc`] converts a failure into the
//! JSON-RPC error object that must be returned to the peer, so handlers never
//! have to build wire errors by hand.

use serde_json::Value;

/// Convenience alias used throughout the crate.
pub type Result<T, E = ProtocolError> = std::result::Result<T, E>;

/// Failure modes of protocol encoding, decoding and session handling.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The payload was not valid JSON, or did not match the expected schema.
    #[error("malformed JSON payload: {0}")]
    Json(#[from] serde_json::Error),

    /// The envelope was structurally wrong, e.g. `jsonrpc != "2.0"` or a
    /// response carrying both `result` and `error`.
    #[error("invalid JSON-RPC envelope: {0}")]
    Envelope(String),

    /// `params` did not deserialize into the type required by `method`.
    #[error("invalid params for method `{method}`: {source}")]
    InvalidParams {
        /// Method whose params failed to deserialize.
        method: String,
        /// Underlying serde failure.
        source: serde_json::Error,
    },

    /// The peer called a method this server does not implement.
    #[error("method not found: {0}")]
    MethodNotFound(String),

    /// The peer violated the MCP lifecycle, e.g. sent a request before
    /// `initialize` completed.
    #[error("protocol state violation: {0}")]
    State(String),

    /// A batch payload was empty or not an array of JSON-RPC messages.
    #[error("invalid batch payload: {0}")]
    Batch(String),

    /// Transport-level failure: closed channel, broken pipe, oversized line.
    #[error("transport failure: {0}")]
    Transport(String),

    /// Server-side failure; must never carry secret material.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ProtocolError {
    /// Build an [`ProtocolError::InvalidParams`] from a method name and a
    /// deserialization failure.
    pub fn invalid_params(method: impl Into<String>, source: serde_json::Error) -> Self {
        Self::InvalidParams {
            method: method.into(),
            source,
        }
    }

    /// Convert this error into the JSON-RPC error object sent to the peer.
    pub fn to_json_rpc(&self) -> crate::jsonrpc::Error {
        use crate::jsonrpc::ErrorCode;
        let (code, message) = match self {
            Self::Json(_) | Self::Envelope(_) | Self::Batch(_) => {
                (ErrorCode::INVALID_REQUEST, self.to_string())
            }
            Self::InvalidParams { .. } => (ErrorCode::INVALID_PARAMS, self.to_string()),
            Self::MethodNotFound(method) => (ErrorCode::METHOD_NOT_FOUND, method.clone()),
            Self::State(_) | Self::Transport(_) => (ErrorCode::INVALID_REQUEST, self.to_string()),
            Self::Internal(_) => (ErrorCode::INTERNAL_ERROR, "internal error".to_owned()),
        };
        crate::jsonrpc::Error::new(code, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonrpc::{ErrorCode, Id};

    #[test]
    fn json_errors_map_to_invalid_request() {
        let err = ProtocolError::Json(serde_json::from_str::<Value>("{").unwrap_err());
        assert_eq!(err.to_json_rpc().code, ErrorCode::INVALID_REQUEST);
    }

    #[test]
    fn method_not_found_uses_method_name_as_message() {
        let err = ProtocolError::MethodNotFound("tools/call".into()).to_json_rpc();
        assert_eq!(err.code, ErrorCode::METHOD_NOT_FOUND);
        assert_eq!(err.message, "tools/call");
        assert_eq!(err.id, None);
    }

    #[test]
    fn internal_errors_do_not_leak_details() {
        let err = ProtocolError::Internal("secret=abc123 in stack".into()).to_json_rpc();
        assert_eq!(err.code, ErrorCode::INTERNAL_ERROR);
        assert!(!err.message.contains("abc123"));
    }

    #[test]
    fn errors_keep_the_response_id() {
        let err = crate::jsonrpc::Error::new(ErrorCode::INTERNAL_ERROR, "boom").with_id(Id::Number(7));
        assert_eq!(err.id, Some(Id::Number(7)));
    }
}
