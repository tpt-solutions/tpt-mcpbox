// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! JSON-RPC 2.0 envelopes as required by MCP.
//!
//! The four wire shapes handled here are [`Request`] (has `id` + `method`),
//! [`Notification`] (`method` only), [`Response`] (`id` + `result` **or**
//! `error`) and a batch (a non-empty JSON array of the above). [`ClientMessage`]
//! and [`ServerMessage`] wrap them so the transports never have to guess which
//! shape arrived.
//!
//! Deserialization is deliberately *strict where the spec is strict*: every
//! envelope must carry `"jsonrpc": "2.0"`, and a response must carry exactly one
//! of `result` / `error`.

use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::error::{ProtocolError, Result};

/// The only JSON-RPC version MCP allows.
pub const JSONRPC_VERSION: &str = "2.0";

fn default_version() -> String {
    JSONRPC_VERSION.to_owned()
}

fn check_version(version: &str) -> std::result::Result<(), String> {
    if version == JSONRPC_VERSION {
        Ok(())
    } else {
        Err(format!(
            "expected \"jsonrpc\":\"{JSONRPC_VERSION}\", got \"{version}\""
        ))
    }
}

/// A JSON-RPC request identifier: a number, a string, or `null`.
///
/// MCP allows number and string ids; `null` appears only in error responses
/// whose request id could not be recovered. Ids of different kinds are never
/// equal, so `1`, `"1"` and `null` are three distinct identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    /// Unknown id (error responses only).
    Null,
    /// Numeric identifier.
    Number(i64),
    /// String identifier.
    String(String),
}

impl Id {
    /// Identifier to use for the next server → client request.
    #[must_use]
    pub fn next(&self) -> Self {
        match self {
            Self::Null => Self::Number(0),
            Self::Number(n) => Self::Number(n.saturating_add(1)),
            Self::String(s) => match s.parse::<i64>() {
                Ok(n) => Self::Number(n.saturating_add(1)),
                Err(_) => Self::String(format!("{s}-1")),
            },
        }
    }

    /// Borrow the numeric form, if any.
    #[must_use]
    pub fn as_number(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            Self::Null | Self::String(_) => None,
        }
    }

    /// Borrow the string form, if any.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            Self::Null | Self::Number(_) => None,
        }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Number(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "{s}"),
        }
    }
}

impl Default for Id {
    /// `null`, the id used when a failure cannot be correlated to a request.
    fn default() -> Self {
        Self::Null
    }
}

impl From<i64> for Id {
    fn from(value: i64) -> Self {
        Self::Number(value)
    }
}

impl From<i32> for Id {
    fn from(value: i32) -> Self {
        Self::Number(i64::from(value))
    }
}

impl From<u32> for Id {
    fn from(value: u32) -> Self {
        Self::Number(i64::from(value))
    }
}

impl From<String> for Id {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for Id {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

/// A JSON-RPC (and MCP) error code.
///
/// A transparent newtype rather than a closed enum: peers legitimately send
/// codes this build does not know about, and they must round-trip unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ErrorCode(pub i32);

impl ErrorCode {
    /// Invalid JSON was received.
    pub const PARSE_ERROR: Self = Self(-32700);
    /// The payload is not a valid JSON-RPC request object.
    pub const INVALID_REQUEST: Self = Self(-32600);
    /// The method does not exist or is not available.
    pub const METHOD_NOT_FOUND: Self = Self(-32601);
    /// Invalid method parameters.
    pub const INVALID_PARAMS: Self = Self(-32602);
    /// Internal JSON-RPC error.
    pub const INTERNAL_ERROR: Self = Self(-32603);

    /// A requested resource does not exist (MCP-defined).
    pub const RESOURCE_NOT_FOUND: Self = Self(-32002);
    /// The request was cancelled by the client (MCP-defined).
    pub const REQUEST_CANCELLED: Self = Self(-32800);
    /// The request payload is too large (MCP-defined).
    pub const CONTENT_TOO_LARGE: Self = Self(-32801);

    /// The raw wire value.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self.0
    }

    /// `true` for the five codes reserved by JSON-RPC 2.0 itself.
    #[must_use]
    pub const fn is_standard(self) -> bool {
        matches!(self.0, -32700 | -32600 | -32601 | -32602 | -32603)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<i32> for ErrorCode {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

/// The `error` member of a JSON-RPC response.
///
/// Only `code`, `message` and `data` are serialized: `id` and `jsonrpc` belong
/// to the enclosing [`Response`]. The `id` field is kept in memory so a failure
/// can be turned into a correctly correlated response.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Error {
    /// Identifier of the request that failed, when known. Never serialized
    /// inside the `error` member.
    #[serde(skip)]
    pub id: Option<Id>,
    /// Machine-readable failure code.
    pub code: ErrorCode,
    /// Human-readable summary. Never contains secret material.
    pub message: String,
    /// Optional structured payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl Error {
    /// Build an error with an explicit code and message.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            id: None,
            code,
            message: message.into(),
            data: None,
        }
    }

    /// `-32602 invalid params`.
    #[must_use]
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::INVALID_PARAMS, message)
    }

    /// `-32601 method not found`.
    #[must_use]
    pub fn method_not_found(method: impl Into<String>) -> Self {
        Self::new(ErrorCode::METHOD_NOT_FOUND, method)
    }

    /// `-32603 internal error`; callers must not attach private detail here.
    #[must_use]
    pub fn internal() -> Self {
        Self::new(ErrorCode::INTERNAL_ERROR, "internal error")
    }

    /// Attach the request id this error answers.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<Id>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Attach a structured payload.
    #[must_use]
    pub fn with_data(mut self, data: impl Into<Value>) -> Self {
        self.data = Some(data.into());
        self
    }
}

impl<'de> Deserialize<'de> for Error {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            id: Option<Id>,
            code: ErrorCode,
            message: String,
            #[serde(default)]
            data: Option<Value>,
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            id: raw.id,
            code: raw.code,
            message: raw.message,
            data: raw.data,
        })
    }
}

/// A JSON-RPC request: has both an `id` and a `method`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Request {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Correlation identifier for the matching [`Response`].
    pub id: Id,
    /// Method name, e.g. `tools/call`.
    pub method: String,
    /// Optional parameters object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl Request {
    /// Create a request with no params.
    pub fn new(id: impl Into<Id>, method: impl Into<String>) -> Self {
        Self {
            jsonrpc: default_version(),
            id: id.into(),
            method: method.into(),
            params: None,
        }
    }

    /// Attach params, replacing any previous value.
    ///
    /// Params are serialized with `serde`. A serialization failure (only
    /// possible for values that are not JSON-representable, which MCP forbids)
    /// degrades to `null` rather than failing, so building an envelope never
    /// panics on a hostile payload.
    #[must_use]
    pub fn with_params<T: serde::Serialize>(mut self, params: T) -> Self {
        self.params = Some(serde_json::to_value(params).unwrap_or(Value::Null));
        self
    }

    /// Deserialize `params` into the type required by this method.
    ///
    /// Missing `params` are treated as `null`, so `T: DeserializeOwned` works
    /// for parameterless methods.
    ///
    /// # Errors
    /// Returns [`ProtocolError::InvalidParams`] when the shape does not match.
    pub fn parse_params<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let value = self.params.clone().unwrap_or(Value::Null);
        serde_json::from_value(value)
            .map_err(|source| ProtocolError::invalid_params(&self.method, source))
    }
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default = "default_version")]
            jsonrpc: String,
            id: Id,
            method: String,
            #[serde(default)]
            params: Option<Value>,
        }

        let raw = Raw::deserialize(deserializer)?;
        check_version(&raw.jsonrpc).map_err(D::Error::custom)?;
        Ok(Self {
            jsonrpc: raw.jsonrpc,
            id: raw.id,
            method: raw.method,
            params: raw.params,
        })
    }
}

/// A JSON-RPC notification: a `method` with no `id`, so no response is allowed.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Notification {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Method name, e.g. `notifications/initialized`.
    pub method: String,
    /// Optional parameters object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl Notification {
    /// Create a notification with no params.
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            jsonrpc: default_version(),
            method: method.into(),
            params: None,
        }
    }

    /// Attach params, replacing any previous value.
    ///
    /// See [`Request::with_params`] for the serialization fallback behaviour.
    #[must_use]
    pub fn with_params<T: serde::Serialize>(mut self, params: T) -> Self {
        self.params = Some(serde_json::to_value(params).unwrap_or(Value::Null));
        self
    }

    /// Deserialize `params` into the type required by this method.
    ///
    /// # Errors
    /// Returns [`ProtocolError::InvalidParams`] when the shape does not match.
    pub fn parse_params<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let value = self.params.clone().unwrap_or(Value::Null);
        serde_json::from_value(value)
            .map_err(|source| ProtocolError::invalid_params(&self.method, source))
    }
}

impl<'de> Deserialize<'de> for Notification {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default = "default_version")]
            jsonrpc: String,
            method: String,
            #[serde(default)]
            params: Option<Value>,
        }

        let raw = Raw::deserialize(deserializer)?;
        check_version(&raw.jsonrpc).map_err(D::Error::custom)?;
        Ok(Self {
            jsonrpc: raw.jsonrpc,
            method: raw.method,
            params: raw.params,
        })
    }
}

/// A JSON-RPC response to a [`Request`].
///
/// Exactly one of [`Response::result`] / [`Response::error`] is `Some`; the
/// invariant is enforced on deserialization.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Response {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Identifier of the request being answered.
    pub id: Id,
    /// Result payload; `None` when this is an error response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload; `None` when this is a success response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}

impl Response {
    /// Build a success response.
    pub fn success(id: impl Into<Id>, result: impl Into<Value>) -> Self {
        Self {
            jsonrpc: default_version(),
            id: id.into(),
            result: Some(result.into()),
            error: None,
        }
    }

    /// Build a success response from any serializable result.
    ///
    /// # Errors
    /// Returns [`serde_json::Error`] if `result` cannot be represented as
    /// JSON (which for MCP payloads means non-string map keys).
    pub fn success_serde<T: serde::Serialize>(
        id: impl Into<Id>,
        result: T,
    ) -> serde_json::Result<Self> {
        Ok(Self::success(id, serde_json::to_value(result)?))
    }

    /// Build an error response from a wire error.
    pub fn failure(error: Error) -> Self {
        Self {
            jsonrpc: default_version(),
            id: error.id.clone().unwrap_or_default(),
            result: None,
            error: Some(error),
        }
    }

    /// Build an error response answering `id`.
    pub fn from_error(id: impl Into<Id>, code: ErrorCode, message: impl Into<String>) -> Self {
        Self::failure(Error::new(code, message).with_id(id))
    }

    /// `true` for error responses.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.error.is_some()
    }

    /// Return the result payload, converting an error response into a
    /// [`ProtocolError`].
    ///
    /// # Errors
    /// Returns the peer's error as [`ProtocolError::Envelope`] when this is an
    /// error response.
    pub fn into_result(self) -> Result<Value> {
        match (self.result, self.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(ProtocolError::Envelope(format!(
                "peer returned error {}: {}",
                error.code, error.message
            ))),
            (Some(_), Some(_)) => Err(ProtocolError::Envelope(
                "response carried both `result` and `error`".to_owned(),
            )),
            (None, None) => Err(ProtocolError::Envelope(
                "response carried neither `result` nor `error`".to_owned(),
            )),
        }
    }
}

impl<'de> Deserialize<'de> for Response {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default = "default_version")]
            jsonrpc: String,
            id: Option<Id>,
            #[serde(default)]
            result: Option<Value>,
            #[serde(default)]
            error: Option<Error>,
        }

        let raw = Raw::deserialize(deserializer)?;
        check_version(&raw.jsonrpc).map_err(D::Error::custom)?;
        match (raw.result.is_some(), raw.error.is_some()) {
            (true, false) | (false, true) => {}
            _ => {
                return Err(D::Error::custom(
                    "response must carry exactly one of `result` or `error`",
                ));
            }
        }
        Ok(Self {
            jsonrpc: raw.jsonrpc,
            id: raw
                .id
                .ok_or_else(|| D::Error::custom("response is missing `id`"))?,
            result: raw.result,
            error: raw.error,
        })
    }
}

/// Classify a raw JSON value into the envelope shape it represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// Has both `method` and `id`.
    Request,
    /// Has `method` but no `id`.
    Notification,
    /// Has `id` and exactly one of `result` / `error`.
    Response,
}

/// Inspect `value` and report which JSON-RPC envelope it is.
///
/// # Errors
/// Returns [`ProtocolError::Envelope`] when the object matches no shape, or
/// when it is ambiguous (both `method` and `result`/`error`).
pub fn classify(value: &Value) -> Result<Shape> {
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::Envelope("JSON-RPC message must be an object".to_owned()))?;

    let has_method = object.contains_key("method");
    let has_id = object.contains_key("id");
    let has_outcome = object.contains_key("result") || object.contains_key("error");

    match (has_method, has_outcome, has_id) {
        (true, false, true) => Ok(Shape::Request),
        (true, false, false) => Ok(Shape::Notification),
        (false, true, _) => Ok(Shape::Response),
        (true, true, _) => Err(ProtocolError::Envelope(
            "message contains both `method` and `result`/`error`".to_owned(),
        )),
        (false, false, _) => Err(ProtocolError::Envelope(
            "message contains neither `method` nor `result`/`error`".to_owned(),
        )),
    }
}

/// Any JSON-RPC message that can arrive *from* an agent.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientMessage {
    /// A client → server request.
    Request(Request),
    /// A client → server notification.
    Notification(Notification),
    /// A response to a server → client request (`roots/list`, `sampling`, …).
    Response(Response),
}

impl ClientMessage {
    /// Classify and parse a raw JSON value.
    ///
    /// # Errors
    /// Propagates [`classify`] and serde failures.
    pub fn from_value(value: Value) -> Result<Self> {
        Ok(match classify(&value)? {
            Shape::Request => Self::Request(serde_json::from_value(value)?),
            Shape::Notification => Self::Notification(serde_json::from_value(value)?),
            Shape::Response => Self::Response(serde_json::from_value(value)?),
        })
    }

    /// Parse a single (non-batch) message from a JSON string.
    ///
    /// Named `parse` rather than `from_str` so it is not confused with
    /// [`std::str::FromStr::from_str`], which this type does not implement.
    ///
    /// # Errors
    /// Propagates JSON and classification failures.
    pub fn parse(json: &str) -> Result<Self> {
        Self::from_value(serde_json::from_str(json)?)
    }

    /// The request id, when this message is correlated.
    #[must_use]
    pub fn id(&self) -> Option<&Id> {
        match self {
            Self::Request(request) => Some(&request.id),
            Self::Response(response) => Some(&response.id),
            Self::Notification(_) => None,
        }
    }

    /// The method name, for requests and notifications.
    #[must_use]
    pub fn method(&self) -> Option<&str> {
        match self {
            Self::Request(request) => Some(request.method.as_str()),
            Self::Notification(notification) => Some(notification.method.as_str()),
            Self::Response(_) => None,
        }
    }
}

impl Serialize for ClientMessage {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Request(value) => value.serialize(serializer),
            Self::Notification(value) => value.serialize(serializer),
            Self::Response(value) => value.serialize(serializer),
        }
    }
}

/// A raw payload as received from a peer: either one message or a batch.
///
/// JSON-RPC 2.0 forbids empty arrays, so an empty array is rejected rather than
/// silently treated as "nothing to do".
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    /// A single message.
    Single(Value),
    /// A non-empty array of messages.
    Batch(Vec<Value>),
}

impl Incoming {
    /// Classify a raw JSON value as single message or batch.
    ///
    /// # Errors
    /// Returns [`ProtocolError::Batch`] for an empty array.
    pub fn from_value(value: Value) -> Result<Self> {
        match value {
            Value::Array(items) if items.is_empty() => {
                Err(ProtocolError::Batch("batch must not be empty".to_owned()))
            }
            Value::Array(items) => Ok(Self::Batch(items)),
            other => Ok(Self::Single(other)),
        }
    }

    /// Number of messages carried by this payload.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Batch(items) => items.len(),
        }
    }

    /// `true` when the payload carries no message at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Parse every carried message into [`ClientMessage`]s.
    ///
    /// # Errors
    /// Returns the first envelope/parse failure encountered.
    pub fn into_client_messages(self) -> Result<Vec<ClientMessage>> {
        match self {
            Self::Single(value) => Ok(vec![ClientMessage::from_value(value)?]),
            Self::Batch(items) => items.into_iter().map(ClientMessage::from_value).collect(),
        }
    }
}

/// Outbound message written by this server: a response, a notification, a
/// request back to the agent, or a batch of those.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ServerMessage {
    /// Answer to a client request.
    Response(Response),
    /// Unsolicited notification.
    Notification(Notification),
    /// Request back to the agent (`roots/list`, `sampling/createMessage`, …).
    Request(Request),
    /// Batched outbound messages; never nested.
    Batch(Vec<ServerMessage>),
}

impl ServerMessage {
    /// Flatten nested batches into a single vector.
    #[must_use]
    pub fn flatten(self) -> Vec<ServerMessage> {
        match self {
            Self::Batch(items) => items.into_iter().flat_map(Self::flatten).collect(),
            other => vec![other],
        }
    }

    /// Convert into the JSON representation written on the wire.
    ///
    /// Returns `None` only if serialization fails, which for these types can
    /// only happen with non-string map keys in `params`.
    #[must_use]
    pub fn into_value(self) -> Option<Value> {
        serde_json::to_value(self).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::CallToolRequest;

    #[test]
    fn request_round_trips_with_params() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fs_read"}}"#;
        let message = ClientMessage::parse(json).expect("parses");
        let ClientMessage::Request(request) = &message else {
            panic!("expected a request");
        };
        assert_eq!(request.id, Id::Number(1));
        assert_eq!(request.method, "tools/call");
        assert_eq!(request.params.as_ref().expect("params")["name"], "fs_read");
        assert_eq!(serde_json::to_string(&message).expect("serializes"), json);
    }

    #[test]
    fn string_ids_are_preserved() {
        let message = ClientMessage::parse(r#"{"jsonrpc":"2.0","id":"abc","method":"ping"}"#)
            .expect("parses");
        assert_eq!(message.id(), Some(&Id::String("abc".to_owned())));
    }

    #[test]
    fn notifications_have_no_id() {
        let message =
            ClientMessage::parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .expect("parses");
        assert!(matches!(message, ClientMessage::Notification(_)));
        assert_eq!(message.id(), None);
        assert_eq!(message.method(), Some("notifications/initialized"));
    }

    #[test]
    fn wrong_jsonrpc_version_is_rejected() {
        let error = ClientMessage::parse(r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#)
            .expect_err("must reject");
        assert!(error.to_string().contains("2.0"), "unexpected: {error}");
    }

    #[test]
    fn response_requires_exactly_one_outcome() {
        let both = r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}"#;
        assert!(ClientMessage::parse(both).is_err());

        let neither = r#"{"jsonrpc":"2.0","id":1}"#;
        assert!(ClientMessage::parse(neither).is_err());
    }

    #[test]
    fn error_responses_keep_code_and_data() {
        let json = r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"tools/call","data":{"hint":"x"}}}"#;
        let ClientMessage::Response(response) = ClientMessage::parse(json).expect("parses") else {
            panic!("expected a response");
        };
        assert!(response.is_error());
        let error = response.error.as_ref().expect("error");
        assert_eq!(error.code, ErrorCode::METHOD_NOT_FOUND);
        assert_eq!(error.data.as_ref().expect("data")["hint"], "x");
        assert_eq!(serde_json::to_string(&response).expect("serializes"), json);
    }

    #[test]
    fn unknown_error_codes_round_trip() {
        let json = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"custom"}}"#;
        let ClientMessage::Response(response) = ClientMessage::parse(json).expect("parses") else {
            panic!("expected a response");
        };
        let error = response.error.as_ref().expect("error");
        assert_eq!(error.code.as_i32(), -1);
        assert!(!error.code.is_standard());
    }

    #[test]
    fn missing_id_on_a_response_is_rejected() {
        assert!(ClientMessage::parse(r#"{"jsonrpc":"2.0","result":{}}"#).is_err());
    }

    #[test]
    fn batches_are_detected_and_parsed() {
        let incoming = Incoming::from_value(serde_json::json!([
            {"jsonrpc":"2.0","id":1,"method":"ping"},
            {"jsonrpc":"2.0","method":"notifications/initialized"}
        ]))
        .expect("batch parses");
        assert_eq!(incoming.len(), 2);
        assert_eq!(
            incoming
                .into_client_messages()
                .expect("messages parse")
                .len(),
            2
        );
    }

    #[test]
    fn empty_batches_are_rejected() {
        let error = Incoming::from_value(serde_json::json!([])).expect_err("must reject");
        assert!(matches!(error, ProtocolError::Batch(_)));
    }

    #[test]
    fn ambiguous_messages_are_rejected() {
        let error = ClientMessage::from_value(serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"ping","result":{}
        }))
        .expect_err("must reject");
        assert!(matches!(error, ProtocolError::Envelope(_)));
    }

    #[test]
    fn id_sequences_advance_per_kind() {
        assert_eq!(Id::Number(1).next(), Id::Number(2));
        assert_eq!(Id::String("7".to_owned()).next(), Id::Number(8));
        assert_eq!(
            Id::String("abc".to_owned()).next(),
            Id::String("abc-1".to_owned())
        );
    }

    #[test]
    fn parse_params_reports_the_method_name() {
        let request =
            Request::new(1, "tools/call").with_params(serde_json::json!({"arguments": 5}));
        let error = request
            .parse_params::<CallToolRequest>()
            .expect_err("invalid");
        assert!(
            error.to_string().contains("tools/call"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn server_messages_flatten_batches() {
        let batch = ServerMessage::Batch(vec![
            ServerMessage::Response(Response::success(1, serde_json::json!({}))),
            ServerMessage::Batch(vec![ServerMessage::Notification(Notification::new(
                crate::method::utilities::MESSAGE,
            ))]),
        ]);
        assert_eq!(batch.flatten().len(), 2);
    }
}
