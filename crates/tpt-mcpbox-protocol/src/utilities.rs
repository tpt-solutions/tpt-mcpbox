// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Protocol utilities: logging, progress, cancellation and the notification
//! constructors the router needs to talk back to the agent.
//!
//! All payloads here are *notifications* (`notifications/…`): they carry no
//! `id` and are never answered. Logging notifications are filtered against the
//! level previously set with `logging/setLevel`.

use serde::{Deserialize, Serialize};

use crate::jsonrpc::{Id, Notification};
use crate::method::utilities;
use crate::model::{LoggingLevel, ProgressToken};

/// Params of `logging/setLevel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetLevelRequest {
    /// Minimum severity to emit.
    pub level: LoggingLevel,
}

/// Params of `notifications/message`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoggingMessageParams {
    /// Severity of this record.
    pub level: LoggingLevel,
    /// Optional logger name, e.g. `tpt-mcpbox::router`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logger: Option<String>,
    /// The record body.
    pub data: serde_json::Value,
}

/// Params of `notifications/progress`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressNotificationParams {
    /// Token from the originating request's `params._meta.progressToken`.
    #[serde(rename = "progressToken")]
    pub progress_token: ProgressToken,
    /// Work completed so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
    /// Total units of work, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    /// Optional human-readable status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Params of `notifications/cancelled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelledParams {
    /// Identifier of the request being cancelled.
    #[serde(rename = "requestId")]
    pub request_id: Id,
    /// Optional explanation surfaced to the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Build a `notifications/message` payload.
#[must_use]
pub fn logging_notification(level: LoggingLevel, data: serde_json::Value) -> Notification {
    Notification::new(utilities::MESSAGE).with_params(LoggingMessageParams {
        level,
        logger: Some("tpt-mcpbox".to_owned()),
        data,
    })
}

/// Build a `notifications/progress` payload.
#[must_use]
pub fn progress_notification(
    token: impl Into<ProgressToken>,
    progress: f64,
    total: Option<f64>,
) -> Notification {
    Notification::new(utilities::PROGRESS).with_params(ProgressNotificationParams {
        progress_token: token.into(),
        progress: Some(progress),
        total,
        message: None,
    })
}

/// Build a `notifications/cancelled` payload.
#[must_use]
pub fn cancelled_notification(
    request_id: impl Into<Id>,
    reason: impl Into<String>,
) -> Notification {
    Notification::new(utilities::CANCELLED).with_params(CancelledParams {
        request_id: request_id.into(),
        reason: Some(reason.into()),
    })
}

/// Build a `logging/setLevel` request.
#[must_use]
pub fn set_level_request(id: impl Into<Id>, level: LoggingLevel) -> crate::jsonrpc::Request {
    crate::jsonrpc::Request::new(id, utilities::SET_LEVEL).with_params(SetLevelRequest { level })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logging_notification_round_trips() {
        let notification = logging_notification(LoggingLevel::Warning, serde_json::json!("denied"));
        assert_eq!(notification.method, utilities::MESSAGE);
        let params: LoggingMessageParams = notification.parse_params().expect("params parse");
        assert_eq!(params.level, LoggingLevel::Warning);
        assert_eq!(params.data, serde_json::json!("denied"));
    }

    #[test]
    fn progress_notification_renames_its_token() {
        let notification = progress_notification(7_i64, 0.5, Some(1.0));
        let json = serde_json::to_value(&notification).expect("serializes");
        assert_eq!(json["params"]["progressToken"], 7);
        assert_eq!(json["params"]["progress"], 0.5);
    }

    #[test]
    fn cancelled_notification_carries_the_request_id() {
        let notification = cancelled_notification(Id::String("req-1".to_owned()), "user aborted");
        let params: CancelledParams = notification.parse_params().expect("params parse");
        assert_eq!(params.request_id, Id::String("req-1".to_owned()));
        assert_eq!(params.reason.as_deref(), Some("user aborted"));
    }

    #[test]
    fn set_level_request_is_a_request_not_a_notification() {
        let request = set_level_request(1, LoggingLevel::Error);
        assert_eq!(request.method, utilities::SET_LEVEL);
        assert!(!crate::method::is_notification(request.method.as_str()));
    }
}
