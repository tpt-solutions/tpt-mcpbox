// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Canonical MCP method names.
//!
//! Keeping them in one place avoids typo-driven dispatch failures, which would
//! otherwise surface as opaque `-32601` responses to agents.

/// Lifecycle
pub mod lifecycle {
    /// Client → server: opening handshake.
    pub const INITIALIZE: &str = "initialize";
    /// Client → server: handshake acknowledgement.
    pub const INITIALIZED: &str = "notifications/initialized";
    /// Bidirectional liveness probe.
    pub const PING: &str = "ping";
    /// Bidirectional orderly shutdown (used by the HTTP `DELETE` flow).
    pub const SHUTDOWN: &str = "shutdown";
}

/// Tools
pub mod tools {
    /// List tools exposed by the server (paginated).
    pub const LIST: &str = "tools/list";
    /// Invoke a tool.
    pub const CALL: &str = "tools/call";
    /// The tool list changed.
    pub const LIST_CHANGED: &str = "notifications/tools/list_changed";
}

/// Resources
pub mod resources {
    /// List resources (paginated).
    pub const LIST: &str = "resources/list";
    /// Read a resource by URI.
    pub const READ: &str = "resources/read";
    /// List resource templates (paginated).
    pub const TEMPLATES_LIST: &str = "resources/templates/list";
    /// Start receiving `notifications/resources/updated` for a URI.
    pub const SUBSCRIBE: &str = "resources/subscribe";
    /// Stop receiving update notifications for a URI.
    pub const UNSUBSCRIBE: &str = "resources/unsubscribe";
    /// The resource list changed.
    pub const LIST_CHANGED: &str = "notifications/resources/list_changed";
    /// A subscribed resource changed.
    pub const UPDATED: &str = "notifications/resources/updated";
}

/// Prompts
pub mod prompts {
    /// List prompts (paginated).
    pub const LIST: &str = "prompts/list";
    /// Render a prompt.
    pub const GET: &str = "prompts/get";
    /// The prompt list changed.
    pub const LIST_CHANGED: &str = "notifications/prompts/list_changed";
}

/// Completion
pub mod completion {
    /// Argument/URI completion suggestions.
    pub const COMPLETE: &str = "completion/complete";
}

/// Utilities
pub mod utilities {
    /// Set the minimum severity of server log notifications.
    pub const SET_LEVEL: &str = "logging/setLevel";
    /// A log record emitted by the server.
    pub const MESSAGE: &str = "notifications/message";
    /// Long-running work progress.
    pub const PROGRESS: &str = "notifications/progress";
    /// Cooperative cancellation of an in-flight request.
    pub const CANCELLED: &str = "notifications/cancelled";
}

/// Server → client requests (agent features routed back to the agent).
pub mod client_features {
    /// List the agent's filesystem roots.
    pub const ROOTS_LIST: &str = "roots/list";
    /// The agent's roots changed.
    pub const ROOTS_LIST_CHANGED: &str = "notifications/roots/list_changed";
    /// Ask the agent to run inference.
    pub const SAMPLING_CREATE_MESSAGE: &str = "sampling/createMessage";
    /// Ask the agent to collect structured input from the user.
    pub const ELICITATION_CREATE: &str = "elicitation/create";
}

/// Returns `true` for methods that are notifications (carry no `id`).
#[must_use]
pub fn is_notification(method: &str) -> bool {
    method.starts_with("notifications/")
}

/// Returns `true` for `initialize`, the only request allowed before the session
/// is ready.
#[must_use]
pub fn is_initialization(method: &str) -> bool {
    method == lifecycle::INITIALIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_are_detected() {
        assert!(is_notification(lifecycle::INITIALIZED));
        assert!(is_notification(tools::LIST_CHANGED));
        assert!(!is_notification(tools::CALL));
        assert!(!is_notification(client_features::ROOTS_LIST));
    }

    #[test]
    fn only_initialize_precedes_the_handshake() {
        assert!(is_initialization(lifecycle::INITIALIZE));
        assert!(!is_initialization(lifecycle::PING));
    }
}
