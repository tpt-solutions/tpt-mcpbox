// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Restarts a stdio upstream whose process has exited.
//!
//! [`supervise`] polls a [`PolicyGate`]. When its connection reports closed, it
//! calls a caller-supplied respawn function with exponential backoff until a new
//! connection is ready, then swaps it in with [`PolicyGate::replace`]. Calls
//! that arrive while the upstream is down fail at once with a closed-connection
//! error. They are not queued.
//!
//! The respawn function owns everything that makes a replacement acceptable:
//! the handshake, and a check that the tool list still matches the one the
//! router registered. A restart that presents different tools is refused,
//! because the router's catalog cannot change under a running server.
//!
//! A child that hangs without exiting is caught by a ping. The supervisor sends
//! one every `ping_every`, but only while no call is outstanding: a busy
//! upstream is judged by its calls, and a late ping would not prove it hung. A
//! ping that gets no reply within `ping_timeout` replaces the connection, and
//! dropping the old one kills the child.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::connection::Connection;
use crate::gate::PolicyGate;

/// Builds a replacement connection. Returns a message when the attempt fails.
pub type Respawn =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Connection, String>> + Send>> + Send + Sync>;

/// How often to check the connection, when to ping it, and how long to wait
/// between restart attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    /// Interval between checks of the connection.
    pub poll: Duration,
    /// Delay before the first restart attempt. Doubles after each failure.
    pub initial_backoff: Duration,
    /// Upper bound on the delay between attempts.
    pub max_backoff: Duration,
    /// How often to ping an idle connection.
    pub ping_every: Duration,
    /// How long a ping may take before the connection counts as hung.
    pub ping_timeout: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(1),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            ping_every: Duration::from_secs(30),
            ping_timeout: Duration::from_secs(10),
        }
    }
}

/// Told whenever a supervised upstream goes down (`false`) or comes back (`true`).
pub type StateObserver = Arc<dyn Fn(bool) + Send + Sync>;

/// Runs the supervisor for `gate` in the background. The task runs until the
/// runtime shuts down.
pub fn supervise(
    gate: Arc<PolicyGate>,
    respawn: Respawn,
    policy: RestartPolicy,
    observer: StateObserver,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_ping = tokio::time::Instant::now();
        loop {
            tokio::time::sleep(policy.poll).await;
            if gate.is_closed() {
                tracing::warn!(
                    upstream = gate.upstream(),
                    "upstream connection closed; restarting"
                );
                replace(&gate, &respawn, &observer, policy).await;
                last_ping = tokio::time::Instant::now();
                continue;
            }
            if last_ping.elapsed() < policy.ping_every {
                continue;
            }
            last_ping = tokio::time::Instant::now();
            // Calls already outstanding are the evidence; a ping would only add
            // a second, slower, opinion of the same upstream.
            if gate.in_flight() > 0 {
                continue;
            }
            if !responds(&gate, policy.ping_timeout).await {
                tracing::warn!(
                    upstream = gate.upstream(),
                    "upstream did not answer ping; restarting"
                );
                replace(&gate, &respawn, &observer, policy).await;
                last_ping = tokio::time::Instant::now();
            }
        }
    })
}

/// `true` when the connection answers a ping within `limit`.
async fn responds(gate: &PolicyGate, limit: Duration) -> bool {
    matches!(tokio::time::timeout(limit, gate.ping()).await, Ok(Ok(())))
}

/// Reports the outage, restarts, and reports recovery.
async fn replace(
    gate: &PolicyGate,
    respawn: &Respawn,
    observer: &StateObserver,
    policy: RestartPolicy,
) {
    observer(false);
    restart(gate, respawn, policy).await;
    observer(true);
}

/// Retries `respawn` until it yields a connection, then swaps it in.
async fn restart(gate: &PolicyGate, respawn: &Respawn, policy: RestartPolicy) {
    let mut backoff = policy.initial_backoff;
    loop {
        tokio::time::sleep(backoff).await;
        match respawn().await {
            Ok(connection) => {
                gate.replace(connection);
                tracing::info!(upstream = gate.upstream(), "upstream restarted");
                return;
            }
            Err(error) => {
                tracing::warn!(
                    upstream = gate.upstream(),
                    %error,
                    retry_in = ?backoff,
                    "upstream restart failed"
                );
                backoff = (backoff * 2).min(policy.max_backoff);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::{Value, json};

    use super::*;
    use crate::upstream::{Client, UpstreamOptions};

    #[test]
    fn default_policy_backs_off_to_a_minute() {
        let policy = RestartPolicy::default();
        assert_eq!(policy.initial_backoff, Duration::from_secs(1));
        assert_eq!(policy.max_backoff, Duration::from_secs(60));
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        // Mirrors the arithmetic in `restart` without running it.
        let policy = RestartPolicy::default();
        let mut backoff = policy.initial_backoff;
        let mut seen = Vec::new();
        for _ in 0..8 {
            seen.push(backoff.as_secs());
            backoff = (backoff * 2).min(policy.max_backoff);
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 32, 60, 60]);
    }

    #[tokio::test]
    async fn restart_retries_until_the_respawn_succeeds() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        let respawn: Respawn = Arc::new(move || {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                if counter.fetch_add(1, Ordering::SeqCst) < 2 {
                    return Err("still starting".to_owned());
                }
                // Keep the peer's end open, so the replacement stays open.
                let (client_side, peer) = tokio::io::duplex(1024);
                std::mem::forget(peer);
                let (read, write) = tokio::io::split(client_side);
                let client = Client::connect(read, write, UpstreamOptions::default());
                let connection: Connection = client.into();
                Ok(connection)
            })
        });
        let gate = closed_gate();

        restart(&gate, &respawn, quick_policy()).await;

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert!(!gate.is_closed(), "the replacement is in place");
    }

    #[tokio::test]
    async fn supervisor_reports_down_then_up() {
        let gate = Arc::new(closed_gate());
        let respawn: Respawn = Arc::new(|| {
            Box::pin(async {
                let (client_side, peer) = tokio::io::duplex(1024);
                std::mem::forget(peer);
                let (read, write) = tokio::io::split(client_side);
                let connection: Connection =
                    Client::connect(read, write, UpstreamOptions::default()).into();
                Ok(connection)
            })
        });
        let (events_tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let observer: StateObserver = Arc::new(move |up| {
            let _ = events_tx.send(up);
        });

        let task = supervise(Arc::clone(&gate), respawn, quick_policy(), observer);
        let down = tokio::time::timeout(Duration::from_secs(5), events.recv()).await;
        let up = tokio::time::timeout(Duration::from_secs(5), events.recv()).await;
        task.abort();

        assert!(!down.expect("a down event").expect("open channel"));
        assert!(up.expect("an up event").expect("open channel"));
        assert!(!gate.is_closed(), "the replacement is in place");
    }

    /// A restart policy that keeps the tests quick.
    fn quick_policy() -> RestartPolicy {
        RestartPolicy {
            poll: Duration::from_millis(5),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(4),
            // Pings stay out of the way of tests that are not about them.
            ping_every: Duration::from_secs(3600),
            ping_timeout: Duration::from_secs(1),
        }
    }

    /// A peer that reads requests and never answers.
    fn silent_gate() -> PolicyGate {
        use tokio::io::AsyncReadExt;

        let (client_side, mut server) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(client_side);
        // Keeps the server end open and drains it, so requests are received and
        // never answered.
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            while matches!(server.read(&mut buffer).await, Ok(n) if n > 0) {}
        });
        let client = Client::connect(read, write, UpstreamOptions::default());
        PolicyGate::new("hung", client, empty_policy())
    }

    /// A connection whose peer answers every request with an empty result.
    fn answering_connection() -> Connection {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (sread, mut swrite) = tokio::io::split(server_side);
        tokio::spawn(async move {
            let mut lines = BufReader::new(sread).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let message: Value = serde_json::from_str(&line).unwrap();
                if let Some(id) = message.get("id") {
                    let reply = json!({ "jsonrpc": "2.0", "id": id, "result": {} });
                    if swrite
                        .write_all(format!("{reply}\n").as_bytes())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });
        let (read, write) = tokio::io::split(client_side);
        Client::connect(read, write, UpstreamOptions::default()).into()
    }

    fn empty_policy() -> Arc<tpt_mcpbox_policy::Policy> {
        Arc::new(
            tpt_mcpbox_policy::Policy::from_config(
                &tpt_mcpbox_config::model::PolicyConfig::default(),
            )
            .expect("empty policy compiles"),
        )
    }

    #[tokio::test]
    async fn a_hung_upstream_is_replaced() {
        let gate = Arc::new(silent_gate());
        let respawn: Respawn = Arc::new(|| Box::pin(async { Ok(answering_connection()) }));
        let (events_tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let observer: StateObserver = Arc::new(move |up| {
            let _ = events_tx.send(up);
        });
        let policy = RestartPolicy {
            poll: Duration::from_millis(5),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(4),
            ping_every: Duration::from_millis(5),
            ping_timeout: Duration::from_millis(50),
        };

        let task = supervise(Arc::clone(&gate), respawn, policy, observer);
        let down = tokio::time::timeout(Duration::from_secs(5), events.recv()).await;
        let up = tokio::time::timeout(Duration::from_secs(5), events.recv()).await;
        task.abort();

        assert!(!down.expect("a down event").expect("open channel"));
        assert!(up.expect("an up event").expect("open channel"));
        // The replacement answers pings, so the gate is healthy again.
        gate.ping().await.expect("the replacement answers");
    }

    #[tokio::test]
    async fn a_busy_upstream_is_not_pinged() {
        // A call that never returns keeps the upstream busy. The supervisor
        // must not treat the silence as a hang while the call is outstanding.
        let gate = Arc::new(silent_gate());
        let busy = Arc::clone(&gate);
        let call = tokio::spawn(async move { busy.connection().call_tool("slow", None).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(gate.in_flight() > 0, "the call is outstanding");

        let (events_tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let observer: StateObserver = Arc::new(move |up| {
            let _ = events_tx.send(up);
        });
        let policy = RestartPolicy {
            ping_every: Duration::from_millis(5),
            ping_timeout: Duration::from_millis(20),
            ..quick_policy()
        };
        let respawn: Respawn = Arc::new(|| Box::pin(async { Ok(answering_connection()) }));
        let task = supervise(Arc::clone(&gate), respawn, policy, observer);
        let outcome = tokio::time::timeout(Duration::from_millis(300), events.recv()).await;
        task.abort();
        call.abort();

        assert!(outcome.is_err(), "no restart while a call is outstanding");
    }

    /// A gate whose only connection has already closed, because its peer
    /// reached end of stream straight away.
    fn closed_gate() -> PolicyGate {
        let client = Client::connect(
            tokio::io::empty(),
            tokio::io::sink(),
            UpstreamOptions::default(),
        );
        let policy = Arc::new(
            tpt_mcpbox_policy::Policy::from_config(
                &tpt_mcpbox_config::model::PolicyConfig::default(),
            )
            .expect("empty policy compiles"),
        );
        PolicyGate::new("fake", client, policy)
    }
}
