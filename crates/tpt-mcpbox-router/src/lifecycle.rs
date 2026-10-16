// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Graceful shutdown: stop admitting new calls, then wait for in-flight calls.
//!
//! Every call holds an [`InFlight`] guard for its duration. Once
//! [`Lifecycle::shutdown`] is called, [`Lifecycle::begin`] refuses new work, and
//! shutdown waits until the existing guards are dropped or the timeout expires.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::Notify;

/// Returned by [`Lifecycle::begin`] after shutdown has started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("server is shutting down and is not accepting new calls")]
pub struct ShuttingDown;

/// Outcome of [`Lifecycle::shutdown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drain {
    /// Every in-flight call finished within the timeout.
    Completed,
    /// The timeout expired with this many calls still running.
    TimedOut {
        /// Calls still in flight when the timeout expired.
        remaining: usize,
    },
}

/// Tracks in-flight calls and gates new ones during shutdown.
#[derive(Debug, Default)]
pub struct Lifecycle {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    state: Mutex<State>,
    idle: Notify,
}

#[derive(Debug, Default)]
struct State {
    closing: bool,
    in_flight: usize,
}

/// Held for the duration of one call. Dropping it marks the call finished.
#[must_use = "dropping the guard immediately marks the call as finished"]
#[derive(Debug)]
pub struct InFlight {
    inner: Arc<Inner>,
}

impl Lifecycle {
    /// Creates a lifecycle that is accepting calls.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a new call, or fails once shutdown has started.
    pub fn begin(&self) -> Result<InFlight, ShuttingDown> {
        let mut state = lock(&self.inner.state);
        if state.closing {
            return Err(ShuttingDown);
        }
        state.in_flight += 1;
        Ok(InFlight {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Number of calls currently in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        lock(&self.inner.state).in_flight
    }

    /// `true` once shutdown has started.
    #[must_use]
    pub fn is_closing(&self) -> bool {
        lock(&self.inner.state).closing
    }

    /// Stops admitting calls and waits up to `timeout` for the running ones.
    ///
    /// Calling this more than once is harmless; later calls wait on the same
    /// in-flight count.
    pub async fn shutdown(&self, timeout: Duration) -> Drain {
        lock(&self.inner.state).closing = true;

        let wait = async {
            loop {
                if lock(&self.inner.state).in_flight == 0 {
                    return;
                }
                self.inner.idle.notified().await;
            }
        };

        match tokio::time::timeout(timeout, wait).await {
            Ok(()) => Drain::Completed,
            Err(_) => Drain::TimedOut {
                remaining: lock(&self.inner.state).in_flight,
            },
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut state = lock(&self.inner.state);
        state.in_flight -= 1;
        if state.in_flight == 0 {
            // `notify_one` stores a permit when nobody is waiting, so a shutdown
            // that starts right after this drop still wakes up.
            self.inner.idle.notify_one();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_counts_and_releases() {
        let lifecycle = Lifecycle::new();
        let a = lifecycle.begin().unwrap();
        let b = lifecycle.begin().unwrap();
        assert_eq!(lifecycle.in_flight(), 2);
        drop(a);
        assert_eq!(lifecycle.in_flight(), 1);
        drop(b);
        assert_eq!(lifecycle.in_flight(), 0);
    }

    #[test]
    fn begin_refused_after_shutdown_starts() {
        let lifecycle = Lifecycle::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        assert_eq!(
            rt.block_on(lifecycle.shutdown(Duration::ZERO)),
            Drain::Completed
        );
        assert!(lifecycle.is_closing());
        assert_eq!(lifecycle.begin().unwrap_err(), ShuttingDown);
    }

    #[tokio::test]
    async fn shutdown_with_no_work_completes_immediately() {
        let lifecycle = Lifecycle::new();
        assert_eq!(
            lifecycle.shutdown(Duration::from_millis(50)).await,
            Drain::Completed
        );
    }

    #[tokio::test]
    async fn shutdown_waits_for_in_flight_calls() {
        let lifecycle = Arc::new(Lifecycle::new());
        let guard = lifecycle.begin().unwrap();

        let shutting_down = {
            let lifecycle = Arc::clone(&lifecycle);
            tokio::spawn(async move { lifecycle.shutdown(Duration::from_secs(5)).await })
        };

        // Give the shutdown task a chance to start waiting.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(lifecycle.begin().is_err());
        assert!(!shutting_down.is_finished());

        drop(guard);
        assert_eq!(shutting_down.await.unwrap(), Drain::Completed);
    }

    #[tokio::test]
    async fn shutdown_times_out_and_reports_remaining() {
        let lifecycle = Lifecycle::new();
        let _stuck = lifecycle.begin().unwrap();
        let _stuck2 = lifecycle.begin().unwrap();
        assert_eq!(
            lifecycle.shutdown(Duration::from_millis(30)).await,
            Drain::TimedOut { remaining: 2 }
        );
    }
}
