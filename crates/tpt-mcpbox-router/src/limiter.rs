// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Per-tool and per-client rate and concurrency limiting.
//!
//! Each tool has its own gate, and each client (session) has a gate that
//! applies to every tool it calls. A call is admitted only when all four gates
//! admit it: tool concurrency, tool rate, client concurrency and client rate.
//! Admission is all-or-nothing; a call rejected by a later gate releases the
//! permits taken from earlier ones when it returns.
//!
//! Overload is rejected at once, unless the tool sets `queue_timeout`. Then a
//! call waits up to that long for a free slot (see [`Limiter::acquire_queued`]).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tpt_mcpbox_config::model::RateLimit;

/// How often idle client gates are swept out of the map. A sweep only removes
/// gates that are indistinguishable from a fresh one, so the interval affects
/// memory use and nothing else.
const CLIENT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// How often a queued call re-checks its gates while it waits for one.
const QUEUE_POLL: Duration = Duration::from_millis(5);

/// Rate and concurrency settings for one gate, in a form the limiter can use
/// without depending on configuration types at every call site.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Limits {
    /// Sustained admissions per second; `None` means no rate limit.
    pub requests_per_second: Option<f64>,
    /// Bucket capacity. Defaults to `ceil(requests_per_second)`, minimum 1.
    pub burst: Option<u32>,
    /// Maximum calls in flight at once; `None` means unlimited.
    pub max_concurrency: Option<u32>,
    /// How long a call waits for a busy gate before it is refused, when the
    /// caller uses [`Limiter::acquire_queued`]. `None` refuses at once.
    pub max_wait: Option<Duration>,
}

impl From<&RateLimit> for Limits {
    fn from(limit: &RateLimit) -> Self {
        Self {
            requests_per_second: limit.requests_per_second,
            burst: limit.burst,
            max_concurrency: limit.max_concurrency,
            max_wait: limit.queue_timeout,
        }
    }
}

/// Why a call was turned away.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    /// The tool's sustained or burst rate is exhausted.
    #[error("tool `{0}` is rate limited")]
    ToolRate(String),
    /// The tool already has its maximum number of calls in flight.
    #[error("tool `{0}` is at its concurrency limit")]
    ToolConcurrency(String),
    /// The client has exhausted its rate budget.
    #[error("client `{0}` is rate limited")]
    ClientRate(String),
    /// The client already has its maximum number of calls in flight.
    #[error("client `{0}` is at its concurrency limit")]
    ClientConcurrency(String),
}

/// Holds the permits for one admitted call. Dropping it releases concurrency.
#[must_use = "dropping the permit immediately releases the concurrency slot"]
#[derive(Debug)]
pub struct Permit {
    _tool: Option<OwnedSemaphorePermit>,
    _client: Option<OwnedSemaphorePermit>,
}

/// Admission control for tool calls.
#[derive(Debug)]
pub struct Limiter {
    tools: HashMap<String, Gate>,
    client_limits: Limits,
    clients: Mutex<Clients>,
}

/// Per-client gates, plus when the map was last swept for idle entries.
#[derive(Debug)]
struct Clients {
    gates: HashMap<String, Gate>,
    last_sweep: Instant,
}

impl Limiter {
    /// Builds a limiter from per-tool limits. Tools not listed are unlimited
    /// per tool, but still subject to the client limits.
    #[must_use]
    pub fn new<'a>(
        tools: impl IntoIterator<Item = (&'a str, Limits)>,
        client_limits: Limits,
    ) -> Self {
        Self {
            tools: tools
                .into_iter()
                .map(|(name, limits)| (name.to_owned(), Gate::new(limits)))
                .collect(),
            client_limits,
            clients: Mutex::new(Clients {
                gates: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Admits or rejects a call from `client` to `tool`, using the current time.
    pub fn acquire(&self, tool: &str, client: &str) -> Result<Permit, Rejection> {
        self.acquire_at(tool, client, Instant::now())
    }

    /// Like [`Limiter::acquire`], but when the tool sets `max_wait` a refused
    /// call is retried every few milliseconds until it is admitted or the wait
    /// runs out. The last refusal is returned in the second case. A tool
    /// without `max_wait` refuses at once, as with `acquire`.
    ///
    /// Polling keeps one admission path for all four gates. Waiting on a
    /// single semaphore would miss a rate refusal or a client's slot.
    ///
    /// # Errors
    ///
    /// Returns the [`Rejection`] that was in force when the wait ran out.
    pub async fn acquire_queued(&self, tool: &str, client: &str) -> Result<Permit, Rejection> {
        let Some(max_wait) = self.tools.get(tool).and_then(|gate| gate.limits.max_wait) else {
            return self.acquire(tool, client);
        };
        let deadline = Instant::now() + max_wait;
        loop {
            let rejection = match self.acquire(tool, client) {
                Ok(permit) => return Ok(permit),
                Err(rejection) => rejection,
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(rejection);
            }
            tokio::time::sleep(QUEUE_POLL.min(remaining)).await;
        }
    }

    /// Like [`Limiter::acquire`], with the clock supplied by the caller.
    pub fn acquire_at(&self, tool: &str, client: &str, now: Instant) -> Result<Permit, Rejection> {
        let tool_gate = self.tools.get(tool);
        let tool_permit = match tool_gate {
            Some(gate) => gate.admit(now).map_err(|kind| match kind {
                GateError::Concurrency => Rejection::ToolConcurrency(tool.to_owned()),
                GateError::Rate => Rejection::ToolRate(tool.to_owned()),
            })?,
            None => None,
        };

        // The client gate is admitted under the map lock, so a sweep cannot
        // evict a gate between looking it up and taking its permit.
        let client_permit = {
            let mut clients = lock(&self.clients);
            self.sweep_if_due(&mut clients, now);
            let gate = clients
                .gates
                .entry(client.to_owned())
                .or_insert_with(|| Gate::new(self.client_limits));
            gate.admit(now).map_err(|kind| match kind {
                GateError::Concurrency => Rejection::ClientConcurrency(client.to_owned()),
                GateError::Rate => Rejection::ClientRate(client.to_owned()),
            })
        };
        let client_permit = match client_permit {
            Ok(permit) => permit,
            Err(rejection) => {
                // The tool's rate token was spent before the client was
                // checked. The call never ran, so the token goes back; the
                // tool's concurrency slot is released when `tool_permit` drops.
                if let Some(gate) = tool_gate {
                    gate.refund_token();
                }
                return Err(rejection);
            }
        };

        Ok(Permit {
            _tool: tool_permit,
            _client: client_permit,
        })
    }

    /// Drops client gates that a fresh gate would match exactly. Gates that
    /// still hold a permit, or whose bucket has not refilled, are kept, so
    /// eviction never resets a client's budget.
    fn sweep_if_due(&self, clients: &mut Clients, now: Instant) {
        if now.saturating_duration_since(clients.last_sweep) < CLIENT_SWEEP_INTERVAL {
            return;
        }
        clients.gates.retain(|_, gate| !gate.is_idle(now));
        clients.last_sweep = now;
    }

    #[cfg(test)]
    fn client_count(&self) -> usize {
        lock(&self.clients).gates.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateError {
    Concurrency,
    Rate,
}

/// One rate bucket and one concurrency pool.
#[derive(Debug)]
struct Gate {
    limits: Limits,
    bucket: Option<Mutex<Bucket>>,
    slots: Option<Arc<Semaphore>>,
}

impl Gate {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            bucket: limits
                .requests_per_second
                .map(|rate| Mutex::new(Bucket::new(rate, limits.burst))),
            slots: limits
                .max_concurrency
                .map(|max| Arc::new(Semaphore::new(max as usize))),
        }
    }

    /// True when the gate is indistinguishable from one built fresh at `now`:
    /// no call holds a concurrency slot and the bucket has refilled.
    fn is_idle(&self, now: Instant) -> bool {
        let slots_free = match (&self.slots, self.limits.max_concurrency) {
            (Some(slots), Some(max)) => slots.available_permits() == max as usize,
            _ => true,
        };
        let refilled = self
            .bucket
            .as_ref()
            .is_none_or(|bucket| lock(bucket).is_full_at(now));
        slots_free && refilled
    }

    /// Returns a rate token taken by [`Gate::admit`] for a call that was then
    /// refused by another gate. A gate without a rate limit has nothing to
    /// return.
    fn refund_token(&self) {
        if let Some(bucket) = &self.bucket {
            lock(bucket).refund();
        }
    }

    /// Takes a concurrency slot first, then a rate token. Taking the slot first
    /// means a call that is only blocked by concurrency does not spend a token.
    fn admit(&self, now: Instant) -> Result<Option<OwnedSemaphorePermit>, GateError> {
        let permit = match &self.slots {
            Some(slots) => match Arc::clone(slots).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => {
                    return Err(GateError::Concurrency);
                }
            },
            None => None,
        };

        if let Some(bucket) = &self.bucket
            && !lock(bucket).take(now)
        {
            return Err(GateError::Rate);
        }

        Ok(permit)
    }
}

/// Token bucket refilled continuously at `rate` tokens per second.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    capacity: f64,
    rate: f64,
    last: Option<Instant>,
}

impl Bucket {
    fn new(rate: f64, burst: Option<u32>) -> Self {
        let capacity = burst.map_or_else(|| rate.ceil().max(1.0), |b| f64::from(b.max(1)));
        Self {
            tokens: capacity,
            capacity,
            rate,
            last: None,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        if let Some(last) = self.last {
            let elapsed = now.saturating_duration_since(last).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        }
        self.last = Some(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Gives one token back, up to capacity.
    fn refund(&mut self) {
        self.tokens = (self.tokens + 1.0).min(self.capacity);
    }

    /// Whether the bucket would be at capacity at `now`, without spending.
    fn is_full_at(&self, now: Instant) -> bool {
        let refilled = match self.last {
            Some(last) => {
                let elapsed = now.saturating_duration_since(last).as_secs_f64();
                self.tokens + elapsed * self.rate
            }
            None => self.tokens,
        };
        refilled >= self.capacity
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock only means another caller panicked mid-update. The
    // counters are still usable, so keep serving rather than cascade the panic.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn limits(rps: Option<f64>, burst: Option<u32>, conc: Option<u32>) -> Limits {
        Limits {
            requests_per_second: rps,
            burst,
            max_concurrency: conc,
            max_wait: None,
        }
    }

    #[test]
    fn unlimited_tool_and_client_always_admit() {
        let limiter = Limiter::new([], Limits::default());
        for _ in 0..100 {
            assert!(limiter.acquire("echo", "c1").is_ok());
        }
    }

    #[test]
    fn a_call_refused_by_the_client_gate_does_not_spend_the_tool_token() {
        let limiter = Limiter::new(
            [("echo", limits(Some(1.0), Some(2), None))],
            limits(None, None, Some(1)),
        );
        let t0 = Instant::now();
        let held = limiter.acquire_at("echo", "c1", t0).unwrap();
        // The client's one slot is taken, so this call is refused after the
        // tool's token was spent. The token must come back.
        assert_eq!(
            limiter.acquire_at("echo", "c1", t0).unwrap_err(),
            Rejection::ClientConcurrency("c1".into())
        );
        drop(held);
        // Two tokens existed at the start, so a second admission still fits.
        assert!(limiter.acquire_at("echo", "c1", t0).is_ok());
    }

    #[test]
    fn burst_then_reject_then_refill() {
        let limiter = Limiter::new(
            [("echo", limits(Some(2.0), Some(3), None))],
            Limits::default(),
        );
        let t0 = Instant::now();
        let permits: Vec<_> = (0..3)
            .map(|_| limiter.acquire_at("echo", "c1", t0).unwrap())
            .collect();
        assert_eq!(
            limiter.acquire_at("echo", "c1", t0).unwrap_err(),
            Rejection::ToolRate("echo".into())
        );
        // Half a second at 2 tokens/s refills one token.
        let later = t0 + Duration::from_millis(500);
        assert!(limiter.acquire_at("echo", "c1", later).is_ok());
        assert!(limiter.acquire_at("echo", "c1", later).is_err());
        drop(permits);
    }

    #[test]
    fn burst_defaults_to_rate_rounded_up() {
        let limiter = Limiter::new([("t", limits(Some(1.5), None, None))], Limits::default());
        let t0 = Instant::now();
        assert!(limiter.acquire_at("t", "c", t0).is_ok());
        assert!(limiter.acquire_at("t", "c", t0).is_ok());
        assert!(limiter.acquire_at("t", "c", t0).is_err());
    }

    #[test]
    fn tool_concurrency_is_released_on_drop() {
        let limiter = Limiter::new([("t", limits(None, None, Some(1)))], Limits::default());
        let first = limiter.acquire("t", "c1").unwrap();
        assert_eq!(
            limiter.acquire("t", "c2").unwrap_err(),
            Rejection::ToolConcurrency("t".into())
        );
        drop(first);
        assert!(limiter.acquire("t", "c2").is_ok());
    }

    #[test]
    fn client_limits_apply_across_tools_and_are_per_client() {
        let client = limits(Some(1.0), Some(1), None);
        let limiter = Limiter::new([("a", Limits::default()), ("b", Limits::default())], client);
        let t0 = Instant::now();
        assert!(limiter.acquire_at("a", "c1", t0).is_ok());
        assert_eq!(
            limiter.acquire_at("b", "c1", t0).unwrap_err(),
            Rejection::ClientRate("c1".into())
        );
        // A different client has its own budget.
        assert!(limiter.acquire_at("b", "c2", t0).is_ok());
    }

    #[test]
    fn client_concurrency_limit() {
        let limiter = Limiter::new([], limits(None, None, Some(1)));
        let _held = limiter.acquire("a", "c1").unwrap();
        assert_eq!(
            limiter.acquire("b", "c1").unwrap_err(),
            Rejection::ClientConcurrency("c1".into())
        );
    }

    #[test]
    fn rejected_tool_rate_does_not_leak_client_concurrency() {
        let limiter = Limiter::new(
            [("t", limits(Some(1.0), Some(1), None))],
            limits(None, None, Some(1)),
        );
        let t0 = Instant::now();
        let _first = limiter.acquire_at("t", "c1", t0).unwrap();
        // The tool rate gate rejects after the client slot has been taken; the
        // slot must be released again, so another tool can still use it.
        assert!(limiter.acquire_at("t", "c1", t0).is_err());
        drop(_first);
        assert!(limiter.acquire_at("other", "c1", t0).is_ok());
    }

    #[test]
    fn rejected_concurrency_does_not_spend_a_rate_token() {
        let limiter = Limiter::new(
            [("t", limits(Some(1.0), Some(2), Some(1)))],
            Limits::default(),
        );
        let t0 = Instant::now();
        let held = limiter.acquire_at("t", "c", t0).unwrap();
        // Concurrency rejects this one; it must not consume the second token.
        assert_eq!(
            limiter.acquire_at("t", "c", t0).unwrap_err(),
            Rejection::ToolConcurrency("t".into())
        );
        drop(held);
        assert!(limiter.acquire_at("t", "c", t0).is_ok());
    }

    #[test]
    fn idle_refilled_client_gates_are_swept() {
        let limiter = Limiter::new([], limits(Some(1.0), Some(1), None));
        let t0 = Instant::now();
        drop(limiter.acquire_at("a", "c1", t0).unwrap());
        assert_eq!(limiter.client_count(), 1);

        // Past the sweep interval, and c1's bucket has long since refilled.
        let later = t0 + CLIENT_SWEEP_INTERVAL + Duration::from_secs(1);
        drop(limiter.acquire_at("a", "c2", later).unwrap());
        assert_eq!(limiter.client_count(), 1, "c1 should be evicted");
    }

    #[test]
    fn client_gate_with_a_held_slot_is_kept() {
        let limiter = Limiter::new([], limits(None, None, Some(1)));
        let t0 = Instant::now();
        let held = limiter.acquire_at("a", "c1", t0).unwrap();

        let later = t0 + CLIENT_SWEEP_INTERVAL + Duration::from_secs(1);
        assert_eq!(
            limiter.acquire_at("a", "c1", later).unwrap_err(),
            Rejection::ClientConcurrency("c1".into())
        );
        assert_eq!(limiter.client_count(), 1);
        drop(held);
    }

    #[test]
    fn unrefilled_client_gate_is_kept_so_its_budget_is_not_reset() {
        // One token per 100 seconds: after 61 seconds the bucket is still short.
        let limiter = Limiter::new([], limits(Some(0.01), Some(1), None));
        let t0 = Instant::now();
        drop(limiter.acquire_at("a", "c1", t0).unwrap());

        let later = t0 + CLIENT_SWEEP_INTERVAL + Duration::from_secs(1);
        assert_eq!(
            limiter.acquire_at("a", "c1", later).unwrap_err(),
            Rejection::ClientRate("c1".into())
        );
        assert_eq!(limiter.client_count(), 1);
    }

    #[test]
    fn many_distinct_idle_clients_do_not_grow_the_map_without_bound() {
        let limiter = Limiter::new([], limits(Some(1.0), Some(1), None));
        let t0 = Instant::now();
        for n in 0..10_000 {
            drop(limiter.acquire_at("a", &format!("c{n}"), t0).unwrap());
        }
        assert_eq!(limiter.client_count(), 10_000);

        // One sweep later, every client has refilled and is idle, so only the
        // caller that triggered the sweep remains.
        let later = t0 + CLIENT_SWEEP_INTERVAL + Duration::from_secs(1);
        drop(limiter.acquire_at("a", "fresh", later).unwrap());
        assert_eq!(limiter.client_count(), 1);
    }

    #[test]
    fn flood_of_client_rejections_leaks_no_tool_slots() {
        // The tool gate admits before the client gate rejects, so every
        // rejected call must give its tool slot back.
        let limiter = Limiter::new(
            [("t", limits(None, None, Some(2)))],
            limits(None, None, Some(1)),
        );
        let held = limiter.acquire("t", "c1").unwrap();
        for _ in 0..1_000 {
            assert_eq!(
                limiter.acquire("t", "c1").unwrap_err(),
                Rejection::ClientConcurrency("c1".into())
            );
        }
        // Only `held` occupies a tool slot, so exactly one is free for others.
        let free = limiter.acquire("t", "c2").unwrap();
        assert_eq!(
            limiter.acquire("t", "c3").unwrap_err(),
            Rejection::ToolConcurrency("t".into())
        );
        drop((held, free));
    }

    #[test]
    fn concurrent_callers_never_exceed_the_tool_cap() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const CAP: u32 = 3;
        let limiter = Arc::new(Limiter::new(
            [("t", limits(None, None, Some(CAP)))],
            Limits::default(),
        ));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let workers: Vec<_> = (0..32)
            .map(|n| {
                let limiter = Arc::clone(&limiter);
                let in_flight = Arc::clone(&in_flight);
                let peak = Arc::clone(&peak);
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        if let Ok(permit) = limiter.acquire("t", &format!("c{n}")) {
                            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            std::thread::yield_now();
                            in_flight.fetch_sub(1, Ordering::SeqCst);
                            drop(permit);
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        assert!(peak.load(Ordering::SeqCst) <= CAP as usize);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    }

    fn queued(max_concurrency: u32, max_wait: Duration) -> Limits {
        Limits {
            max_concurrency: Some(max_concurrency),
            max_wait: Some(max_wait),
            ..Limits::default()
        }
    }

    #[tokio::test]
    async fn queued_call_is_admitted_when_a_slot_frees_within_the_wait() {
        let limiter = Arc::new(Limiter::new(
            [("t", queued(1, Duration::from_secs(2)))],
            Limits::default(),
        ));
        let held = limiter.acquire("t", "c1").unwrap();
        let waiter = {
            let limiter = Arc::clone(&limiter);
            tokio::spawn(async move { limiter.acquire_queued("t", "c2").await.map(|_| ()) })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);
        assert!(waiter.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn queued_call_is_refused_with_the_last_rejection_when_the_wait_runs_out() {
        let limiter = Limiter::new(
            [("t", queued(1, Duration::from_millis(30)))],
            Limits::default(),
        );
        let _held = limiter.acquire("t", "c1").unwrap();
        let started = Instant::now();
        assert_eq!(
            limiter.acquire_queued("t", "c2").await.unwrap_err(),
            Rejection::ToolConcurrency("t".into())
        );
        assert!(started.elapsed() >= Duration::from_millis(30));
    }

    #[tokio::test]
    async fn tool_without_a_wait_refuses_at_once() {
        let limiter = Limiter::new([("t", limits(None, None, Some(1)))], Limits::default());
        let _held = limiter.acquire("t", "c1").unwrap();
        assert_eq!(
            limiter.acquire_queued("t", "c2").await.unwrap_err(),
            Rejection::ToolConcurrency("t".into())
        );
    }

    #[test]
    fn rate_from_config_model() {
        let config = RateLimit {
            requests_per_second: Some(5.0),
            burst: Some(2),
            max_concurrency: Some(4),
            queue_timeout: Some(Duration::from_millis(250)),
        };
        assert_eq!(
            Limits::from(&config),
            Limits {
                max_wait: Some(Duration::from_millis(250)),
                ..limits(Some(5.0), Some(2), Some(4))
            }
        );
    }
}
