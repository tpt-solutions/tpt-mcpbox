// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Prometheus metrics for the router.
//!
//! Every call is counted once by kind (`tool`, `resource_read`, `prompt_get`)
//! and outcome (`ok`, `denied`, `rate_limited`, ...), and its duration is put in
//! a histogram by kind. Label values come only from fixed sets in this code.
//! Tool, resource and prompt names are never labels: they would let an agent
//! grow the number of series without limit, and they are not needed to see
//! how the hub is behaving. Secret values never reach this module.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tpt_mcpbox_runtime::LoadedTool;

/// Upper bounds of the duration histogram, in seconds. `+Inf` is implicit.
pub const BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Debug, Default, Clone, PartialEq)]
struct Histogram {
    /// Observations at or below each bound in [`BUCKETS`].
    buckets: Vec<u64>,
    count: u64,
    sum: f64,
}

/// Counters, gauges and histograms shared by every call the router serves.
#[derive(Debug, Default)]
pub struct Metrics {
    calls: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    durations: Mutex<BTreeMap<&'static str, Histogram>>,
    in_flight: AtomicI64,
    /// Supervised upstream name → whether its process is up. Names come from
    /// configuration, so the label set is bounded.
    upstreams_up: Mutex<BTreeMap<String, bool>>,
    /// Wasm tools whose instance pools are summed at render time.
    pools: Mutex<Vec<Arc<LoadedTool>>>,
}

/// Counts one call as in flight for as long as it lives.
#[derive(Debug)]
#[must_use = "dropping the guard immediately ends the in-flight count"]
pub struct InFlight<'a>(&'a Metrics);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Metrics {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks a call as started. The count drops when the guard does.
    pub fn enter(&self) -> InFlight<'_> {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlight(self)
    }

    /// Calls currently running.
    #[must_use]
    pub fn in_flight(&self) -> i64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Records whether a supervised upstream's process is up.
    pub fn set_upstream_up(&self, upstream: &str, up: bool) {
        lock(&self.upstreams_up).insert(upstream.to_owned(), up);
    }

    /// Includes `tool`'s instance pool in the pool gauges. A tool is counted
    /// once, however many descriptors it exposes.
    pub fn track_pool(&self, tool: &Arc<LoadedTool>) {
        let mut pools = lock(&self.pools);
        if !pools.iter().any(|known| Arc::ptr_eq(known, tool)) {
            pools.push(Arc::clone(tool));
        }
    }

    /// Records one finished call.
    pub fn observe(&self, kind: &'static str, outcome: &'static str, elapsed: Duration) {
        *lock(&self.calls).entry((kind, outcome)).or_insert(0) += 1;

        let seconds = elapsed.as_secs_f64();
        let mut durations = lock(&self.durations);
        let histogram = durations.entry(kind).or_insert_with(|| Histogram {
            buckets: vec![0; BUCKETS.len()],
            ..Histogram::default()
        });
        histogram.count += 1;
        histogram.sum += seconds;
        for (bound, slot) in BUCKETS.iter().zip(histogram.buckets.iter_mut()) {
            if seconds <= *bound {
                *slot += 1;
            }
        }
    }

    /// Number of calls recorded with this kind and outcome.
    #[must_use]
    pub fn calls(&self, kind: &str, outcome: &str) -> u64 {
        lock(&self.calls)
            .iter()
            .find(|((k, o), _)| *k == kind && *o == outcome)
            .map_or(0, |(_, count)| *count)
    }

    /// Renders every series in the Prometheus text exposition format.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP tpt_mcpbox_calls_total Calls served, by kind and outcome.\n");
        out.push_str("# TYPE tpt_mcpbox_calls_total counter\n");
        for ((kind, outcome), count) in lock(&self.calls).iter() {
            let _ = writeln!(
                out,
                "tpt_mcpbox_calls_total{{kind=\"{kind}\",outcome=\"{outcome}\"}} {count}"
            );
        }

        out.push_str("# HELP tpt_mcpbox_calls_in_flight Calls running right now.\n");
        out.push_str("# TYPE tpt_mcpbox_calls_in_flight gauge\n");
        let _ = writeln!(out, "tpt_mcpbox_calls_in_flight {}", self.in_flight());
        // Summed across tools, so the gauges carry no tool names.
        let (mut leased, mut capacity) = (0_usize, 0_usize);
        for tool in lock(&self.pools).iter() {
            let usage = tool.pool_usage();
            leased += usage.leased;
            capacity += usage.capacity;
        }
        out.push_str(
            "# HELP tpt_mcpbox_tool_instances_in_use Wasm instances checked out for calls.\n",
        );
        out.push_str("# TYPE tpt_mcpbox_tool_instances_in_use gauge\n");
        let _ = writeln!(out, "tpt_mcpbox_tool_instances_in_use {leased}");
        out.push_str(
            "# HELP tpt_mcpbox_tool_instances_capacity Most Wasm instances the pools may hold.\n",
        );
        out.push_str("# TYPE tpt_mcpbox_tool_instances_capacity gauge\n");
        let _ = writeln!(out, "tpt_mcpbox_tool_instances_capacity {capacity}");
        out.push_str("# HELP tpt_mcpbox_upstream_up 1 when a supervised upstream is running.\n");
        out.push_str("# TYPE tpt_mcpbox_upstream_up gauge\n");
        for (upstream, up) in lock(&self.upstreams_up).iter() {
            let _ = writeln!(
                out,
                "tpt_mcpbox_upstream_up{{upstream=\"{}\"}} {}",
                escape_label(upstream),
                u8::from(*up)
            );
        }
        out.push_str("# HELP tpt_mcpbox_call_duration_seconds Call duration, by kind.\n");
        out.push_str("# TYPE tpt_mcpbox_call_duration_seconds histogram\n");
        for (kind, histogram) in lock(&self.durations).iter() {
            for (bound, count) in BUCKETS.iter().zip(&histogram.buckets) {
                let _ = writeln!(
                    out,
                    "tpt_mcpbox_call_duration_seconds_bucket{{kind=\"{kind}\",le=\"{bound}\"}} {count}"
                );
            }
            let _ = writeln!(
                out,
                "tpt_mcpbox_call_duration_seconds_bucket{{kind=\"{kind}\",le=\"+Inf\"}} {}",
                histogram.count
            );
            let _ = writeln!(
                out,
                "tpt_mcpbox_call_duration_seconds_sum{{kind=\"{kind}\"}} {}",
                histogram.sum
            );
            let _ = writeln!(
                out,
                "tpt_mcpbox_call_duration_seconds_count{{kind=\"{kind}\"}} {}",
                histogram.count
            );
        }

        out
    }
}

/// Escapes a label value for the text format: backslash, quote and newline.
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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
    fn counts_are_kept_per_kind_and_outcome() {
        let metrics = Metrics::new();
        metrics.observe("tool", "ok", Duration::from_millis(1));
        metrics.observe("tool", "ok", Duration::from_millis(1));
        metrics.observe("tool", "denied", Duration::from_millis(1));
        assert_eq!(metrics.calls("tool", "ok"), 2);
        assert_eq!(metrics.calls("tool", "denied"), 1);
        assert_eq!(metrics.calls("prompt_get", "ok"), 0);
    }

    #[test]
    fn histogram_buckets_are_cumulative() {
        let metrics = Metrics::new();
        metrics.observe("tool", "ok", Duration::from_micros(500)); // 0.0005s
        metrics.observe("tool", "ok", Duration::from_millis(50)); // 0.05s
        let text = metrics.render();
        assert!(
            text.contains("tpt_mcpbox_call_duration_seconds_bucket{kind=\"tool\",le=\"0.001\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("tpt_mcpbox_call_duration_seconds_bucket{kind=\"tool\",le=\"0.05\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("tpt_mcpbox_call_duration_seconds_bucket{kind=\"tool\",le=\"+Inf\"} 2"),
            "{text}"
        );
        assert!(text.contains("tpt_mcpbox_call_duration_seconds_count{kind=\"tool\"} 2"));
    }

    #[test]
    fn in_flight_counts_while_a_guard_lives() {
        let metrics = Metrics::new();
        let first = metrics.enter();
        let second = metrics.enter();
        assert_eq!(metrics.in_flight(), 2);
        drop(first);
        assert_eq!(metrics.in_flight(), 1);
        drop(second);
        assert_eq!(metrics.in_flight(), 0);
    }

    #[test]
    fn upstream_up_is_rendered_with_escaped_names() {
        let metrics = Metrics::new();
        metrics.set_upstream_up("github", true);
        metrics.set_upstream_up("odd\"name", false);
        let text = metrics.render();
        assert!(
            text.contains("tpt_mcpbox_upstream_up{upstream=\"github\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("tpt_mcpbox_upstream_up{upstream=\"odd\\\"name\"} 0"),
            "{text}"
        );
        assert!(text.contains("# TYPE tpt_mcpbox_calls_in_flight gauge"));
    }

    #[test]
    fn render_names_every_series() {
        let metrics = Metrics::new();
        metrics.observe("resource_read", "rate_limited", Duration::from_millis(2));
        let text = metrics.render();
        assert!(text.contains("# TYPE tpt_mcpbox_calls_total counter"));
        assert!(
            text.contains(
                "tpt_mcpbox_calls_total{kind=\"resource_read\",outcome=\"rate_limited\"} 1"
            )
        );
        assert!(text.contains("# TYPE tpt_mcpbox_call_duration_seconds histogram"));
    }
}
