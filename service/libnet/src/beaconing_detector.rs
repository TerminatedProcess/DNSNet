//! Beaconing detector — flags domains queried at suspiciously high frequency.
//!
//! Tracks per-domain query timestamps in a sliding time window and flags domains
//! that exceed a configurable threshold, indicating potential tracking beacons
//! or malware phoning home at regular intervals.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::Instant;

/// Result of a beaconing check for a single domain.
#[derive(Debug, Clone, PartialEq)]
pub struct BeaconingResult {
    /// Whether the domain exceeded the query frequency threshold.
    pub is_beaconing: bool,
    /// Number of queries observed within the current window.
    pub query_count: u32,
    /// Size of the sliding window in seconds.
    pub window_seconds: u32,
}

/// Per-domain state: a ring buffer of query timestamps within the sliding window.
struct DomainState {
    /// Timestamps of recent queries, ordered oldest to newest.
    timestamps: Vec<Instant>,
}

impl DomainState {
    fn new() -> Self {
        DomainState {
            timestamps: Vec::new(),
        }
    }

    /// Record a query at `now` and prune timestamps older than `window`.
    /// Returns the number of queries remaining in the window (including this one).
    fn record(&mut self, now: Instant, window: std::time::Duration) -> u32 {
        // Prune expired timestamps.
        // Since timestamps are ordered, find the first one still within the window.
        let cutoff = now.checked_sub(window).unwrap_or(now);
        let keep_from = self.timestamps.partition_point(|t| *t < cutoff);
        if keep_from > 0 {
            self.timestamps.drain(..keep_from);
        }

        self.timestamps.push(now);
        self.timestamps.len() as u32
    }
}

/// Detects domains being queried at suspiciously high frequency.
///
/// Uses an LRU cache bounded to `max_entries` domains so memory stays bounded
/// even on a device seeing many unique domains.
pub struct BeaconingDetector {
    /// Sliding window duration.
    window: std::time::Duration,
    /// Number of queries in the window that triggers a beaconing flag.
    threshold: u32,
    /// Per-domain query history. LRU-evicts cold domains automatically.
    cache: LruCache<String, DomainState>,
}

impl BeaconingDetector {
    /// Create a new detector.
    ///
    /// * `window_seconds` — size of the sliding time window (e.g. 60).
    /// * `threshold` — query count within the window that triggers beaconing (e.g. 30).
    pub fn new(window_seconds: u32, threshold: u32) -> Self {
        Self::with_capacity(window_seconds, threshold, 5000)
    }

    /// Create a new detector with a custom LRU capacity (mainly for tests).
    pub fn with_capacity(window_seconds: u32, threshold: u32, max_entries: usize) -> Self {
        BeaconingDetector {
            window: std::time::Duration::from_secs(window_seconds as u64),
            threshold,
            cache: LruCache::new(
                NonZeroUsize::new(max_entries).expect("max_entries must be > 0"),
            ),
        }
    }

    /// Record a DNS query for `domain` and check if it is beaconing.
    ///
    /// This should be called on every DNS query. It is O(1) amortized
    /// (LRU lookup + pruning expired timestamps from a small vec).
    pub fn record_and_check(&mut self, domain: &str) -> BeaconingResult {
        let now = Instant::now();

        // Get or insert domain state.
        let state = self
            .cache
            .get_or_insert_mut(domain.to_owned(), || DomainState::new());

        let query_count = state.record(now, self.window);

        BeaconingResult {
            is_beaconing: query_count >= self.threshold,
            query_count,
            window_seconds: self.window.as_secs() as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_no_beaconing_single_query() {
        let mut detector = BeaconingDetector::new(60, 30);
        let result = detector.record_and_check("example.com");
        assert!(!result.is_beaconing);
        assert_eq!(result.query_count, 1);
        assert_eq!(result.window_seconds, 60);
    }

    #[test]
    fn test_beaconing_threshold_exact() {
        let mut detector = BeaconingDetector::new(60, 5);
        for i in 0..4 {
            let result = detector.record_and_check("beacon.evil.com");
            assert!(!result.is_beaconing, "should not trigger at query {}", i + 1);
        }
        // 5th query hits the threshold
        let result = detector.record_and_check("beacon.evil.com");
        assert!(result.is_beaconing);
        assert_eq!(result.query_count, 5);
    }

    #[test]
    fn test_different_domains_independent() {
        let mut detector = BeaconingDetector::new(60, 3);
        detector.record_and_check("a.com");
        detector.record_and_check("a.com");
        let result_b = detector.record_and_check("b.com");
        assert_eq!(result_b.query_count, 1);
        assert!(!result_b.is_beaconing);
    }

    #[test]
    fn test_lru_eviction() {
        // Capacity of 2 — third domain evicts the least-recently-used one.
        let mut detector = BeaconingDetector::with_capacity(60, 3, 2);
        detector.record_and_check("a.com"); // count=1
        detector.record_and_check("a.com"); // count=2
        detector.record_and_check("b.com"); // b enters, a still present
        detector.record_and_check("c.com"); // c enters, a gets evicted (LRU)

        // a.com was evicted — next query starts fresh at count=1
        let result = detector.record_and_check("a.com");
        assert_eq!(result.query_count, 1);
    }

    #[test]
    fn test_window_expiry() {
        // We can't easily fast-forward Instant, so test the DomainState directly.
        let mut state = DomainState::new();
        let base = Instant::now();
        let window = Duration::from_secs(10);

        // Simulate timestamps at base-15s, base-12s, base-5s (first two are outside window).
        // We need to construct this manually since we can't subtract from Instant arbitrarily.
        // Instead, test the pruning logic with real time (all queries are "now").
        // This verifies that fresh queries accumulate correctly.
        for _ in 0..5 {
            state.record(base, window);
        }
        assert_eq!(state.timestamps.len(), 5);

        // All at the same instant, none expire.
        let count = state.record(base, window);
        assert_eq!(count, 6);
    }

    #[test]
    fn test_pruning_with_synthetic_timestamps() {
        // Directly test DomainState pruning by inserting "old" timestamps
        // and then recording at a later time.
        let mut state = DomainState::new();
        let now = Instant::now();
        let window = Duration::from_secs(10);

        // Push some timestamps that are "now" — they'll all be within window.
        state.record(now, window);
        state.record(now, window);
        assert_eq!(state.timestamps.len(), 2);

        // Simulate time passing: push a timestamp far in the future.
        // The old ones should be pruned.
        let future = now + Duration::from_secs(20);
        let count = state.record(future, window);
        // The two old timestamps (at `now`) are 20s old, outside the 10s window.
        assert_eq!(count, 1);
        assert_eq!(state.timestamps.len(), 1);
    }

    #[test]
    fn test_result_fields() {
        let mut detector = BeaconingDetector::new(120, 10);
        let result = detector.record_and_check("test.org");
        assert_eq!(result.window_seconds, 120);
        assert_eq!(result.query_count, 1);
        assert!(!result.is_beaconing);
    }
}
