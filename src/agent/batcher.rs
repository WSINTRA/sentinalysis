//! Bounded in-memory log buffer for the agent.
//!
//! When the hub is unreachable, lines accumulate up to `log_buffer_max`;
//! beyond that the OLDEST lines are dropped (never blocks, never grows
//! unbounded) and counted so gaps are observable.

use std::collections::VecDeque;

/// A log line awaiting forwarding.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingLine {
    pub timestamp_ms: i64,
    pub container: String,
    pub stream: String,
    pub message: String,
}

/// Bounded FIFO with drop-oldest overflow semantics.
#[derive(Debug)]
pub struct BoundedBatcher {
    buf: VecDeque<PendingLine>,
    max: usize,
    dropped_since_report: u64,
    total_dropped: u64,
}

impl BoundedBatcher {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            max: max.max(1),
            dropped_since_report: 0,
            total_dropped: 0,
        }
    }

    /// Pushes a line; drops the oldest when at capacity.
    pub fn push(&mut self, line: PendingLine) {
        while self.buf.len() >= self.max {
            if self.buf.pop_front().is_some() {
                self.dropped_since_report += 1;
                self.total_dropped += 1;
            }
        }
        self.buf.push_back(line);
    }

    /// Drains up to `n` lines for a flush.
    pub fn drain(&mut self, n: usize) -> Vec<PendingLine> {
        let n = n.min(self.buf.len());
        self.buf.drain(..n).collect()
    }

    /// Current buffered count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Takes the count of lines dropped since the last report.
    pub fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped_since_report)
    }

    /// Cumulative drops (for shutdown reporting).
    #[must_use]
    pub fn total_dropped(&self) -> u64 {
        self.total_dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(i: usize) -> PendingLine {
        PendingLine {
            timestamp_ms: i as i64,
            container: "app".into(),
            stream: "stdout".into(),
            message: format!("line {i}"),
        }
    }

    #[test]
    fn holds_under_capacity() {
        let mut batcher = BoundedBatcher::new(10);
        for i in 0..10 {
            batcher.push(line(i));
        }
        assert_eq!(batcher.len(), 10);
        assert_eq!(batcher.take_dropped(), 0);
    }

    #[test]
    fn drops_oldest_on_overflow() {
        let mut batcher = BoundedBatcher::new(3);
        for i in 0..6 {
            batcher.push(line(i));
        }
        assert_eq!(batcher.len(), 3);
        assert_eq!(batcher.take_dropped(), 3);
        // The surviving lines are the newest: 3, 4, 5.
        let drained = batcher.drain(10);
        assert_eq!(
            drained
                .iter()
                .map(|l| l.message.as_str())
                .collect::<Vec<_>>(),
            vec!["line 3", "line 4", "line 5"]
        );
    }

    #[test]
    fn drain_is_bounded_by_count() {
        let mut batcher = BoundedBatcher::new(10);
        for i in 0..5 {
            batcher.push(line(i));
        }
        let first = batcher.drain(2);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].message, "line 0");
        assert_eq!(batcher.len(), 3);
        assert!(batcher.drain(0).is_empty());
    }

    #[test]
    fn total_dropped_tracked_across_reports() {
        let mut batcher = BoundedBatcher::new(2);
        for i in 0..5 {
            batcher.push(line(i));
        }
        let _ = batcher.take_dropped(); // 3
        for _ in 0..2 {
            batcher.push(line(9));
        }
        assert_eq!(batcher.take_dropped(), 2);
        assert_eq!(batcher.take_dropped(), 0); // reset after take
        assert_eq!(batcher.total_dropped(), 5);
    }

    #[test]
    fn min_capacity_is_one() {
        let mut batcher = BoundedBatcher::new(0);
        batcher.push(line(1));
        batcher.push(line(2));
        assert_eq!(batcher.len(), 1);
    }
}
