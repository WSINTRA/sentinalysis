//! Time-range allowlist for query parameters.
//!
//! The `range` query parameter must never reach SQL as an interpolated
//! string: it parses to this closed enum, which maps to compile-time
//! `&'static str` fragments. An unknown value is rejected outright, so
//! `?range=1h;DROP TABLE agents` can never become part of a query.

/// The closed set of time ranges the hub's query endpoints accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MetricRange {
    /// Last hour.
    H1,
    /// Last 6 hours.
    H6,
    /// Last 24 hours (default).
    #[default]
    H24,
    /// Last 7 days.
    D7,
    /// Last 30 days.
    D30,
}

impl MetricRange {
    /// Parses the wire value; `None` for anything outside the allowlist.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "1h" => Some(Self::H1),
            "6h" => Some(Self::H6),
            "24h" => Some(Self::H24),
            "7d" => Some(Self::D7),
            "30d" => Some(Self::D30),
            _ => None,
        }
    }

    /// The Postgres interval fragment for `NOW() - INTERVAL '<this>'`.
    #[must_use]
    pub fn interval(self) -> &'static str {
        match self {
            Self::H1 => "1 hour",
            Self::H6 => "6 hours",
            Self::H24 => "24 hours",
            Self::D7 => "7 days",
            Self::D30 => "30 days",
        }
    }

    /// The downsample bucket size in seconds, so long ranges do not return
    /// unbounded row counts. Seconds (not `date_trunc` names) because
    /// Postgres `date_trunc` rejects intervals like `5 minutes`.
    #[must_use]
    pub fn bucket_seconds(self) -> i64 {
        match self {
            Self::H1 | Self::H6 => 60,
            Self::H24 => 300,
            Self::D7 => 1_800,
            Self::D30 => 7_200,
        }
    }

    /// Hard cap on returned series length, independent of the bucket.
    #[must_use]
    pub fn max_rows(self) -> i64 {
        let _ = self;
        2000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_allowlist() {
        for (input, expected) in [
            ("1h", MetricRange::H1),
            ("6h", MetricRange::H6),
            ("24h", MetricRange::H24),
            ("7d", MetricRange::D7),
            ("30d", MetricRange::D30),
        ] {
            assert_eq!(MetricRange::parse(input), Some(expected), "{input}");
        }
    }

    #[test]
    fn parse_rejects_everything_else() {
        for input in [
            "",
            "1",
            "1H",
            "24H",
            "999d",
            "-1h",
            "1h;DROP TABLE agents",
            "1h --",
            "0h",
            "1m",
            "10y",
            "1 h",
            " 24h",
        ] {
            assert_eq!(MetricRange::parse(input), None, "must reject '{input}'");
        }
    }

    #[test]
    fn fragments_are_static_and_wellformed() {
        for range in [
            MetricRange::H1,
            MetricRange::H6,
            MetricRange::H24,
            MetricRange::D7,
            MetricRange::D30,
        ] {
            assert!(!range.interval().contains(';'));
            assert!(!range.interval().contains('\''));
            assert!(!range.interval().contains("--"));
            assert!(
                range.bucket_seconds() > 0 && range.bucket_seconds() % 60 == 0,
                "bucket must be a whole number of minutes"
            );
        }
    }

    #[test]
    fn default_is_24h() {
        assert_eq!(MetricRange::default(), MetricRange::H24);
    }

    #[test]
    fn max_rows_bounded() {
        for range in [
            MetricRange::H1,
            MetricRange::H6,
            MetricRange::H24,
            MetricRange::D7,
            MetricRange::D30,
        ] {
            assert!(range.max_rows() > 0);
            assert!(range.max_rows() <= 5000);
        }
    }
}
