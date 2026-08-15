//! End-to-end pipeline test without a database.
//!
//! Real log file on disk → `FileTailer` (notify) → `Scanner` +
//! `Pipeline` (parse → filter → classify) → in-memory sink. The pool is
//! a `connect_lazy` handle to an unreachable server, which also covers
//! the "DB down" degradation path: service resolution fails gracefully
//! and entries are stored without a service link.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sentinel::config::NoiseFilterConfig;
use sentinel::db::models::InsertLogEntry;
use sentinel::error::SentinelError;
use sentinel::log_scanner::pipeline::{BoxFuture, build_pipeline};
use sentinel::log_scanner::scanner::{LogSink, Scanner};
use sentinel::log_scanner::tailer::FileTailer;

const CLEAN_LINE: &str = "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 15 \"-\" \"curl/8.0\" \"shop.example.com\" 0.1";
const ATTACK_LINE: &str = "10.0.0.2 - - [01/Jan/2025:00:00:01 +0000] \"GET /users?id=1 UNION SELECT * FROM passwords HTTP/1.1\" 400 0 \"-\" \"curl/8.0\" \"shop.example.com\" 0.1";
const NOISE_LINE: &str = "127.0.0.1 - - [01/Jan/2025:00:00:02 +0000] \"GET /health HTTP/1.1\" 200 15 \"-\" \"HealthChecker/1.0\" \"shop.example.com\" 0.001";
/// Health check from a non-excluded IP: noise via aggregation.
const HEALTHCHECK_LINE: &str = "203.0.113.7 - - [01/Jan/2025:00:00:03 +0000] \"GET /health HTTP/1.1\" 200 15 \"-\" \"HealthChecker/1.0\" \"shop.example.com\" 0.001";
/// Reconnaissance against a known scanner endpoint: security event.
const SCANNER_LINE: &str = "203.0.113.9 - - [01/Jan/2025:00:00:04 +0000] \"GET /wp-admin HTTP/1.1\" 404 0 \"-\" \"curl/8.0\" \"shop.example.com\" 0.01";

/// The shared destination for flushed entries; clone the `Arc` to observe
/// it from outside the spawned scanner task.
pub type SharedEntries = Arc<Mutex<Vec<InsertLogEntry>>>;

/// Sinks processed entries in memory.
#[derive(Default)]
struct CollectorSink {
    entries: SharedEntries,
}

impl LogSink for CollectorSink {
    fn insert_batch<'s>(
        &'s self,
        entries: &'s [InsertLogEntry],
    ) -> BoxFuture<'s, Result<usize, SentinelError>> {
        let snapshot = entries.to_vec();
        let entries_ref = self.entries.clone();
        Box::pin(async move {
            let len = snapshot.len();
            entries_ref.lock().unwrap().extend(snapshot);
            Ok(len)
        })
    }
}

/// Poll `entries` until `n` of them are present or the deadline passes.
async fn wait_for_entries(entries: &SharedEntries, n: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if entries.lock().unwrap().len() >= n {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {n} entries, got {:?}",
            entries.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The full daemon path (minus Postgres): a written file is tailed,
/// every line is parsed, filtered, classified, and flushed to the sink
/// with the right fields.
#[tokio::test]
async fn test_file_to_sink_end_to_end() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let log_path = temp_dir.path().join("shop.example.com-access.log");
    std::fs::write(
        &log_path,
        format!("{CLEAN_LINE}\n{ATTACK_LINE}\n{NOISE_LINE}\n{HEALTHCHECK_LINE}\n{SCANNER_LINE}\n"),
    )
    .unwrap();

    let mut tailer = FileTailer::new()
        .with_watch_directory(temp_dir.path().to_path_buf(), "*.log")
        .unwrap();
    let rx = tailer.start().await.unwrap();

    let pool = sqlx::PgPool::connect_lazy("postgresql://invalid:5432/none")
        .expect("lazy pool does not connect");
    let pipeline = build_pipeline(pool, &NoiseFilterConfig::default());

    let sink = CollectorSink::default();
    let observed = sink.entries.clone();
    // Batch size 1: every processed line is flushed immediately, so the
    // test observes entries without depending on the flush timer.
    let scanner = Scanner::with_batching(pipeline, 1, None);
    let cancel = scanner.cancel_token();

    let handle = tokio::spawn(async move {
        scanner.run(rx, &sink).await.unwrap();
    });

    wait_for_entries(&observed, 5).await;

    cancel.cancel();
    tailer.stop();
    handle.await.unwrap();

    let entries = observed.lock().unwrap();

    // The DB is unreachable: entries are stored, just without a service.
    assert!(
        entries.iter().all(|e| e.service_id.is_none()),
        "service resolution must degrade gracefully without a DB"
    );

    let clean = entries
        .iter()
        .find(|e| e.request_path.as_deref() == Some("/index.html"))
        .expect("clean line must be stored");
    assert_eq!(clean.level, "info");
    assert_eq!(clean.threat_level, "none");
    assert!(!clean.is_noise);
    assert_eq!(clean.status_code, Some(200));
    assert!(clean.raw_line.is_some());

    let attack = entries
        .iter()
        .find(|e| {
            e.request_path
                .as_deref()
                .is_some_and(|p| p.starts_with("/users"))
        })
        .expect("attack line must be stored");
    assert_eq!(attack.level, "security", "High+ threats store as security");
    assert_eq!(attack.threat_level, "high");
    assert!(
        attack
            .threat_categories
            .contains(&"sql-injection".to_string()),
        "expected sql-injection category, got {:?}",
        attack.threat_categories
    );

    let noise = entries
        .iter()
        .find(|e| e.client_ip.as_deref() == Some("127.0.0.1"))
        .expect("noise line must be stored");
    assert!(noise.is_noise, "loopback health check is default noise");
    assert!(noise.noise_reason.is_some());
    assert!(noise.raw_line.is_none(), "noise lines drop their raw line");

    let healthcheck = entries
        .iter()
        .find(|e| e.client_ip.as_deref() == Some("203.0.113.7"))
        .expect("external health check must be stored");
    assert!(healthcheck.is_noise, "health checks are noise from any IP");
    assert!(
        healthcheck.raw_line.is_none(),
        "aggregated noise drops its raw line"
    );

    let scanner = entries
        .iter()
        .find(|e| e.request_path.as_deref() == Some("/wp-admin"))
        .expect("scanner path must be stored");
    assert_eq!(
        scanner.level, "security",
        "reconnaissance endpoints are stored as security events"
    );
}
