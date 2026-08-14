//! Batching orchestrator for the log pipeline.
//!
//! `Scanner` consumes `TailEvent`s from the tailer, runs each line through
//! the [`Pipeline`], and flushes batches of `InsertLogEntry` to a
//! [`LogSink`] (the database in production, an in-memory collector in
//! tests). Batching policy: flush at `BATCH_SIZE` entries or every
//! `BATCH_INTERVAL`, whichever comes first; a final flush happens on
//! shutdown.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::db::models::InsertLogEntry;
use crate::db::repositories::log_entry_repo::LogEntryRepository;
use crate::error::SentinelError;
use crate::log_scanner::pipeline::{BoxFuture, Pipeline};
use crate::log_scanner::tailer::TailEvent;

/// Flush a batch after this many entries.
pub const BATCH_SIZE: usize = 100;
/// ...or on this timer, whichever comes first.
pub const BATCH_INTERVAL: Duration = Duration::from_secs(1);

/// Persists a batch of log entries.
pub trait LogSink: Send + Sync {
    /// Insert the entries, returning how many were written.
    fn insert_batch<'s>(
        &'s self,
        entries: &'s [InsertLogEntry],
    ) -> BoxFuture<'s, Result<usize, SentinelError>>;
}

/// [`LogSink`] backed by the [`LogEntryRepository`].
pub struct RepositorySink<'a> {
    repo: &'a LogEntryRepository,
}

impl<'a> RepositorySink<'a> {
    #[must_use]
    pub fn new(repo: &'a LogEntryRepository) -> Self {
        Self { repo }
    }
}

impl LogSink for RepositorySink<'_> {
    fn insert_batch<'s>(
        &'s self,
        entries: &'s [InsertLogEntry],
    ) -> BoxFuture<'s, Result<usize, SentinelError>> {
        Box::pin(self.repo.insert_batch(entries))
    }
}

/// Consumes tail events, processes them with the pipeline, and batches
/// writes to the sink.
pub struct Scanner {
    pipeline: Arc<Pipeline>,
    cancel_token: CancellationToken,
    batch_size: usize,
    batch_interval: Option<Duration>,
}

impl Scanner {
    /// Scanner with the default batching policy.
    #[must_use]
    pub fn new(pipeline: Arc<Pipeline>) -> Self {
        Self::with_batching(pipeline, BATCH_SIZE, Some(BATCH_INTERVAL))
    }

    /// Scanner with an explicit batching policy. `batch_interval: None`
    /// disables timer-based flushing (size and shutdown flushes only) —
    /// used by tests for deterministic behaviour.
    #[must_use]
    pub fn with_batching(
        pipeline: Arc<Pipeline>,
        batch_size: usize,
        batch_interval: Option<Duration>,
    ) -> Self {
        Self::with_cancel(
            pipeline,
            batch_size,
            batch_interval,
            CancellationToken::new(),
        )
    }

    /// Like [`Self::with_batching`], but the scanner stops when the
    /// provided external token is cancelled (e.g. the daemon's shutdown
    /// signal), still performing the final flush.
    #[must_use]
    pub fn with_cancel(
        pipeline: Arc<Pipeline>,
        batch_size: usize,
        batch_interval: Option<Duration>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            pipeline,
            cancel_token,
            batch_size,
            batch_interval,
        }
    }

    /// Request a stop; the current batch is flushed before `run` returns.
    pub fn stop(&self) {
        self.cancel_token.cancel();
    }

    /// A clone of the cancel token, for callers that need to stop the
    /// scanner without keeping a `&Scanner` alive.
    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// Run until the cancel token fires or the event stream ends.
    pub async fn run<S: LogSink>(
        self,
        mut rx: Receiver<TailEvent>,
        sink: &S,
    ) -> Result<(), SentinelError> {
        let mut batch: Vec<InsertLogEntry> = Vec::with_capacity(self.batch_size);
        let mut flush_interval = self.batch_interval.map(tokio::time::interval);

        info!("scanner started");

        loop {
            let event = tokio::select! {
                // In-flight events win over cancellation so that lines
                // already in the channel are still processed at shutdown.
                biased;
                Some(event) = rx.recv() => Some(event),
                () = self.cancel_token.cancelled() => None,
                _ = async {
                    match &mut flush_interval {
                        Some(interval) => interval.tick().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if !batch.is_empty() {
                        self.flush_batch(sink, &mut batch).await?;
                    }
                    continue;
                }
            };

            let Some(event) = event else {
                // Cancelled: final flush so no processed entries are lost.
                self.flush_batch(sink, &mut batch).await?;
                info!("scanner stopped");
                break;
            };

            match event {
                Ok(line) => match self.pipeline.process_line(&line).await {
                    Ok(Some(entry)) => batch.push(entry),
                    // Empty/declined lines are expected, not errors.
                    Ok(None) => {}
                    Err(e) => warn!("failed to process line: {e}"),
                },
                Err(e) => error!("tailer error: {e}"),
            }

            if batch.len() >= self.batch_size {
                self.flush_batch(sink, &mut batch).await?;
            }
        }

        Ok(())
    }

    /// Write the pending batch. On failure the entries are put back so
    /// they are retried on the next flush.
    async fn flush_batch<S: LogSink>(
        &self,
        sink: &S,
        batch: &mut Vec<InsertLogEntry>,
    ) -> Result<(), SentinelError> {
        if batch.is_empty() {
            return Ok(());
        }

        let count = batch.len();
        let entries = std::mem::take(batch);

        match sink.insert_batch(&entries).await {
            Ok(inserted) => {
                info!("flushed {count} log entries ({inserted} inserted)");
            }
            Err(e) => {
                error!("failed to flush batch: {e}");
                *batch = entries;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_scanner::classifier::Classifier;
    use crate::log_scanner::filter::NoiseFilter;
    use crate::log_scanner::pipeline::{InMemoryServiceResolver, ParserRegistry};
    use crate::log_scanner::tailer::TailLine;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Collects flushed batches in memory.
    #[derive(Default)]
    struct FakeSink {
        batches: Arc<Mutex<Vec<Vec<InsertLogEntry>>>>,
    }

    impl LogSink for FakeSink {
        fn insert_batch<'s>(
            &'s self,
            entries: &'s [InsertLogEntry],
        ) -> BoxFuture<'s, Result<usize, SentinelError>> {
            let snapshot = entries.to_vec();
            let batches = self.batches.clone();
            Box::pin(async move {
                let len = snapshot.len();
                batches.lock().unwrap().push(snapshot);
                Ok(len)
            })
        }
    }

    fn test_pipeline() -> Arc<Pipeline> {
        Arc::new(Pipeline::new(
            ParserRegistry::default_registry(),
            Arc::new(NoiseFilter::new()),
            Arc::new(Classifier::new()),
            Arc::new(InMemoryServiceResolver::new()),
        ))
    }

    fn nginx_line(i: u64) -> TailLine {
        TailLine {
            file_path: PathBuf::from("/var/log/nginx/app.example.com-access.log"),
            line: format!(
                "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /{i} HTTP/1.1\" 200 15 \"-\" \"curl/8.0\" \"app.example.com\" 0.1"
            ),
            byte_offset: i,
        }
    }

    async fn wait_for_batches(sink: &FakeSink, n: usize) -> bool {
        for _ in 0..250 {
            if sink.batches.lock().unwrap().len() >= n {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn test_scanner_stop_cancels() {
        let scanner = Scanner::new(test_pipeline());
        scanner.stop();
        assert!(scanner.cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_scanner_flushes_at_batch_size_and_on_shutdown() {
        // No timer: only size- and shutdown-based flushes can happen.
        let scanner = Scanner::with_batching(test_pipeline(), BATCH_SIZE, None);
        let cancel = scanner.cancel_token();
        let sink = Arc::new(FakeSink::default());
        let (tx, rx) = tokio::sync::mpsc::channel(2 * BATCH_SIZE);

        let sink2 = sink.clone();
        let handle = tokio::spawn(async move { scanner.run(rx, sink2.as_ref()).await });

        // BATCH_SIZE lines trigger a size-based flush.
        for i in 0..BATCH_SIZE as u64 {
            tx.send(Ok::<TailLine, SentinelError>(nginx_line(i)))
                .await
                .unwrap();
        }
        assert!(
            wait_for_batches(&sink, 1).await,
            "expected a size-based flush"
        );
        assert_eq!(sink.batches.lock().unwrap()[0].len(), BATCH_SIZE);

        // One more line, then shutdown: it is flushed by the final flush.
        tx.send(Ok(nginx_line(BATCH_SIZE as u64))).await.unwrap();
        cancel.cancel();
        handle.await.unwrap().unwrap();

        let batches = sink.batches.lock().unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[1].len(), 1);
    }

    #[tokio::test]
    async fn test_scanner_empty_batch_does_not_flush() {
        let scanner = Scanner::new(test_pipeline());
        let cancel = scanner.cancel_token();
        let sink = Arc::new(FakeSink::default());
        let (tx, rx) = tokio::sync::mpsc::channel(4);

        let sink2 = sink.clone();
        let handle = tokio::spawn(async move { scanner.run(rx, sink2.as_ref()).await });
        drop(tx);
        cancel.cancel();
        handle.await.unwrap().unwrap();

        // Cancelling with an empty batch must not produce a write.
        assert!(sink.batches.lock().unwrap().is_empty());
    }
}
