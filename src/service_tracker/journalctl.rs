//! Tail systemd journal output for the configured services.
use std::thread;
use std::time::Duration;

use crossbeam_channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender, bounded};
use sdjournal::Journal;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::error::SentinelError;

#[derive(Debug, Clone)]
pub struct JournalLine {
    pub service: String,
    pub line: String,
}

pub struct JournalctlTailer {
    cancel_token: CancellationToken,
}

impl JournalctlTailer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancel_token: CancellationToken::new(),
        }
    }

    pub fn stop(&self) {
        self.cancel_token.cancel();
    }

    pub fn tail_services(
        &self,
        services: &[String],
    ) -> Result<Receiver<JournalLine>, SentinelError> {
        if services.is_empty() {
            return Err(SentinelError::ConfigError(
                "no services specified for journalctl tailing".into(),
            ));
        }

        let journal = Journal::open_default().map_err(|e| {
            SentinelError::ServiceError(format!("failed to open systemd journal: {e}"))
        })?;

        let live = journal.live().map_err(|e| {
            SentinelError::ServiceError(format!("failed to create live journal: {e}"))
        })?;

        let (tx, rx) = mpsc::channel::<JournalLine>(1024);
        let cancel = self.cancel_token.clone();

        let mut live = live;
        let mut subscriptions = Vec::with_capacity(services.len());

        for service in services {
            let unit = normalize_unit(service);
            let mut filter = live.filter();
            filter.match_unit(&unit);

            let sub = live.subscribe(filter).map_err(|e| {
                SentinelError::ServiceError(format!(
                    "failed to subscribe to journal for '{unit}': {e}"
                ))
            })?;

            subscriptions.push((service.clone(), sub));
        }

        let engine_handle = thread::spawn(move || {
            if let Err(e) = live.run() {
                warn!("live journal engine stopped: {e}");
            }
        });

        for (service, sub) in subscriptions {
            let tx_clone = tx.clone();
            let cancel_clone = cancel.clone();

            tokio::spawn(async move {
                if let Err(e) = consume_subscription(&service, sub, tx_clone, cancel_clone).await {
                    error!("journal tail error for '{service}': {e}");
                }
            });
        }

        let cancel_for_engine = self.cancel_token.clone();
        tokio::spawn(async move {
            cancel_for_engine.cancelled().await;
            let () = engine_handle.thread().unpark();
        });

        info!("journalctl tailer started for {} services", services.len());
        Ok(rx)
    }
}

impl Default for JournalctlTailer {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_unit(service: &str) -> String {
    if service.ends_with(".service") {
        service.to_string()
    } else {
        format!("{service}.service")
    }
}

/// Join a thread, waiting at most `timeout`. Returns whether the thread
/// finished within the deadline — a stuck journal read must not hang
/// shutdown.
fn join_bounded(handle: std::thread::JoinHandle<()>, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while !handle.is_finished() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // The thread has exited (possibly with a panic); `join` now returns
    // immediately, so any panic is re-raised to the caller.
    let _ = handle.join();
    true
}

async fn consume_subscription(
    service: &str,
    sub: sdjournal::LiveSubscription,
    tx: Sender<JournalLine>,
    cancel: CancellationToken,
) -> Result<(), SentinelError> {
    info!("journal tailing started for '{}'", normalize_unit(service));

    let (bridge_tx, bridge_rx): (CrossbeamSender<JournalLine>, CrossbeamReceiver<JournalLine>) =
        bounded(256);

    let service_name = service.to_string();
    let read_handle = thread::spawn(move || {
        loop {
            match sub.recv() {
                Ok(Ok(entry)) => {
                    if let Some(message_bytes) = entry.get("MESSAGE") {
                        let message = String::from_utf8_lossy(message_bytes)
                            .trim_end_matches('\0')
                            .trim()
                            .to_string();

                        if message.is_empty() {
                            continue;
                        }

                        let journal_line = JournalLine {
                            service: service_name.clone(),
                            line: message,
                        };

                        if bridge_tx.send(journal_line).is_err() {
                            break;
                        }
                    }
                }

                Ok(Err(e)) => {
                    warn!("journal read error for '{service_name}': {e}");
                    thread::sleep(Duration::from_secs(1));
                }

                Err(_) => {
                    info!("journal subscription closed for '{service_name}'");
                    break;
                }
            }
        }
    });

    let rt = tokio::runtime::Handle::current();

    let mut bridge_handle = tokio::spawn(async move {
        while let Ok(journal_line) = bridge_rx.recv() {
            if rt.block_on(tx.send(journal_line)).is_err() {
                break;
            }
        }
    });

    tokio::select! {
        biased;

        () = cancel.cancelled() => {
            if !join_bounded(read_handle, Duration::from_secs(5)) {
                warn!(
                    "journal read thread for '{service}' did not exit in time; abandoning it"
                );
            }
            bridge_handle.abort();
            info!("journal tailer stopped for '{service}'");
            Ok(())
        }

        _ = (&mut bridge_handle) => {
            if !join_bounded(read_handle, Duration::from_secs(5)) {
                warn!(
                    "journal read thread for '{service}' did not exit in time; abandoning it"
                );
            }
            Err(SentinelError::ServiceError(
                "journal bridge channel closed".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tailer_creation() {
        let tailer = JournalctlTailer::new();
        let _ = &tailer;
    }

    #[test]
    fn test_tailer_default() {
        let tailer = JournalctlTailer::default();
        let _ = &tailer;
    }

    #[tokio::test]
    async fn test_tailer_stop() {
        let tailer = JournalctlTailer::new();
        tailer.stop();
        assert!(tailer.cancel_token.is_cancelled());
    }

    #[test]
    fn test_tail_services_empty_list_fails() {
        let tailer = JournalctlTailer::new();
        let result = tailer.tail_services(&[]);
        assert!(result.is_err());
        match result {
            Err(SentinelError::ConfigError(msg)) => {
                assert!(msg.contains("no services specified"));
            }
            _ => panic!("Expected ConfigError"),
        }
    }

    #[test]
    fn test_journal_line_structure() {
        let line = JournalLine {
            service: "my-python-app.service".to_string(),
            line: "INFO: Application started".to_string(),
        };
        assert_eq!(line.service, "my-python-app.service");
    }

    #[test]
    fn test_normalize_unit_with_suffix() {
        assert_eq!(normalize_unit("my-app.service"), "my-app.service");
    }

    #[test]
    fn test_normalize_unit_without_suffix() {
        assert_eq!(normalize_unit("my-app"), "my-app.service");
    }

    #[test]
    fn test_join_bounded_returns_when_thread_finishes() {
        let handle = thread::spawn(|| thread::sleep(Duration::from_millis(20)));
        assert!(join_bounded(handle, Duration::from_secs(1)));
    }

    #[test]
    fn test_join_bounded_gives_up_on_stuck_thread() {
        let handle = thread::spawn(|| thread::sleep(Duration::from_secs(5)));
        let started = std::time::Instant::now();
        assert!(!join_bounded(handle, Duration::from_millis(100)));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "must not block on the stuck thread"
        );
        // The stuck thread is abandoned (it sleeps, then exits harmlessly).
    }
}
