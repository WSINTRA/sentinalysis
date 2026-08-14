use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::db::models::InsertLogEntry;
use crate::db::repositories::log_entry_repo::LogEntryRepository;
use crate::db::repositories::service_repo::ServiceRepository;
use crate::error::SentinelError;
use crate::log_scanner::classifier::{Classifier, ThreatLevel, ThreatResult};
use crate::log_scanner::filter::{FilterResult, NoiseFilter};
use crate::log_scanner::parser::LogParser;
use crate::log_scanner::parser::nginx::NginxAccessParser;
use crate::log_scanner::tailer::{TailEvent, TailLine};

const BATCH_SIZE: usize = 100;
const BATCH_INTERVAL: Duration = Duration::from_secs(1);

pub struct Scanner {
    pool: PgPool,
    cancel_token: CancellationToken,
}

impl Scanner {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cancel_token: CancellationToken::new(),
        }
    }

    pub fn stop(&self) {
        self.cancel_token.cancel();
    }

    pub async fn run(self, mut rx: Receiver<TailEvent>) -> Result<(), SentinelError> {
        let log_repo = LogEntryRepository::new(self.pool.clone());
        let service_repo = ServiceRepository::new(self.pool.clone());
        let filter = Arc::new(NoiseFilter::new());
        let classifier = Arc::new(Classifier::new());
        let nginx_parser = Arc::new(NginxAccessParser::new());

        let mut batch: Vec<InsertLogEntry> = Vec::with_capacity(BATCH_SIZE);
        let mut flush_interval = tokio::time::interval(BATCH_INTERVAL);

        info!("scanner started");

        loop {
            tokio::select! {
                () = self.cancel_token.cancelled() => {
                    if !batch.is_empty() {
                        self.flush_batch(&log_repo, &mut batch).await?;
                    }
                    info!("scanner stopped");
                    break;
                }
                _ = flush_interval.tick() => {
                    if !batch.is_empty() {
                        self.flush_batch(&log_repo, &mut batch).await?;
                    }
                }
                Some(event) = rx.recv() => {
                    match event {
                        Ok(line) => {
                            if let Err(e) = self.process_line(
                                &line,
                                &nginx_parser,
                                &filter,
                                &classifier,
                                &service_repo,
                                &mut batch,
                            ).await {
                                warn!("failed to process line: {}", e);
                            }

                            if batch.len() >= BATCH_SIZE {
                                self.flush_batch(&log_repo, &mut batch).await?;
                            }
                        }
                        Err(e) => {
                            error!("tailer error: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn extract_vhost_from_file_path(file_path: &Path) -> Option<String> {
        file_path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|name| name.ends_with("-access.log"))
            .map(|name| name.trim_end_matches("-access.log").to_string())
    }

    #[allow(clippy::cast_possible_wrap)]
    async fn process_line(
        &self,
        line: &TailLine,
        parser: &Arc<NginxAccessParser>,
        filter: &Arc<NoiseFilter>,
        classifier: &Arc<Classifier>,
        service_repo: &ServiceRepository,
        batch: &mut Vec<InsertLogEntry>,
    ) -> Result<(), SentinelError> {
        let parsed = parser
            .parse(&line.line)
            .map_err(|e| SentinelError::ParseError(format!(
                "{} [{}]: {}",
                parser.name(),
                line.file_path.display(),
                e
            )))?;

        let Some(entry) = parsed else {
            return Ok(());
        };

        let filter_result = filter.evaluate(&entry);
        let threat_result = classifier.classify(&entry);

        let is_noise = matches!(filter_result, FilterResult::Exclude(_));
        let noise_reason = match &filter_result {
            FilterResult::Exclude(reason) => Some(reason.clone()),
            _ => None,
        };

        let virtual_host = Self::extract_vhost_from_file_path(&line.file_path)
            .or_else(|| entry.metadata.virtual_host.clone());
        let service_id = if let Some(vhost) = &virtual_host {
            let service = crate::db::models::InsertService {
                name: vhost.clone(),
                unit_type: "nginx-vhost".to_string(),
                log_paths: None,
                virtual_host: Some(vhost.clone()),
            };
            match service_repo.get_or_create(&service).await {
                Ok(id) => Some(id),
                Err(e) => {
                    warn!("failed to get/create service '{}': {}", vhost, e);
                    None
                }
            }
        } else {
            None
        };

        let level = Self::classify_level(entry.level, &threat_result);

        let db_entry = InsertLogEntry {
            service_id,
            timestamp: entry.timestamp,
            level,
            message: entry.message,
            raw_line: if is_noise { None } else { Some(entry.raw) },
            client_ip: entry.metadata.client_ip.map(|ip| ip.to_string()),
            request_path: entry.metadata.request_path,
            status_code: entry.metadata.status_code.map(|s| s as i16),
            response_time_ms: entry.metadata.response_time_ms.map(|ms| ms as i64),
            is_noise,
            noise_reason,
        };

        batch.push(db_entry);
        Ok(())
    }

    fn classify_level(
        base_level: crate::log_scanner::parser::LogLevel,
        threat: &ThreatResult,
    ) -> String {
        if threat.threat_level >= ThreatLevel::High {
            return "security".to_string();
        }

        match base_level {
            crate::log_scanner::parser::LogLevel::Debug => "debug".to_string(),
            crate::log_scanner::parser::LogLevel::Info => "info".to_string(),
            crate::log_scanner::parser::LogLevel::Warn => "warn".to_string(),
            crate::log_scanner::parser::LogLevel::Error => "error".to_string(),
            crate::log_scanner::parser::LogLevel::Critical => "critical".to_string(),
            crate::log_scanner::parser::LogLevel::Security => "security".to_string(),
        }
    }

    async fn flush_batch(
        &self,
        log_repo: &LogEntryRepository,
        batch: &mut Vec<InsertLogEntry>,
    ) -> Result<(), SentinelError> {
        if batch.is_empty() {
            return Ok(());
        }

        let count = batch.len();
        let entries = std::mem::take(batch);

        match log_repo.insert_batch(&entries).await {
            Ok(inserted) => {
                info!("flushed {} log entries ({} inserted)", count, inserted);
            }
            Err(e) => {
                error!("failed to flush batch: {}", e);
                *batch = entries;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_scanner::parser::LogLevel;

    #[tokio::test]
    async fn test_scanner_creation() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost/test").unwrap();
        let scanner = Scanner::new(pool);
        let _ = &scanner;
    }

    #[tokio::test]
    async fn test_scanner_stop() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost/test").unwrap();
        let scanner = Scanner::new(pool);
        scanner.stop();
        assert!(scanner.cancel_token.is_cancelled());
    }

    #[test]
    fn test_classify_level_security_threat() {
        let threat = crate::log_scanner::classifier::ThreatResult {
            threat_level: ThreatLevel::High,
            categories: vec![],
            confidence: 0.9,
        };
        let level = Scanner::classify_level(LogLevel::Info, &threat);
        assert_eq!(level, "security");
    }

    #[test]
    fn test_classify_level_base_info() {
        let threat = crate::log_scanner::classifier::ThreatResult {
            threat_level: ThreatLevel::None,
            categories: vec![],
            confidence: 0.0,
        };
        let level = Scanner::classify_level(LogLevel::Info, &threat);
        assert_eq!(level, "info");
    }

    #[test]
    fn test_classify_level_base_error() {
        let threat = crate::log_scanner::classifier::ThreatResult {
            threat_level: ThreatLevel::None,
            categories: vec![],
            confidence: 0.0,
        };
        let level = Scanner::classify_level(LogLevel::Error, &threat);
        assert_eq!(level, "error");
    }

    #[tokio::test]
    async fn test_flush_batch_empty() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost/test").unwrap();
        let scanner = Scanner::new(pool.clone());
        let log_repo = LogEntryRepository::new(pool);
        let mut batch: Vec<InsertLogEntry> = vec![];

        let result = scanner.flush_batch(&log_repo, &mut batch).await;
        assert!(result.is_ok());
    }
}
