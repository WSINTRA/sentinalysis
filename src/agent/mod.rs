//! Sentinel agent: forwards system metrics + Docker logs to the hub.
//!
//! The agent is a stateless forwarder: its identity is its API key, and
//! the hub derives `agent_id`/`hostname` from the key row (nothing
//! identity-shaped crosses the wire). Runs as a hardened non-root systemd service.

pub mod batcher;
pub mod docker_logs;
pub mod metrics;

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::config::{AgentConfig, Config};
use crate::error::SentinelError;
use crate::hub::pb::ingest_client::IngestClient;
use crate::hub::pb::{LogLine, LogsRequest, MetricPoint, MetricsRequest};
use batcher::{BoundedBatcher, PendingLine};

/// Runs the agent until SIGINT/SIGTERM.
///
/// # Errors
/// Config errors; runtime failures are logged and handled by reconnect
/// logic.
pub async fn run(config: Config) -> Result<(), SentinelError> {
    let agent = &config.agent;
    if !agent.enabled {
        return Err(SentinelError::ConfigError(
            "agent mode requested but agent.enabled is false in the config".into(),
        ));
    }
    if agent.api_key.is_empty() {
        return Err(SentinelError::ConfigError(
            "agent.api_key (or SENTINEL_API_KEY_FILE) is required in agent mode".into(),
        ));
    }

    let cancel = CancellationToken::new();

    let mut client = HubClient::connect(agent, &cancel).await?;
    let mut batcher = BoundedBatcher::new(agent.log_buffer_max);

    // Discover containers once; retry discovery on the next flush cycle if
    // Docker wasn't ready at boot. The sync mpsc receiver is bridged into
    // the main loop via a pump task.
    let (log_tx, mut log_rx) = tokio::sync::mpsc::channel::<docker_logs::DockerLogLine>(1024);
    match docker_logs::tail_containers(
        std::path::Path::new(docker_logs::DEFAULT_DOCKER_ROOT),
        &agent.containers,
        &cancel,
    ) {
        Ok(sync_rx) => {
            tokio::spawn(async move {
                let mut sync_rx = sync_rx;
                while let Some(line) = sync_rx.recv().await {
                    if log_tx.send(line).await.is_err() {
                        return;
                    }
                }
            });
        }
        Err(e) => tracing::warn!("docker log discovery failed: {e}"),
    }

    let mut metrics_interval =
        tokio::time::interval(Duration::from_secs(agent.metrics_interval_secs.max(1)));
    let mut flush_interval =
        tokio::time::interval(Duration::from_secs(agent.log_flush_interval_secs.max(1)));
    let mut collector = metrics::SystemMetricsCollector::new();

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                shutdown(&mut client, &mut batcher, agent.flush_timeout_secs).await;
                return Ok(());
            }
            _ = metrics_interval.tick() => {
                let sample = collector.collect();
                let point = MetricPoint {
                    timestamp_ms: sample.timestamp_ms,
                    cpu_percent: f64::from(sample.cpu_percent),
                    mem_used_bytes: sample.mem_used_bytes,
                    mem_total_bytes: sample.mem_total_bytes,
                    disk_used_bytes: sample.disk_used_bytes,
                    disk_total_bytes: sample.disk_total_bytes,
                    load_1m: sample.load_1m,
                    load_5m: sample.load_5m,
                    net_rx_bytes_total: sample.net_rx_bytes_total,
                    net_tx_bytes_total: sample.net_tx_bytes_total,
                };
                if let Err(e) = client.send_metrics(point).await {
                    tracing::warn!("metrics send failed: {e}");
                }
            }
            _ = flush_interval.tick() => {
                flush(&mut client, &mut batcher, agent.log_batch_size).await;
            }
            line = log_rx.recv() => {
                let Some(line) = line else {
                    // Channel closed; wait for shutdown instead of spinning.
                    std::future::pending::<()>().await;
                    unreachable!();
                };
                batcher.push(PendingLine {
                    timestamp_ms: line.timestamp_ms,
                    container: line.container.clone(),
                    stream: line.stream.clone(),
                    message: line.message.clone(),
                });
                if batcher.len() >= agent.log_batch_size {
                    flush(&mut client, &mut batcher, agent.log_batch_size).await;
                }
            }
        }
    }
}

/// Flushes buffered lines (bounded per request).
async fn flush(client: &mut HubClient, batcher: &mut BoundedBatcher, batch_size: usize) {
    if batcher.is_empty() {
        return;
    }
    let lines = batcher
        .drain(batch_size)
        .into_iter()
        .map(|pending| LogLine {
            timestamp_ms: pending.timestamp_ms,
            container: pending.container.clone(),
            stream: pending.stream.clone(),
            message: pending.message.clone(),
        })
        .collect::<Vec<_>>();
    if let Err(e) = client.send_logs(lines).await {
        tracing::warn!("logs send failed: {e}");
    }
    let dropped = batcher.take_dropped();
    if dropped > 0 {
        tracing::warn!(dropped, "agent dropped oldest log lines (hub unreachable)");
    }
}

/// Final flush with a deadline; leftover drops are counted and logged.
async fn shutdown(client: &mut HubClient, batcher: &mut BoundedBatcher, timeout_secs: u64) {
    let deadline = Duration::from_secs(timeout_secs.max(1));
    let flush_future = flush(client, batcher, usize::MAX);
    if tokio::time::timeout(deadline, flush_future).await.is_err() {
        tracing::warn!(
            buffered = batcher.len(),
            "final flush deadline hit; buffered lines dropped"
        );
    }
    let remaining = batcher.take_dropped();
    let total = batcher.total_dropped();
    tracing::info!(
        dropped_now = remaining,
        total_dropped = total,
        "agent shutdown"
    );
}

/// gRPC client with `x-api-key` auth on every call.
pub struct HubClient {
    client: IngestClient<tonic::transport::Channel>,
    api_key: String,
}

impl HubClient {
    /// Connects with retry + exponential backoff until the hub is
    /// reachable or `cancel` fires.
    ///
    /// # Errors
    /// Config error when the hub address is unparseable; returns Ok even
    /// while disconnected (call sites handle per-call errors).
    pub async fn connect(
        agent: &AgentConfig,
        cancel: &CancellationToken,
    ) -> Result<Self, SentinelError> {
        let endpoint = tonic::transport::Endpoint::from_shared(format!(
            "http://{}",
            agent
                .hub_addr
                .trim_start_matches("http://")
                .trim_start_matches("https://")
        ))
        .map_err(|e| {
            SentinelError::ConfigError(format!("invalid hub_addr '{}': {e}", agent.hub_addr))
        })?
        .connect_timeout(Duration::from_secs(agent.connect_timeout_secs.max(1)))
        .tcp_nodelay(true);

        let mut backoff = 1u64;
        let channel = loop {
            if cancel.is_cancelled() {
                return Err(SentinelError::ServiceError(
                    "cancelled during connect".into(),
                ));
            }
            match endpoint.connect().await {
                Ok(channel) => break channel,
                Err(e) => {
                    tracing::warn!(hub_addr = %agent.hub_addr, backoff_secs = backoff, "hub connect failed: {e}");
                    tokio::select! {
                        () = cancel.cancelled() => {
                            return Err(SentinelError::ServiceError("cancelled during connect".into()));
                        }
                        () = tokio::time::sleep(Duration::from_secs(backoff)) => {
                            backoff = (backoff * 2).min(60);
                        }
                    }
                }
            }
        };

        Ok(Self {
            client: IngestClient::new(channel),
            api_key: agent.api_key.clone(),
        })
    }

    /// Sends one metric sample.
    ///
    /// # Errors
    /// gRPC failure.
    // tonic::Status is a fixed-size type imposed by the client API; the
    // lint's boxing suggestion would only complicate call sites.
    #[allow(unknown_lints, clippy::result_large_err)]
    pub async fn send_metrics(&mut self, point: MetricPoint) -> Result<(), tonic::Status> {
        let mut request = tonic::Request::new(MetricsRequest { point: Some(point) });
        request
            .metadata_mut()
            .insert("x-api-key", self.api_key.parse().expect("valid metadata"));
        self.client.send_metrics(request).await.map(|_| ())
    }

    /// Sends a batch of log lines.
    ///
    /// # Errors
    /// gRPC failure.
    #[allow(unknown_lints, clippy::result_large_err)]
    pub async fn send_logs(&mut self, lines: Vec<LogLine>) -> Result<(), tonic::Status> {
        let mut request = tonic::Request::new(LogsRequest { lines });
        request
            .metadata_mut()
            .insert("x-api-key", self.api_key.parse().expect("valid metadata"));
        self.client.send_logs(request).await.map(|_| ())
    }
}
