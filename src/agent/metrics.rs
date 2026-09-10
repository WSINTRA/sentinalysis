//! System metrics collection via `sysinfo`.
//!
//! Every source (`/proc/stat`, `/proc/meminfo`, `/proc/loadavg`,
//! `/proc/net/dev`, statvfs) is world-readable, so collection works fully
//! as a non-root user.

use std::time::{SystemTime, UNIX_EPOCH};

use sysinfo::{Disks, Networks, RefreshKind, System};

/// One collected sample, proto-ready.
#[derive(Debug, Clone)]
pub struct CollectedMetrics {
    pub timestamp_ms: i64,
    pub cpu_percent: f32,
    pub mem_used_bytes: u64,
    pub mem_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub load_1m: f64,
    pub load_5m: f64,
    pub net_rx_bytes_total: u64,
    pub net_tx_bytes_total: u64,
}

/// Collects host metrics; keep one instance alive so `sysinfo`'s
/// CPU-average bookkeeping works across refreshes.
pub struct SystemMetricsCollector {
    system: System,
    networks: Networks,
    disks: Disks,
}

impl Default for SystemMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemMetricsCollector {
    #[must_use]
    pub fn new() -> Self {
        let mut system = System::new();
        // Two refreshes spaced by the CPU interval give sysinfo the baseline
        // it needs for a meaningful first reading; a single refresh reports
        // zeros on some platforms.
        system.refresh_specifics(
            RefreshKind::nothing()
                .with_cpu(sysinfo::CpuRefreshKind::everything())
                .with_memory(sysinfo::MemoryRefreshKind::everything()),
        );
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        system.refresh_specifics(
            RefreshKind::nothing()
                .with_cpu(sysinfo::CpuRefreshKind::everything())
                .with_memory(sysinfo::MemoryRefreshKind::everything()),
        );

        Self {
            system,
            networks: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
        }
    }

    /// Refreshes and returns the current sample.
    pub fn collect(&mut self) -> CollectedMetrics {
        self.system.refresh_specifics(
            RefreshKind::nothing()
                .with_cpu(sysinfo::CpuRefreshKind::everything())
                .with_memory(sysinfo::MemoryRefreshKind::everything()),
        );
        self.networks.refresh(true);
        self.disks.refresh(true);

        let load = System::load_average();
        let (disk_used, disk_total) = disk_totals(&self.disks);

        CollectedMetrics {
            timestamp_ms: now_millis(),
            cpu_percent: self.system.global_cpu_usage(),
            mem_used_bytes: self.system.used_memory(),
            mem_total_bytes: self.system.total_memory(),
            disk_used_bytes: disk_used,
            disk_total_bytes: disk_total,
            load_1m: load.one,
            load_5m: load.five,
            net_rx_bytes_total: self
                .networks
                .values()
                .map(sysinfo::NetworkData::total_received)
                .sum(),
            net_tx_bytes_total: self
                .networks
                .values()
                .map(sysinfo::NetworkData::total_transmitted)
                .sum(),
        }
    }
}

/// Sums usage across all physical disks (skipping loop/ram pseudo-devices).
fn disk_totals(disks: &Disks) -> (u64, u64) {
    let mut used = 0u64;
    let mut total = 0u64;
    for disk in disks.list() {
        let mount = disk.mount_point().to_string_lossy();
        if mount.starts_with("/dev")
            || mount.starts_with("/run")
            || mount.starts_with("/proc")
            || mount.starts_with("/sys")
            || mount.starts_with("loop")
        {
            continue;
        }
        used += disk.total_space().saturating_sub(disk.available_space());
        total += disk.total_space();
    }
    (used, total)
}

/// Current UNIX time in milliseconds.
#[must_use]
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or_default())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_plausible_metrics() {
        let mut collector = SystemMetricsCollector::new();
        let metrics = collector.collect();
        assert!(metrics.timestamp_ms > 0);
        assert!(metrics.cpu_percent >= 0.0);
        assert!(metrics.mem_total_bytes > 0);
        assert!(metrics.disk_total_bytes > 0);
        assert!(metrics.load_1m >= 0.0);
        assert!(metrics.load_5m >= 0.0);
        // Used cannot exceed total for memory and disk.
        assert!(metrics.mem_used_bytes <= metrics.mem_total_bytes);
        assert!(metrics.disk_used_bytes <= metrics.disk_total_bytes);
    }

    #[test]
    fn now_millis_is_reasonable() {
        let now = now_millis();
        // 2026-01-01 in ms.
        assert!(now > 1_767_225_600_000);
        assert!(now < 4_102_444_800_000); // year 2100 sanity cap
    }
}
