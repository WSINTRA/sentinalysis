use std::process::Command;

use crate::error::SentinelError;

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceStatus {
    pub name: String,
    pub active_state: String,
    pub sub_state: String,
    pub load_state: String,
    pub main_pid: Option<u32>,
    pub restart_count: u32,
    pub memory_current: Option<u64>,
    pub cpu_usage_seconds: Option<f64>,
}

#[derive(Debug, Clone, Default)]
pub struct ServiceMonitor;

impl ServiceMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn get_status(&self, service_name: &str) -> Result<ServiceStatus, SentinelError> {
        let properties = Self::get_systemctl_properties(service_name)?;

        let active_state = properties
            .get("ActiveState")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let sub_state = properties
            .get("SubState")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let load_state = properties
            .get("LoadState")
            .cloned()
            .unwrap_or_else(|| "not-found".to_string());

        let main_pid = parse_pid(properties.get("MainPID"));
        let restart_count = parse_u32(properties.get("NRestart"), 0);
        let memory_current = parse_bytes(properties.get("MemoryCurrent"));
        let cpu_usage_seconds = parse_cpu_usec(properties.get("CPUUsageNSec"));

        Ok(ServiceStatus {
            name: service_name.to_string(),
            active_state,
            sub_state,
            load_state,
            main_pid,
            restart_count,
            memory_current,
            cpu_usage_seconds,
        })
    }

    fn get_systemctl_properties(
        service_name: &str,
    ) -> Result<std::collections::HashMap<String, String>, SentinelError> {
        let unit = if service_name.ends_with(".service") {
            service_name.to_string()
        } else {
            format!("{service_name}.service")
        };

        let output = Command::new("systemctl")
            .args(["show", "--property=ActiveState,SubState,LoadState,MainPID,NRestart,MemoryCurrent,CPUUsageNSec", &unit])
            .output()
            .map_err(|e| {
                SentinelError::ServiceError(format!(
                    "failed to run systemctl show '{unit}': {e}"
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SentinelError::ServiceError(format!(
                "systemctl show '{unit}' failed: {stderr}"
            )));
        }

        let mut properties = std::collections::HashMap::new();
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            if let Some((key, value)) = line.split_once('=') {
                properties.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        Ok(properties)
    }

    pub fn list_active_services(&self) -> Result<Vec<String>, SentinelError> {
        let output = Command::new("systemctl")
            .args([
                "list-units",
                "--type=service",
                "--state=active",
                "--no-pager",
                "--no-legend",
            ])
            .output()
            .map_err(|e| {
                SentinelError::ServiceError(format!("failed to run systemctl list-units: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SentinelError::ServiceError(format!(
                "systemctl list-units failed: {stderr}"
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let services = stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                parts.first().map(|s| s.trim().to_string())
            })
            .collect();

        Ok(services)
    }
}

fn parse_pid(value: Option<&String>) -> Option<u32> {
    value.and_then(|v| {
        if v.is_empty() || *v == "0" {
            None
        } else {
            v.parse().ok()
        }
    })
}

fn parse_u32(value: Option<&String>, default: u32) -> u32 {
    value.and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn parse_bytes(value: Option<&String>) -> Option<u64> {
    value.and_then(|v| {
        if v.is_empty() || *v == "0" || *v == "inactive" {
            return None;
        }

        let v = v.trim();
        if let Some(stripped) = v.strip_suffix('K') {
            stripped.parse::<f64>().ok().map(|n| (n * 1024.0) as u64)
        } else if let Some(stripped) = v.strip_suffix('M') {
            stripped
                .parse::<f64>()
                .ok()
                .map(|n| (n * 1024.0 * 1024.0) as u64)
        } else if let Some(stripped) = v.strip_suffix('G') {
            stripped
                .parse::<f64>()
                .ok()
                .map(|n| (n * 1024.0 * 1024.0 * 1024.0) as u64)
        } else {
            v.parse().ok()
        }
    })
}

#[allow(clippy::cast_precision_loss)]
fn parse_cpu_usec(value: Option<&String>) -> Option<f64> {
    value.and_then(|v| {
        if v.is_empty() || *v == "0" {
            return None;
        }
        v.parse::<u64>()
            .ok()
            .map(|nanos| nanos as f64 / 1_000_000_000.0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_creation() {
        let monitor = ServiceMonitor::new();
        let _ = &monitor;
    }

    #[test]
    fn test_monitor_default() {
        let monitor = ServiceMonitor::default();
        let _ = &monitor;
    }

    #[test]
    fn test_parse_pid_valid() {
        assert_eq!(parse_pid(Some(&"1234".to_string())), Some(1234));
    }

    #[test]
    fn test_parse_pid_zero() {
        assert_eq!(parse_pid(Some(&"0".to_string())), None);
    }

    #[test]
    fn test_parse_pid_empty() {
        assert_eq!(parse_pid(Some(&"".to_string())), None);
    }

    #[test]
    fn test_parse_pid_none() {
        assert_eq!(parse_pid(None), None);
    }

    #[test]
    fn test_parse_u32_valid() {
        assert_eq!(parse_u32(Some(&"5".to_string()), 0), 5);
    }

    #[test]
    fn test_parse_u32_invalid() {
        assert_eq!(parse_u32(Some(&"invalid".to_string()), 10), 10);
    }

    #[test]
    fn test_parse_bytes_kilobytes() {
        assert_eq!(parse_bytes(Some(&"1024K".to_string())), Some(1048576));
    }

    #[test]
    fn test_parse_bytes_megabytes() {
        assert_eq!(parse_bytes(Some(&"1M".to_string())), Some(1048576));
    }

    #[test]
    fn test_parse_bytes_gigabytes() {
        assert_eq!(parse_bytes(Some(&"1G".to_string())), Some(1073741824));
    }

    #[test]
    fn test_parse_bytes_raw() {
        assert_eq!(parse_bytes(Some(&"5000".to_string())), Some(5000));
    }

    #[test]
    fn test_parse_bytes_inactive() {
        assert_eq!(parse_bytes(Some(&"inactive".to_string())), None);
    }

    #[test]
    fn test_parse_cpu_usec() {
        assert_eq!(parse_cpu_usec(Some(&"1500000000".to_string())), Some(1.5));
    }

    #[test]
    fn test_parse_cpu_usec_zero() {
        assert_eq!(parse_cpu_usec(Some(&"0".to_string())), None);
    }

    #[test]
    fn test_service_status_structure() {
        let status = ServiceStatus {
            name: "my-app".to_string(),
            active_state: "active".to_string(),
            sub_state: "running".to_string(),
            load_state: "loaded".to_string(),
            main_pid: Some(1234),
            restart_count: 3,
            memory_current: Some(1048576),
            cpu_usage_seconds: Some(1.5),
        };
        assert_eq!(status.name, "my-app");
        assert_eq!(status.active_state, "active");
    }
}
