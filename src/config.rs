//! User configuration (YAML file, optional) and its defaults.
//!
//! Each section owns its own `Default` impl; `Config::default()` — and
//! therefore a missing config file — is exactly the sum of those
//! per-section defaults.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use crate::error::SentinelError;

/// `#[serde(default)]` makes partial config files valid: any omitted
/// section falls back to its own defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub log_watching: LogWatchingConfig,
    pub noise_filter: NoiseFilterConfig,
    pub service_tracker: ServiceTrackerConfig,
    pub journalctl: JournalctlConfig,
    pub hub: HubConfig,
    pub agent: AgentConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogWatchingConfig {
    pub directories: Vec<LogDirectoryConfig>,
    pub files: Vec<PathBuf>,
}

/// Default watch targets: every nginx vhost access log plus the system
/// auth log. The single source of truth for `Config::default()`.
impl Default for LogWatchingConfig {
    fn default() -> Self {
        Self {
            directories: vec![LogDirectoryConfig {
                path: PathBuf::from("/var/log/nginx"),
                pattern: "*.log".to_string(),
            }],
            files: vec![PathBuf::from("/var/log/auth.log")],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogDirectoryConfig {
    pub path: PathBuf,
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NoiseFilterConfig {
    pub excluded_ips: Vec<IpAddr>,
    pub health_check_paths: Vec<String>,
    pub static_asset_extensions: Vec<String>,
    pub known_bot_user_agents: Vec<String>,
}

impl Default for NoiseFilterConfig {
    fn default() -> Self {
        Self {
            excluded_ips: vec![IpAddr::from([127, 0, 0, 1])],
            health_check_paths: vec!["/health".to_string(), "/healthz".to_string()],
            static_asset_extensions: vec![
                "css".to_string(),
                "js".to_string(),
                "png".to_string(),
                "jpg".to_string(),
                "jpeg".to_string(),
                "gif".to_string(),
                "ico".to_string(),
                "svg".to_string(),
                "woff".to_string(),
                "woff2".to_string(),
                "ttf".to_string(),
                "eot".to_string(),
            ],
            known_bot_user_agents: vec![
                "Googlebot".to_string(),
                "Bingbot".to_string(),
                "YandexBot".to_string(),
                "Slurp".to_string(),
                "DuckDuckBot".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceTrackerConfig {
    pub enabled: bool,
    pub discovery_paths: Vec<String>,
    pub poll_interval_seconds: u64,
    pub services: Vec<ServiceOverrideConfig>,
}

impl Default for ServiceTrackerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            discovery_paths: vec![
                "/etc/systemd/system".to_string(),
                "/usr/lib/systemd/system".to_string(),
            ],
            poll_interval_seconds: 30,
            services: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceOverrideConfig {
    pub name: String,
    pub log_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct JournalctlConfig {
    pub enabled: bool,
    pub services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HubConfig {
    pub enabled: bool,
    pub grpc_host: String,
    pub grpc_port: u16,
    pub rest_host: String,
    pub rest_port: u16,
    pub spa_path: PathBuf,
    pub tls: TlsConfig,
    /// Non-empty restricts `event_type` values to this allowlist.
    pub allowed_event_types: Vec<String>,
    /// Retention window for `app_events` / `log_entries` (days; 0 disables).
    pub retention_days: u32,
    /// Retention window for `system_metrics` (days; 0 disables).
    pub metrics_retention_days: u32,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            grpc_host: "127.0.0.1".into(),
            grpc_port: 50051,
            rest_host: "127.0.0.1".into(),
            rest_port: 8080,
            spa_path: PathBuf::from("./web/dist"),
            tls: TlsConfig::default(),
            allowed_event_types: vec![],
            retention_days: 90,
            metrics_retention_days: 30,
        }
    }
}

impl HubConfig {
    fn parse_host(host: &str) -> Option<IpAddr> {
        if host == "localhost" {
            return Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        host.parse::<IpAddr>().ok()
    }

    fn is_tailscale(ip: IpAddr) -> bool {
        // CGNAT 100.64.0.0/10 — the range Tailscale assigns. (`Ipv4Addr::
        // is_shared` covers this but is still nightly-gated.)
        matches!(ip, IpAddr::V4(v4) if {
            let [o1, o2, ..] = v4.octets();
            o1 == 100 && (64..=127).contains(&o2)
        })
    }

    /// Startup guard for plaintext exposure:
    /// - loopback bind: fine.
    /// - Tailscale (CGNAT `100.64/10`) bind without TLS: allowed (`WireGuard`
    ///   encrypts), but a loud warning is logged so the choice is visible.
    /// - any other non-loopback bind without TLS: refused — an accidental
    ///   public plaintext exposure is exactly what this guard exists for.
    ///
    /// # Errors
    /// `ConfigError` when a public bind would run without TLS.
    pub fn validate_bind_security(&self) -> Result<(), SentinelError> {
        if self.tls.enabled {
            return Ok(());
        }
        let mut warned = false;
        for (name, host) in [
            ("grpc_host", &self.grpc_host),
            ("rest_host", &self.rest_host),
        ] {
            let Some(ip) = Self::parse_host(host) else {
                // Unparseable host (e.g. a DNS name): allow only if it is
                // obviously loopback-ish; otherwise refuse without TLS.
                if host != "localhost" {
                    return Err(SentinelError::ConfigError(format!(
                        "hub {name} '{host}' is not an IP or 'localhost'; refusing to bind \
                         without TLS (set hub.tls.enabled or use 127.0.0.1)"
                    )));
                }
                continue;
            };
            if ip.is_loopback() {
                continue;
            }
            if Self::is_tailscale(ip) {
                tracing::warn!(
                    host = %host,
                    "hub {name} is a Tailscale address without TLS; transport is encrypted \
                     by WireGuard, but consider enabling hub.tls.enabled for defense in depth"
                );
                warned = true;
            } else {
                return Err(SentinelError::ConfigError(format!(
                    "hub {name} '{host}' is a public address but hub.tls.enabled is false; \
                     keys and payloads would travel in plaintext"
                )));
            }
        }
        if warned {
            tracing::warn!(
                "hub running without TLS on a Tailscale interface — acceptable per config, \
                 review if this is unintended"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub enabled: bool,
    pub hub_addr: String,
    /// Raw API key (`snt_...`), or a path loaded via `SENTINEL_API_KEY_FILE`.
    pub api_key: String,
    /// Docker container names to tail.
    pub containers: Vec<String>,
    /// Forward daemon-parity host logs (tail `log_watching` sources,
    /// parse/classify locally, ship structured entries to the hub).
    pub logs_enabled: bool,
    pub metrics_interval_secs: u64,
    pub log_batch_size: usize,
    pub log_flush_interval_secs: u64,
    /// Bounded in-memory log buffer; oldest lines drop on overflow.
    pub log_buffer_max: usize,
    pub connect_timeout_secs: u64,
    /// Final flush deadline on shutdown.
    pub flush_timeout_secs: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hub_addr: "127.0.0.1:50051".into(),
            api_key: String::new(),
            containers: vec!["app".into()],
            logs_enabled: false,
            metrics_interval_secs: 30,
            log_batch_size: 100,
            log_flush_interval_secs: 5,
            log_buffer_max: 10_000,
            connect_timeout_secs: 10,
            flush_timeout_secs: 5,
        }
    }
}

impl Config {
    /// The built-in defaults used when no config file is present.
    ///
    /// Delegates to each section's own `Default` impl so the defaults live
    /// in exactly one place per section.
    #[must_use]
    pub fn default_config() -> Self {
        Self::default()
    }

    pub fn load(path: &str) -> Result<Self, SentinelError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            SentinelError::ConfigError(format!("failed to read config file '{path}': {e}"))
        })?;

        serde_yaml::from_str(&content).map_err(|e| {
            SentinelError::ConfigError(format!("failed to parse config file '{path}': {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default_config();
        assert!(!config.log_watching.directories.is_empty());
        assert!(config.service_tracker.enabled);
        assert!(!config.journalctl.enabled);
    }

    /// `default_config` must agree with the per-section `Default` impls —
    /// the sections are the single source of truth for the defaults.
    #[test]
    fn test_default_config_matches_section_defaults() {
        let config = Config::default_config();
        assert_eq!(config, Config::default());
        assert_eq!(config.log_watching, LogWatchingConfig::default());
        assert_eq!(config.noise_filter, NoiseFilterConfig::default());
        assert_eq!(config.service_tracker, ServiceTrackerConfig::default());
        assert_eq!(config.journalctl, JournalctlConfig::default());
    }

    #[test]
    fn test_load_valid_config() {
        let yaml = r#"
log_watching:
  directories:
    - path: /var/log/nginx
      pattern: "*.log"
  files:
    - /var/log/auth.log
noise_filter:
  excluded_ips:
    - 127.0.0.1
    - 10.0.0.1
  health_check_paths:
    - /health
service_tracker:
  enabled: true
  poll_interval_seconds: 60
journalctl:
  enabled: true
  services:
    - my-python-app.service
    - my-bun-app.service
"#;

        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, yaml.as_bytes()).unwrap();

        let config = Config::load(file.path().to_str().unwrap()).unwrap();
        assert!(config.journalctl.enabled);
        assert_eq!(config.journalctl.services.len(), 2);
        assert!(
            config
                .noise_filter
                .excluded_ips
                .contains(&IpAddr::from([10, 0, 0, 1]))
        );
    }

    #[test]
    fn test_load_missing_file() {
        let result = Config::load("/nonexistent/config.yaml");
        assert!(result.is_err());
        match result {
            Err(SentinelError::ConfigError(msg)) => {
                assert!(msg.contains("failed to read config file"));
            }
            _ => panic!("Expected ConfigError"),
        }
    }

    #[test]
    fn test_load_invalid_yaml() {
        // Genuinely malformed YAML (an unclosed flow sequence).
        let yaml = "log_watching: [unclosed";

        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, yaml.as_bytes()).unwrap();

        let result = Config::load(file.path().to_str().unwrap());
        assert!(result.is_err());
        match result {
            Err(SentinelError::ConfigError(msg)) => {
                assert!(msg.contains("failed to parse config file"));
            }
            _ => panic!("Expected ConfigError"),
        }
    }

    /// Unknown keys are ignored and omitted sections keep their defaults,
    /// so a config file only needs to spell out what it overrides.
    #[test]
    fn test_load_partial_config_fills_defaults() {
        let yaml = "journalctl:\n  enabled: true\n  services: []\n";

        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, yaml.as_bytes()).unwrap();

        let config = Config::load(file.path().to_str().unwrap()).unwrap();
        assert!(config.journalctl.enabled);
        assert_eq!(config.log_watching, LogWatchingConfig::default());
        assert_eq!(config.noise_filter, NoiseFilterConfig::default());
    }

    /// Agent section: `logs_enabled` opt-in for daemon-parity host logs.
    #[test]
    fn test_agent_logs_enabled_parses() {
        let yaml = "agent:\n  enabled: true\n  logs_enabled: true\n";
        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, yaml.as_bytes()).unwrap();

        let config = Config::load(file.path().to_str().unwrap()).unwrap();
        assert!(config.agent.enabled);
        assert!(config.agent.logs_enabled);
        // Omitted => off (existing deployments unaffected).
        let yaml_off = "agent:\n  enabled: true\n";
        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, yaml_off.as_bytes()).unwrap();
        assert!(
            !Config::load(file.path().to_str().unwrap())
                .unwrap()
                .agent
                .logs_enabled
        );
    }

    #[test]
    fn test_service_override_config() {
        let yaml = r"
log_watching:
  directories: []
  files: []
noise_filter:
  excluded_ips: []
  health_check_paths: []
service_tracker:
  enabled: true
  poll_interval_seconds: 30
  services:
    - name: my-python-app
      log_paths:
        - /var/log/my-python-app.log
journalctl:
  enabled: false
  services: []
";

        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, yaml.as_bytes()).unwrap();

        let config = Config::load(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.service_tracker.services.len(), 1);
        assert_eq!(config.service_tracker.services[0].name, "my-python-app");
    }

    // ---- Hub bind-security guard ----

    #[test]
    fn test_hub_guard_loopback_ok() {
        HubConfig::default().validate_bind_security().unwrap();
    }

    #[test]
    fn test_hub_guard_localhost_string_ok() {
        let config = HubConfig {
            grpc_host: "localhost".into(),
            rest_host: "localhost".into(),
            ..HubConfig::default()
        };
        config.validate_bind_security().unwrap();
    }

    #[test]
    fn test_hub_guard_tls_anywhere_ok() {
        let config = HubConfig {
            grpc_host: "0.0.0.0".into(),
            rest_host: "0.0.0.0".into(),
            tls: TlsConfig {
                enabled: true,
                ..TlsConfig::default()
            },
            ..HubConfig::default()
        };
        config.validate_bind_security().unwrap();
    }

    #[test]
    fn test_hub_guard_public_bind_refused() {
        let config = HubConfig {
            rest_host: "203.0.113.10".into(), // TEST-NET public address
            ..HubConfig::default()
        };
        let err = config.validate_bind_security().unwrap_err();
        assert!(err.to_string().contains("plaintext"), "{err}");
    }

    #[test]
    fn test_hub_guard_wildcard_refused() {
        let config = HubConfig {
            grpc_host: "0.0.0.0".into(),
            ..HubConfig::default()
        };
        let err = config.validate_bind_security().unwrap_err();
        assert!(err.to_string().contains("public address"), "{err}");
    }

    #[test]
    fn test_hub_guard_dns_name_refused_without_tls() {
        let config = HubConfig {
            grpc_host: "hub.example.com".into(),
            ..HubConfig::default()
        };
        let err = config.validate_bind_security().unwrap_err();
        assert!(err.to_string().contains("not an IP"), "{err}");
    }

    #[test]
    fn test_hub_guard_tailscale_allowed() {
        let config = HubConfig {
            grpc_host: "100.64.0.5".into(),
            rest_host: "100.64.0.5".into(),
            // Allowed (WireGuard encrypts), only warns.
            ..HubConfig::default()
        };
        config.validate_bind_security().unwrap();
    }

    #[test]
    fn test_hub_guard_partial_config() {
        let yaml = "hub:\n  enabled: true\n";
        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, yaml.as_bytes()).unwrap();

        let config = Config::load(file.path().to_str().unwrap()).unwrap();
        assert!(config.hub.enabled);
        assert_eq!(config.hub.grpc_port, 50051);
        assert_eq!(config.hub.rest_port, 8080);
        assert_eq!(config.hub.retention_days, 90);
        assert_eq!(config.hub.metrics_retention_days, 30);
        assert!(!config.hub.tls.enabled);
    }
}
