//! User configuration (YAML file, optional) and its defaults.
//!
//! Each section owns its own `Default` impl; `Config::default()` — and
//! therefore a missing config file — is exactly the sum of those
//! per-section defaults.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
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
}
