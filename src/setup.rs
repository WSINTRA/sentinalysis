//! One-time process setup: tracing initialisation and config loading.

use std::path::Path;

use tracing::info;

use crate::config::Config;
use crate::error::SentinelError;

/// Initialise the tracing subscriber. Defaults to `sentinel=info` and
/// honours `RUST_LOG` for overrides.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sentinel=info".parse().unwrap()),
        )
        .with_target(false)
        .init();
}

/// Load the config file at `path`, falling back to the built-in defaults
/// when the file does not exist.
pub fn load_config(path: &Path) -> Result<Config, SentinelError> {
    if path.exists() {
        let Some(path_str) = path.to_str() else {
            return Err(SentinelError::ConfigError(format!(
                "config path '{}' is not valid UTF-8",
                path.display()
            )));
        };
        Config::load(path_str)
    } else {
        info!(
            "Config file not found at '{}', using defaults",
            path.display()
        );
        Ok(Config::default_config())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// A missing config file must fall back to the defaults, not fail.
    #[test]
    fn test_load_config_missing_file_uses_defaults() {
        let config = load_config(Path::new("/nonexistent/sentinel.yaml"))
            .expect("missing file falls back to defaults");
        assert_eq!(config, Config::default());
    }

    /// An existing file is parsed; its values override the defaults.
    #[test]
    fn test_load_config_reads_existing_file() {
        let yaml = "journalctl:\n  enabled: true\n  services:\n    - my-app.service\n";
        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, yaml.as_bytes()).unwrap();

        let config = load_config(file.path()).expect("valid file loads");
        assert!(config.journalctl.enabled);
        assert_eq!(config.journalctl.services, vec!["my-app.service"]);
    }

    /// Malformed YAML is a config error, not a panic.
    #[test]
    fn test_load_config_invalid_file_is_error() {
        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"log_watching: [unclosed").unwrap();

        let result = load_config(file.path());
        assert!(matches!(result, Err(SentinelError::ConfigError(_))));
    }
}
