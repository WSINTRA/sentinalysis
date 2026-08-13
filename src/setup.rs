use sentinel::config::Config;
use sentinel::error::SentinelError;
use std::path::Path;
use tracing::info;

// tracing
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sentinel=info".parse().unwrap()),
        )
        .with_target(false)
        .init();
}

// Config load
pub fn load_config(path: &Path) -> Result<Config, SentinelError> {
    if path.exists() {
        Config::load(path.to_str().unwrap())
    } else {
        info!(
            "Config file not found at '{}', using defaults",
            path.display()
        );
        Ok(Config::default_config())
    }
}
