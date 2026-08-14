use sqlx::PgPool;

use crate::config::Config;
use crate::error::SentinelError;
use crate::tui::action::Action;
use crate::tui::components::Composite;

#[derive(Debug, Clone)]
pub struct VirtualHostInfo {
    pub name: String,
    pub source: VirtualHostSource,
    pub entry_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VirtualHostSource {
    LogEntry,
    SystemdService,
    JournalctlConfig,
}

#[derive(Debug, Clone)]
pub struct DisplayLogEntry {
    pub id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: crate::log_scanner::parser::LogLevel,
    pub threat_level: crate::log_scanner::classifier::ThreatLevel,
    pub message: String,
    pub raw: String,
    pub virtual_host: String,
    pub threat_categories: Vec<String>,
}

pub struct App {
    composite: Composite,
    _config: Config,
}

impl App {
    #[must_use]
    pub fn new(pool: PgPool, config: Config) -> Self {
        let (entry_tx, _entry_rx) = tokio::sync::mpsc::unbounded_channel();

        let composite = Composite::new(vec![
            Box::new(crate::tui::components::log_viewer::LogViewer::new(pool, entry_tx)),
            Box::new(crate::tui::components::status_bar::StatusBar::new()),
        ]);

        Self {
            composite,
            _config: config,
        }
    }

    pub async fn init(&mut self) -> Result<(), SentinelError> {
        self.composite.init().await?;
        Ok(())
    }

    pub fn handle_action(&mut self, action: &Action) -> Result<Option<Action>, SentinelError> {
        self.composite.handle_action(action)
    }

    pub fn draw(&mut self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        self.composite.draw(frame, area);
    }
}
