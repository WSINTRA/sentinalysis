//! Two-panel log viewer: a sources list (left) and an entry list (right).
//!
//! This module owns the viewer's state and action handling. All data
//! (sources, counts, entries) comes through the [`LogDataSource`] trait,
//! so the component holds no database or filesystem logic and is
//! testable with an in-memory source; frame drawing lives in the
//! [`render`] submodule.

mod render;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use tracing::{error, info, warn};

use crate::error::SentinelError;
use crate::log_scanner::source::{Source, SourceKind};
use crate::tui::action::Action;
use crate::tui::components::{BoxedFuture, Component};
use crate::tui::data::{DisplayLogEntry, LogDataSource, SourceInfo};

/// Max entries kept in memory per source.
pub const MAX_ENTRIES_PER_HOST: usize = 1000;
/// Max entries fetched per poll for a single source.
const NEW_ENTRIES_PER_POLL: i64 = 100;
/// How often the selected source is polled for new entries.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Which panel receives navigation keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PanelFocus {
    HostList,
    LogList,
}

pub struct LogViewer<D: LogDataSource> {
    data: D,
    virtual_hosts: Vec<SourceInfo>,
    system_logs: Vec<SourceInfo>,
    host_state: ListState,
    log_entries: HashMap<String, Vec<DisplayLogEntry>>,
    log_state: ListState,
    selected_source: Option<Source>,
    filter_mode: bool,
    filter_text: String,
    focus: PanelFocus,
    poll_interval: Duration,
    last_poll: Option<Instant>,
}

impl<D: LogDataSource> LogViewer<D> {
    #[must_use]
    pub fn new(data: D) -> Self {
        let mut host_state = ListState::default();
        host_state.select(Some(0));

        let mut log_state = ListState::default();
        log_state.select(Some(0));

        Self {
            data,
            virtual_hosts: Vec::new(),
            system_logs: Vec::new(),
            host_state,
            log_entries: HashMap::new(),
            log_state,
            selected_source: None,
            filter_mode: false,
            filter_text: String::new(),
            focus: PanelFocus::HostList,
            poll_interval: DEFAULT_POLL_INTERVAL,
            last_poll: None,
        }
    }

    /// Override the poll interval (mainly for tests).
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Load the most recent entries for `source`, replacing whatever was
    /// cached for it.
    async fn load_recent_entries(&mut self, source: &Source) -> Result<(), SentinelError> {
        let limit = i64::try_from(MAX_ENTRIES_PER_HOST).unwrap_or(i64::MAX);

        let entries = self.data.recent(source, limit).await?;

        info!("Loaded {} entries for '{}'", entries.len(), source.name);
        self.log_entries.insert(source.name.clone(), entries);
        self.log_state.select(Some(0));
        Ok(())
    }

    /// Poll the database for entries newer than the newest one on screen
    /// and prepend them to the cached list for `source`.
    async fn check_new_entries(&mut self, source: &Source) -> Result<(), SentinelError> {
        // Entries are stored newest-first, so the first one is the newest
        // on screen; anything still missing must be newer than it.
        let Some((since, since_id)) = self
            .log_entries
            .get(&source.name)
            .and_then(|entries| entries.first())
            .map(|newest| (newest.timestamp, newest.id))
        else {
            return Ok(());
        };

        let new_entries = self
            .data
            .newer(source, since, since_id, NEW_ENTRIES_PER_POLL)
            .await?;

        if new_entries.is_empty() {
            return Ok(());
        }

        if let Some(host_entries) = self.log_entries.get_mut(&source.name) {
            host_entries.splice(0..0, new_entries);
            if host_entries.len() > MAX_ENTRIES_PER_HOST {
                host_entries.truncate(MAX_ENTRIES_PER_HOST);
            }
        }

        Ok(())
    }

    /// Total number of rows in the sources panel, including section headers.
    fn total_host_list_len(&self) -> usize {
        let mut len = 1 + self.virtual_hosts.len();
        if !self.system_logs.is_empty() {
            len += 1 + self.system_logs.len();
        }
        len
    }

    /// What source (if any) the sources-panel row at `index` points at.
    /// Header rows (`Virtual Hosts`, `System Logs`) map to `None`.
    fn resolve_selection(&self, index: usize) -> Option<Source> {
        // Row 0 is the "Virtual Hosts" header.
        if index == 0 {
            return None;
        }
        if let Some(vhost) = self.virtual_hosts.get(index - 1) {
            return Some(vhost.source.clone());
        }

        // Next row is the "System Logs" header, then the system logs.
        let system_header = 1 + self.virtual_hosts.len();
        if !self.system_logs.is_empty()
            && index > system_header
            && let Some(system_log) = self.system_logs.get(index - system_header - 1)
        {
            return Some(system_log.source.clone());
        }

        None
    }

    /// Highest valid index of the selected source's entry list (0 when empty).
    fn log_list_max(&self) -> usize {
        self.selected_source
            .as_ref()
            .and_then(|s| {
                self.log_entries
                    .get(&s.name)
                    .map(|v| v.len().saturating_sub(1))
            })
            .unwrap_or(0)
    }

    /// Route actions while the filter box is active: keys edit the filter
    /// text, Esc clears it, and everything else is swallowed.
    fn handle_filter_action(&mut self, action: &Action) {
        match action {
            Action::FilterInput(c) => self.filter_text.push(*c),
            Action::FilterBackspace => {
                self.filter_text.pop();
            }
            Action::ClearFilter => {
                self.filter_mode = false;
                self.filter_text.clear();
            }
            // Toggling or refreshing exits filter mode without a text change.
            Action::ToggleFilter | Action::Refresh => self.filter_mode = false,
            _ => {}
        }
    }

    /// Move the selection of the focused panel by `delta` positions,
    /// clamped to the panel bounds.
    fn move_selection(&mut self, delta: isize) {
        match self.focus {
            PanelFocus::HostList => {
                if let Some(i) = self.host_state.selected() {
                    let max = self.total_host_list_len().saturating_sub(1);
                    self.host_state
                        .select(Some(i.saturating_add_signed(delta).min(max)));
                }
            }
            PanelFocus::LogList => {
                if let Some(i) = self.log_state.selected() {
                    self.log_state.select(Some(
                        i.saturating_add_signed(delta).min(self.log_list_max()),
                    ));
                }
            }
        }
    }
}

impl<D: LogDataSource> Component for LogViewer<D> {
    fn init(&mut self) -> BoxedFuture<'_, Result<(), SentinelError>> {
        Box::pin(async move {
            let discovered = self.data.sources().await?;
            // Sources arrive vhosts-first; split the panel lists on kind.
            let (vhosts, system_logs): (Vec<SourceInfo>, Vec<SourceInfo>) = discovered
                .into_iter()
                .partition(|s| s.source.kind == SourceKind::Vhost);
            self.virtual_hosts = vhosts;
            self.system_logs = system_logs;

            if let Some(first) = self.virtual_hosts.first().map(|s| s.source.clone()) {
                self.selected_source = Some(first.clone());
                self.load_recent_entries(&first).await?;
            }

            Ok(())
        })
    }

    fn handle_action<'a>(
        &'a mut self,
        action: &'a Action,
    ) -> BoxedFuture<'a, Result<(), SentinelError>> {
        Box::pin(async move {
            if self.filter_mode {
                self.handle_filter_action(action);
                return Ok(());
            }

            match action {
                Action::ToggleFocus => {
                    self.focus = match self.focus {
                        PanelFocus::HostList => PanelFocus::LogList,
                        PanelFocus::LogList => PanelFocus::HostList,
                    };
                }
                Action::SelectUp => self.move_selection(-1),
                Action::SelectDown => self.move_selection(1),
                Action::Refresh => {
                    if let Some(i) = self.host_state.selected()
                        && let Some(source) = self.resolve_selection(i)
                        && self.selected_source.as_ref() != Some(&source)
                    {
                        self.selected_source = Some(source.clone());
                        self.log_state.select(Some(0));
                        if let Err(e) = self.load_recent_entries(&source).await {
                            error!("failed to load entries for '{}': {e}", source.name);
                        }
                    }
                }
                Action::ToggleFilter => self.filter_mode = true,
                Action::ClearFilter => self.filter_text.clear(),
                Action::PageUp => {
                    if let Some(i) = self.log_state.selected() {
                        self.log_state.select(Some(i.saturating_sub(20)));
                    }
                }
                Action::PageDown => {
                    if let Some(i) = self.log_state.selected() {
                        self.log_state
                            .select(Some((i + 20).min(self.log_list_max())));
                    }
                }
                Action::ScrollToTop => self.log_state.select(Some(0)),
                // `log_list_max` reports 0 for an empty list, matching the
                // previous behaviour of selecting index 0 in that case.
                Action::ScrollToBottom
                    if self
                        .selected_source
                        .as_ref()
                        .is_some_and(|s| self.log_entries.contains_key(&s.name)) =>
                {
                    self.log_state.select(Some(self.log_list_max()));
                }
                Action::Tick => {
                    // Poll at most every `poll_interval`; the 100 ms ticks
                    // are for redraws, not database traffic.
                    let due = self.last_poll.is_none_or(|last| {
                        Instant::now().duration_since(last) >= self.poll_interval
                    });
                    if due && let Some(selected) = self.selected_source.clone() {
                        self.last_poll = Some(Instant::now());
                        if let Err(e) = self.check_new_entries(&selected).await {
                            warn!("failed to poll for new entries: {e}");
                        }
                    }
                }
                _ => {}
            }

            Ok(())
        })
    }

    fn draw(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        self.render(frame, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SentinelError;
    use crate::log_scanner::source::SourceKind;
    use crate::tui::data::BoxFuture;
    use crate::tui::data::memory::MemoryLogDataSource;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    fn viewer(data: MemoryLogDataSource) -> LogViewer<MemoryLogDataSource> {
        LogViewer::new(data)
    }

    fn vhost_info(name: &str) -> SourceInfo {
        SourceInfo::new(SourceKind::Vhost, name, 0)
    }

    fn system_log_info(name: &str) -> SourceInfo {
        SourceInfo::new(SourceKind::SystemLog, name, 0)
    }

    fn display_entry(seq: u64, timestamp: DateTime<Utc>) -> DisplayLogEntry {
        DisplayLogEntry {
            id: Uuid::new_v4(),
            timestamp,
            level: crate::log_scanner::parser::LogLevel::Info,
            threat_level: crate::log_scanner::classifier::ThreatLevel::None,
            message: format!("entry {seq}"),
            raw: String::new(),
            source_name: "test".to_string(),
            threat_categories: Vec::new(),
        }
    }

    /// Data source that counts `newer` calls, to observe poll frequency.
    /// The counter is shared with the test through an `Arc`.
    #[derive(Clone, Default)]
    struct CountingSource {
        newer_calls: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }

    impl CountingSource {
        fn call_count(&self) -> u32 {
            use std::sync::atomic::Ordering;
            self.newer_calls.load(Ordering::SeqCst)
        }
    }

    impl LogDataSource for CountingSource {
        fn sources(&self) -> BoxFuture<'_, Result<Vec<SourceInfo>, SentinelError>> {
            Box::pin(async { Ok(vec![]) })
        }

        fn recent(
            &self,
            _source: &Source,
            _limit: i64,
        ) -> BoxFuture<'_, Result<Vec<DisplayLogEntry>, SentinelError>> {
            Box::pin(async { Ok(vec![]) })
        }

        fn newer(
            &self,
            _source: &Source,
            _since: DateTime<Utc>,
            _since_id: Uuid,
            _limit: i64,
        ) -> BoxFuture<'_, Result<Vec<DisplayLogEntry>, SentinelError>> {
            use std::sync::atomic::Ordering;
            self.newer_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(vec![]) })
        }
    }

    #[tokio::test]
    async fn test_resolve_selection_skips_headers() {
        let mut v = viewer(MemoryLogDataSource::new());
        v.virtual_hosts = vec![
            vhost_info("api.example.com"),
            vhost_info("shop.example.com"),
        ];
        v.system_logs = vec![system_log_info("auth.log")];

        // 0 = "Virtual Hosts" header.
        assert_eq!(v.resolve_selection(0), None);
        assert_eq!(
            v.resolve_selection(1),
            Some(Source::vhost("api.example.com"))
        );
        assert_eq!(
            v.resolve_selection(2),
            Some(Source::vhost("shop.example.com"))
        );
        // 3 = "System Logs" header.
        assert_eq!(v.resolve_selection(3), None);
        assert_eq!(v.resolve_selection(4), Some(Source::system_log("auth.log")));
        assert_eq!(v.resolve_selection(5), None);
    }

    #[tokio::test]
    async fn test_resolve_selection_without_system_logs() {
        let mut v = viewer(MemoryLogDataSource::new());
        v.virtual_hosts = vec![vhost_info("only.example.com")];

        assert_eq!(
            v.resolve_selection(1),
            Some(Source::vhost("only.example.com"))
        );
        // No system-log section at all.
        assert_eq!(v.resolve_selection(2), None);
    }

    #[tokio::test]
    async fn test_move_selection_clamps_to_bounds() {
        let mut v = viewer(MemoryLogDataSource::new());
        v.virtual_hosts = vec![vhost_info("a"), vhost_info("b")];

        v.focus = PanelFocus::HostList;
        v.host_state.select(Some(0));
        v.move_selection(-1);
        assert_eq!(v.host_state.selected(), Some(0), "cannot go below 0");

        v.move_selection(100);
        assert_eq!(
            v.host_state.selected(),
            Some(v.total_host_list_len() - 1),
            "cannot go past the last row"
        );
    }

    #[tokio::test]
    async fn test_filter_action_edits_and_exits() {
        let mut v = viewer(MemoryLogDataSource::new());
        v.filter_mode = true;

        for c in ['a', 'b', 'c'] {
            v.handle_filter_action(&Action::FilterInput(c));
        }
        assert_eq!(v.filter_text, "abc");

        v.handle_filter_action(&Action::FilterBackspace);
        assert_eq!(v.filter_text, "ab");

        v.handle_filter_action(&Action::ClearFilter);
        assert!(!v.filter_mode, "Esc exits filter mode");
        assert!(v.filter_text.is_empty());
    }

    #[tokio::test]
    async fn test_filter_action_swallows_navigation() {
        let mut v = viewer(MemoryLogDataSource::new());
        v.filter_mode = true;
        v.focus = PanelFocus::HostList;
        v.host_state.select(Some(0));

        // Navigation keys are swallowed while typing a filter.
        v.handle_filter_action(&Action::SelectDown);
        assert_eq!(v.host_state.selected(), Some(0));
    }

    #[tokio::test]
    async fn test_log_list_max_empty_and_full() {
        let mut v = viewer(MemoryLogDataSource::new());
        v.selected_source = Some(Source::vhost("h"));
        assert_eq!(v.log_list_max(), 0, "no entries yet");

        v.log_entries.insert(
            "h".to_string(),
            vec![display_entry(0, Utc::now()), display_entry(1, Utc::now())],
        );
        assert_eq!(v.log_list_max(), 1);
    }

    #[tokio::test]
    async fn test_init_selects_first_source_and_loads_entries() {
        let ds = MemoryLogDataSource::new()
            .with_sources(vec![vhost_info("a.example.com")], vec![])
            .with_entries("a.example.com", vec![display_entry(1, Utc::now())]);

        let mut v = viewer(ds);
        v.init().await.unwrap();

        assert_eq!(v.selected_source, Some(Source::vhost("a.example.com")));
        assert_eq!(v.log_entries.get("a.example.com").map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn test_init_without_vhosts_selects_nothing() {
        let ds = MemoryLogDataSource::new().with_sources(vec![], vec![system_log_info("auth.log")]);

        let mut v = viewer(ds);
        v.init().await.unwrap();

        assert_eq!(v.selected_source, None);
        assert!(v.log_entries.is_empty());
    }

    /// A source with cached entries is required for a poll to happen.
    fn viewer_with_cached_entries(data: CountingSource) -> LogViewer<CountingSource> {
        let mut v = LogViewer::new(data);
        v.selected_source = Some(Source::vhost("h"));
        v.log_entries
            .insert("h".to_string(), vec![display_entry(1, Utc::now())]);
        v
    }

    /// Newest-first entries `entry 1`..`entry count` with distinct
    /// increasing timestamps (`entry count` is the newest).
    fn seq_entries(t0: DateTime<Utc>, count: u64) -> Vec<DisplayLogEntry> {
        (1..=count)
            .map(|seq| {
                display_entry(
                    seq,
                    t0 + chrono::TimeDelta::try_seconds(i64::try_from(seq).unwrap()).unwrap(),
                )
            })
            .rev()
            .collect()
    }

    #[tokio::test]
    async fn test_check_new_entries_prepends_only_genuinely_new() {
        // The store holds four entries; the viewer cached the newest two,
        // exactly as `recent(2)` would return.
        let t0 = Utc::now();
        let store = seq_entries(t0, 4);
        let ds = MemoryLogDataSource::new()
            .with_sources(vec![vhost_info("h")], vec![])
            .with_entries("h", store.clone());
        let mut v = viewer(ds);
        v.init().await.unwrap();
        // Same entries (ids included) as in the store, as `recent(2)`
        // would return.
        v.log_entries.insert("h".to_string(), store[2..].to_vec());

        v.check_new_entries(&Source::vhost("h")).await.unwrap();

        // Only the two genuinely-new entries are prepended; nothing that
        // is already on screen is duplicated.
        assert_eq!(
            v.log_entries["h"]
                .iter()
                .map(|e| &e.message)
                .collect::<Vec<_>>(),
            ["entry 4", "entry 3", "entry 2", "entry 1"]
        );
    }

    #[tokio::test]
    async fn test_check_new_entries_truncates_to_max_entries() {
        let t0 = Utc::now();
        let store = seq_entries(t0, 1060);
        let ds = MemoryLogDataSource::new()
            .with_sources(vec![vhost_info("h")], vec![])
            .with_entries("h", store.clone());
        let mut v = viewer(ds);
        v.init().await.unwrap();
        // The cache holds `entry 1000`..`entry 2` (999 entries), leaving
        // room for 60 new ones to overflow the cap.
        let mut cached = store;
        cached.drain(0..60);
        cached.pop();
        v.log_entries.insert("h".to_string(), cached);

        v.check_new_entries(&Source::vhost("h")).await.unwrap();

        let entries = &v.log_entries["h"];
        assert_eq!(entries.len(), MAX_ENTRIES_PER_HOST);
        assert_eq!(entries[0].message, "entry 1060");
        assert_eq!(entries[entries.len() - 1].message, "entry 61");
    }

    #[tokio::test]
    async fn test_check_new_entries_is_noop_when_nothing_newer() {
        let t0 = Utc::now();
        let ds = MemoryLogDataSource::new()
            .with_sources(vec![vhost_info("h")], vec![])
            .with_entries("h", seq_entries(t0, 3));
        let mut v = viewer(ds);
        v.init().await.unwrap();

        let before: Vec<String> = v.log_entries["h"]
            .iter()
            .map(|e| e.message.clone())
            .collect();
        v.check_new_entries(&Source::vhost("h")).await.unwrap();

        let after: Vec<String> = v.log_entries["h"]
            .iter()
            .map(|e| e.message.clone())
            .collect();
        assert_eq!(after, before);
    }

    #[tokio::test]
    async fn test_refresh_switches_to_highlighted_source() {
        let ds = MemoryLogDataSource::new()
            .with_sources(
                vec![vhost_info("a.example.com"), vhost_info("b.example.com")],
                vec![],
            )
            .with_entries("a.example.com", vec![display_entry(1, Utc::now())])
            .with_entries(
                "b.example.com",
                vec![display_entry(2, Utc::now()), display_entry(3, Utc::now())],
            );
        let mut v = viewer(ds);
        v.init().await.unwrap();
        assert_eq!(v.selected_source, Some(Source::vhost("a.example.com")));

        // Highlight the second vhost (row 2) and refresh.
        v.host_state.select(Some(2));
        v.handle_action(&Action::Refresh).await.unwrap();

        assert_eq!(v.selected_source, Some(Source::vhost("b.example.com")));
        assert_eq!(
            v.log_entries.get("b.example.com").map(Vec::len),
            Some(2),
            "refreshing loads the highlighted source's entries"
        );
    }

    #[tokio::test]
    async fn test_tick_polls_at_most_every_interval() {
        let data = CountingSource::default();
        let mut v =
            viewer_with_cached_entries(data.clone()).with_poll_interval(Duration::from_hours(1));

        // Two back-to-back ticks: only the first is due.
        let tick = Action::Tick;
        v.handle_action(&tick).await.unwrap();
        v.handle_action(&tick).await.unwrap();

        assert_eq!(data.call_count(), 1, "second tick must not re-poll");
    }

    #[tokio::test]
    async fn test_tick_polls_every_tick_with_zero_interval() {
        let data = CountingSource::default();
        let mut v =
            viewer_with_cached_entries(data.clone()).with_poll_interval(Duration::from_secs(0));

        let tick = Action::Tick;
        v.handle_action(&tick).await.unwrap();
        v.handle_action(&tick).await.unwrap();

        assert_eq!(data.call_count(), 2, "zero interval polls every tick");
    }

    #[tokio::test]
    async fn test_tick_without_selected_source_does_not_poll() {
        let mut v = viewer(MemoryLogDataSource::new()).with_poll_interval(Duration::from_secs(0));

        let tick = Action::Tick;
        v.handle_action(&tick).await.unwrap();
        assert!(v.last_poll.is_none(), "no source, no poll");
    }
}
