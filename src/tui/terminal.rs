use std::time::Duration;

use crossterm::event::{Event as CrosstermEvent, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::error::SentinelError;
use crate::tui::action::Action;
use crate::tui::app::App;

#[derive(Debug, Clone)]
pub enum Event {
    Tick,
    Key(crossterm::event::KeyEvent),
    FocusLost,
    FocusGained,
    Resize(u16, u16),
    Mouse(crossterm::event::MouseEvent),
}

pub struct Tui {
    terminal: Terminal<CrosstermBackend<std::io::Stdout>>,
    event_rx: mpsc::Receiver<Event>,
    cancel_token: CancellationToken,
}

impl Tui {
    pub fn new() -> Result<Self, SentinelError> {
        let terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))
            .map_err(|e| SentinelError::Internal(format!("failed to initialize terminal: {e}")))?;

        let (event_tx, event_rx) = mpsc::channel(100);
        let cancel_token = CancellationToken::new();

        Self::setup_terminal()?;
        Self::start_event_listener(event_tx, cancel_token.clone());

        Ok(Self {
            terminal,
            event_rx,
            cancel_token,
        })
    }

    fn setup_terminal() -> Result<(), SentinelError> {
        crossterm::terminal::enable_raw_mode()
            .map_err(|e| SentinelError::Internal(format!("failed to enable raw mode: {e}")))?;
        crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::EnterAlternateScreen,
            crossterm::event::EnableMouseCapture,
        )
        .map_err(|e| SentinelError::Internal(format!("failed to setup terminal: {e}")))?;
        Ok(())
    }

    fn start_event_listener(event_tx: mpsc::Sender<Event>, cancel_token: CancellationToken) {
        tokio::spawn(async move {
            let mut event_stream = EventStream::new();
            let mut tick_interval = tokio::time::interval(Duration::from_millis(100));

            loop {
                tokio::select! {
                    () = cancel_token.cancelled() => break,
                    _ = tick_interval.tick() => {
                        if event_tx.send(Event::Tick).await.is_err() {
                            break;
                        }
                    }
                    result = event_stream.next() => {
                        match result {
                            Some(Ok(crossterm_event)) => {
                                let app_event = Self::map_event(&crossterm_event);
                                if event_tx.send(app_event).await.is_err() {
                                    break;
                                }
                            }
                            Some(Err(_)) | None => break,
                        }
                    }
                }
            }
        });
    }

    fn map_event(event: &CrosstermEvent) -> Event {
        match event {
            CrosstermEvent::Key(key) if key.kind == KeyEventKind::Press => Event::Key(*key),
            CrosstermEvent::Key(_) | CrosstermEvent::Paste(_) => Event::Tick,
            CrosstermEvent::FocusLost => Event::FocusLost,
            CrosstermEvent::FocusGained => Event::FocusGained,
            CrosstermEvent::Resize(w, h) => Event::Resize(*w, *h),
            CrosstermEvent::Mouse(mouse) => Event::Mouse(*mouse),
        }
    }

    pub async fn run(&mut self, mut app: App) -> Result<(), SentinelError> {
        info!("TUI event loop starting");

        app.init().await?;

        loop {
            if let Err(e) = self.terminal.draw(|frame| app.draw(frame, frame.area())) {
                error!("Failed to draw frame: {e}");
                break;
            }

            let Some(event) = self.event_rx.recv().await else {
                break;
            };

            let Some(action) = Self::event_to_action(&event) else {
                continue;
            };

            if let Some(next_action) = app.handle_action(&action)?
                && next_action == Action::Quit
            {
                break;
            }
        }

        Self::reset_terminal();
        info!("TUI event loop ended");
        Ok(())
    }

    fn event_to_action(event: &Event) -> Option<Action> {
        match event {
            Event::Key(key) => Some(Self::key_to_action(key)),
            Event::Tick => Some(Action::Tick),
            _ => None,
        }
    }

    fn key_to_action(key: &crossterm::event::KeyEvent) -> Action {
        match key.code {
            crossterm::event::KeyCode::Char('q') => Action::Quit,
            crossterm::event::KeyCode::Char('/') => Action::ToggleFilter,
            crossterm::event::KeyCode::Up => Action::SelectUp,
            crossterm::event::KeyCode::Down => Action::SelectDown,
            crossterm::event::KeyCode::Tab => Action::ToggleFocus,
            crossterm::event::KeyCode::Enter | crossterm::event::KeyCode::Char('r') => {
                Action::Refresh
            }
            crossterm::event::KeyCode::Esc => Action::ClearFilter,
            crossterm::event::KeyCode::Backspace => Action::FilterBackspace,
            crossterm::event::KeyCode::PageUp => Action::PageUp,
            crossterm::event::KeyCode::PageDown => Action::PageDown,
            crossterm::event::KeyCode::Home => Action::ScrollToTop,
            crossterm::event::KeyCode::End => Action::ScrollToBottom,
            crossterm::event::KeyCode::Char(c) => Action::FilterInput(c),
            _ => Action::Tick,
        }
    }

    fn reset_terminal() {
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture,
        );
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        Self::reset_terminal();
    }
}
