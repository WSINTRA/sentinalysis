use strum::Display;

#[derive(Debug, Clone, Display, PartialEq)]
pub enum Action {
    #[strum(to_string = "Quit")]
    Quit,

    #[strum(to_string = "Tick")]
    Tick,

    #[strum(to_string = "SelectUp")]
    SelectUp,

    #[strum(to_string = "SelectDown")]
    SelectDown,

    #[strum(to_string = "Refresh")]
    Refresh,

    #[strum(to_string = "ToggleFilter")]
    ToggleFilter,

    #[strum(to_string = "ClearFilter")]
    ClearFilter,

    #[strum(to_string = "LogEntryAdded")]
    LogEntryAdded,

    #[strum(to_string = "ScrollUp")]
    ScrollUp,

    #[strum(to_string = "ScrollDown")]
    ScrollDown,

    #[strum(to_string = "PageUp")]
    PageUp,

    #[strum(to_string = "PageDown")]
    PageDown,

    #[strum(to_string = "ScrollToTop")]
    ScrollToTop,

    #[strum(to_string = "ScrollToBottom")]
    ScrollToBottom,

    #[strum(to_string = "FilterInput")]
    FilterInput,

    #[strum(to_string = "LoadOlderEntries")]
    LoadOlderEntries,

    #[strum(to_string = "ToggleFocus")]
    ToggleFocus,
}
