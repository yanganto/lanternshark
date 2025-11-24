//! Event handling for user input.

use super::key_config::KeyEvent::{
    ApplyFilter, ClearFilter, DtlDown, DtlUp, HexDown, HexUp, PktDown, PktEnd, PktHome,
    PktPageDown, PktPageUp, PktUp, Quit,
};
use super::state::App;
use crossterm_keybind::KeyBindTrait;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;
use tui_input::InputRequest;

/// Handle terminal events (keyboard input).
///
/// # Errors
///
/// Returns an error if reading from the terminal fails.
pub fn handle_events(app: &mut App) -> Result<(), std::io::Error> {
    // Poll for events with a timeout
    if event::poll(Duration::from_millis(100))? {
        let evt = event::read()?;
        if let Event::Key(key) = evt {
            // Do not handle KeyEventKind::Release
            if matches!(key.kind, event::KeyEventKind::Release) {
                return Ok(());
            }
            if app.filter_editing {
                if ApplyFilter.match_any(&key) {
                    app.apply_filter_from_input(); // Apply filter
                } else if ClearFilter.match_any(&key) {
                    if app.filter_input.value().is_empty() {
                        // Already empty, just exit filter mode
                        app.exit_filter_mode();
                    } else {
                        // Clear filter and input
                        app.clear_filter_and_input();
                    }
                } else {
                    if let Some(req) = keyevent_to_input_request(&key) {
                        app.filter_input.handle(req);
                    }
                }
            } else {
                handle_key_event(app, key);
            }
        }
    }
    Ok(())
}

/// Handle keyboard key events.
fn handle_key_event(app: &mut App, key: KeyEvent) -> bool {
    if Quit.match_any(&key) {
        app.quit()
    } else if ApplyFilter.match_any(&key) {
        app.enter_filter_mode()
    } else if ClearFilter.match_any(&key) {
        // Exits filter editing mode when Esc pressed outside filter mode, but saves current input
        app.exit_filter_mode()
    } else if PktUp.match_any(&key) {
        app.select_previous()
    } else if PktDown.match_any(&key) {
        app.select_next()
    } else if PktPageUp.match_any(&key) {
        app.page_up()
    } else if PktPageDown.match_any(&key) {
        app.page_down()
    } else if PktHome.match_any(&key) {
        app.set_selected(0)
    } else if PktEnd.match_any(&key) {
        app.set_selected(app.filtered_count().saturating_sub(1))
    } else if DtlUp.match_any(&key) {
        app.scroll_details_up()
    } else if DtlDown.match_any(&key) {
        app.scroll_details_down()
    } else if HexUp.match_any(&key) {
        app.scroll_hex_up()
    } else if HexDown.match_any(&key) {
        app.scroll_hex_down()
    }
    true
}

/// Convert a [`KeyEvent`] to an optional [`InputRequest`] for tui_input. Adapted from [tui_input's own implementation](https://github.com/sayanarijit/tui-input/blob/main/src/backend/crossterm.rs#L16-L66).
pub fn keyevent_to_input_request(key: &KeyEvent) -> Option<InputRequest> {
    use InputRequest::*;
    use KeyCode::*;
    let KeyEvent {
        code, modifiers, ..
    } = *key;
    match (code, modifiers) {
        // Backspace without modifiers to delete previous character
        (Backspace, KeyModifiers::NONE) => Some(DeletePrevChar),
        // Delete key without modifiers to delete next character
        (Delete, KeyModifiers::NONE) => Some(DeleteNextChar),
        // Left arrow to move cursor left
        (Left, KeyModifiers::NONE) => Some(GoToPrevChar),
        // Ctrl + Left arrow to move cursor to previous word
        (Left, KeyModifiers::CONTROL) => Some(GoToPrevWord),
        // Right arrow to move cursor right
        (Right, KeyModifiers::NONE) => Some(GoToNextChar),
        // Ctrl + Right arrow to move cursor to next word
        (Right, KeyModifiers::CONTROL) => Some(GoToNextWord),
        // Ctrl + Backspace or Ctrl + H to delete previous word (Ctrl + Backspace will be recognized as Ctrl + H on some systems)
        (Backspace, KeyModifiers::CONTROL) | (Char('h'), KeyModifiers::CONTROL) => {
            Some(DeletePrevWord)
        }
        // Ctrl + Delete to delete next word
        (Delete, KeyModifiers::CONTROL) => Some(DeleteNextWord),
        // Ctrl + K to delete till end of line
        (Char('k'), KeyModifiers::CONTROL) => Some(DeleteTillEnd),
        // Home key to move cursor to start of line
        (Home, KeyModifiers::NONE) => Some(GoToStart),
        // End key to move cursor to end of line
        (End, KeyModifiers::NONE) => Some(GoToEnd),
        // Insert character for regular character input
        (Char(c), KeyModifiers::NONE | KeyModifiers::SHIFT) => Some(InsertChar(c)),
        (_, _) => None,
    }
}
