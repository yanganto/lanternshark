//! Event handling for user input.

use super::state::App;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;

/// Handle terminal events (keyboard input).
///
/// # Errors
///
/// Returns an error if reading from the terminal fails.
pub fn handle_events(app: &mut App) -> Result<(), std::io::Error> {
    // Poll for events with a timeout
    if event::poll(Duration::from_millis(100))? {
        if let Event::Key(key) = event::read()? {
            handle_key_event(app, key);
        }
    }
    Ok(())
}

/// Handle keyboard key events.
fn handle_key_event(app: &mut App, key: KeyEvent) {
    // If in filter mode, handle filter input
    if app.filter_mode {
        handle_filter_input(app, key);
        return;
    }

    // Do not handle KeyEventKind::Release
    if matches!(key.kind, event::KeyEventKind::Release) {
        return;
    }

    match key.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Char('Q') => app.quit(),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => app.quit(),

        // Filter mode
        KeyCode::Enter => app.enter_filter_mode(),
        KeyCode::Esc => app.clear_filter(), // Clear filter when Esc pressed outside filter mode

        // Navigate packet list
        KeyCode::Up | KeyCode::Char('k') => app.select_previous(),
        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
        KeyCode::PageUp => app.page_up(),
        KeyCode::PageDown => app.page_down(),
        KeyCode::Home => app.set_selected(0),
        KeyCode::End => app.set_selected(app.filtered_count().saturating_sub(1)),

        // Scroll details view
        KeyCode::Char('w') => app.scroll_details_up(),
        KeyCode::Char('s') => app.scroll_details_down(),

        // Scroll hex dump
        KeyCode::Char('e') => app.scroll_hex_up(),
        KeyCode::Char('d') => app.scroll_hex_down(),

        _ => {}
    }
}

/// Handle keyboard input when in filter mode.
fn handle_filter_input(app: &mut App, key: KeyEvent) {
    match key.code {
        // Exit filter mode without applying
        KeyCode::Esc => app.exit_filter_mode(),

        // Apply filter
        KeyCode::Enter => app.apply_filter_input(),

        // Delete last character
        KeyCode::Backspace => {
            app.filter_input.pop();
        }

        // Add character to input
        KeyCode::Char(c) => {
            app.filter_input.push(c);
        }

        _ => {}
    }
}
