//! Event handling for user input.

use super::state::App;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;
use tui_input::backend::crossterm::EventHandler;

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
                match key.code {
                    KeyCode::Enter => app.apply_filter_from_input(), // Apply filter
                    KeyCode::Esc => {
                        if app.filter_input.value().is_empty() {
                            // Already empty, just exit filter mode
                            app.exit_filter_mode();
                        } else {
                            // Clear filter and input
                            app.clear_filter_and_input();
                        }
                    },
                    _ => {
                        app.filter_input.handle_event(&evt);
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
    match key.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Char('Q') => app.quit(),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => app.quit(),

        // Filter mode
        KeyCode::Enter => app.enter_filter_mode(),
        KeyCode::Esc => app.exit_filter_mode(), // Exits filter editing mode when Esc pressed outside filter mode, but saves current input

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
    true
}
