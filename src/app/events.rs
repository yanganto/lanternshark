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
    match key.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Char('Q') => app.quit(),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => app.quit(),
        
        // Navigate packet list
        KeyCode::Up | KeyCode::Char('k') => app.select_previous(),
        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
        KeyCode::PageUp => {
            for _ in 0..10 {
                app.select_previous();
            }
        }
        KeyCode::PageDown => {
            for _ in 0..10 {
                app.select_next();
            }
        }
        KeyCode::Home => {
            app.selected = 0;
            app.table_state.select(Some(0));
            app.details_scroll = 0;
            app.hex_scroll = 0;
        }
        KeyCode::End => {
            if !app.packets.is_empty() {
                app.selected = app.packets.len() - 1;
                app.table_state.select(Some(app.selected));
                app.details_scroll = 0;
                app.hex_scroll = 0;
            }
        }
        
        // Scroll details view
        KeyCode::Char('w') => app.scroll_details_up(),
        KeyCode::Char('s') => app.scroll_details_down(),
        
        // Scroll hex dump
        KeyCode::Char('e') => app.scroll_hex_up(),
        KeyCode::Char('d') => app.scroll_hex_down(),
        
        _ => {}
    }
}
