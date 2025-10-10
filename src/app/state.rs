//! Application state management.

use super::packet_info::PacketInfo;
use ratatui::widgets::TableState;

/// Main application state.
#[derive(Debug)]
pub struct App {
    /// List of captured packets
    pub packets: Vec<PacketInfo>,
    /// Currently selected packet index
    pub selected: usize,
    /// Table state for the packet list
    pub table_state: TableState,
    /// Scroll offset for the packet details view
    pub details_scroll: u16,
    /// Scroll offset for the hex dump view
    pub hex_scroll: u16,
    /// Whether the application should quit
    pub should_quit: bool,
}

impl App {
    /// Create a new application state.
    #[must_use]
    pub fn new() -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self {
            packets: Vec::new(),
            selected: 0,
            table_state,
            details_scroll: 0,
            hex_scroll: 0,
            should_quit: false,
        }
    }

    /// Add a new packet to the list.
    pub fn add_packet(&mut self, packet: PacketInfo) {
        self.packets.push(packet);
    }

    /// Get the currently selected packet.
    #[must_use]
    pub fn selected_packet(&self) -> Option<&PacketInfo> {
        self.packets.get(self.selected)
    }

    /// Set the selected packet index.
    pub fn set_selected(&mut self, index: usize) {
        if index < self.packets.len() {
            self.selected = index;
            self.table_state.select(Some(self.selected));
            self.details_scroll = 0;
            self.hex_scroll = 0;
        }
    }

    /// Move selection by given offset.
    pub fn move_selection(&mut self, offset: isize) {
        let new_index = if offset.is_negative() {
            self.selected.saturating_sub(offset.wrapping_abs() as usize)
        } else {
            self.selected.saturating_add(offset as usize)
        };
        self.set_selected(new_index);
    }

    /// Move selection up.
    pub fn select_previous(&mut self) {
        self.move_selection(-1);
    }

    /// Move selection down.
    pub fn select_next(&mut self) {
        self.move_selection(1);
    }

    /// Scroll details view up.
    pub fn scroll_details_up(&mut self) {
        self.details_scroll = self.details_scroll.saturating_sub(1);
    }

    /// Scroll details view down.
    pub fn scroll_details_down(&mut self) {
        self.details_scroll = self.details_scroll.saturating_add(1);
    }

    /// Scroll hex dump up.
    pub fn scroll_hex_up(&mut self) {
        self.hex_scroll = self.hex_scroll.saturating_sub(1);
    }

    /// Scroll hex dump down.
    pub fn scroll_hex_down(&mut self) {
        self.hex_scroll = self.hex_scroll.saturating_add(1);
    }

    /// Request to quit the application.
    pub fn quit(&mut self) {
        self.should_quit = true;
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
