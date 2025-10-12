//! Application state management.

use super::filter::PacketFilter;
use super::packet_info::PacketInfo;
use ratatui::widgets::TableState;

/// Main application state.
#[derive(Debug)]
pub struct App {
    /// All captured packets (unfiltered)
    pub all_packets: Vec<PacketInfo>,
    /// Filtered packets for display
    pub packets: Vec<PacketInfo>,
    /// Currently selected packet index (in filtered list)
    pub selected: usize,
    /// Table state for the packet list
    pub table_state: TableState,
    /// Scroll offset for the packet details view
    pub details_scroll: u16,
    /// Scroll offset for the hex dump view
    pub hex_scroll: u16,
    /// Whether the application should quit
    pub should_quit: bool,
    /// Current packet filter
    pub filter: Option<PacketFilter>,
    /// Filter input string (when editing)
    pub filter_input: String,
    /// Whether filter input mode is active
    pub filter_mode: bool,
    /// Error message from last filter parse attempt
    pub filter_error: Option<String>,
}

impl App {
    /// Create a new application state.
    #[must_use]
    pub fn new() -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self {
            all_packets: Vec::new(),
            packets: Vec::new(),
            selected: 0,
            table_state,
            details_scroll: 0,
            hex_scroll: 0,
            should_quit: false,
            filter: None,
            filter_input: String::new(),
            filter_mode: false,
            filter_error: None,
        }
    }

    /// Add a new packet to the list.
    pub fn add_packet(&mut self, packet: PacketInfo) {
        self.all_packets.push(packet.clone());

        // Apply filter if active
        if let Some(ref filter) = self.filter {
            if filter.matches(&packet) {
                self.packets.push(packet);
            }
        } else {
            self.packets.push(packet);
        }
    }

    /// Apply a filter to all captured packets.
    pub fn apply_filter(&mut self) {
        self.packets.clear();

        if let Some(ref filter) = self.filter {
            for packet in &self.all_packets {
                if filter.matches(packet) {
                    self.packets.push(packet.clone());
                }
            }
        } else {
            self.packets = self.all_packets.clone();
        }

        // Reset selection to first item
        self.selected = 0;
        self.table_state.select(Some(0));
        self.details_scroll = 0;
        self.hex_scroll = 0;
    }

    /// Set filter from input string.
    pub fn set_filter(&mut self, input: &str) {
        if input.trim().is_empty() {
            self.filter = None;
            self.filter_error = None;
        } else {
            match PacketFilter::parse(input) {
                Ok(filter) => {
                    self.filter = Some(filter);
                    self.filter_error = None;
                }
                Err(e) => {
                    self.filter_error = Some(e);
                    return; // Don't apply invalid filter
                }
            }
        }

        self.apply_filter();
    }

    /// Enter filter editing mode.
    pub fn enter_filter_mode(&mut self) {
        self.filter_mode = true;
        // Initialize input with current filter if any
        self.filter_input = self.filter
            .as_ref()
            .map(|f| f.to_string())
            .unwrap_or_default();
    }

    /// Exit filter editing mode without applying.
    pub fn exit_filter_mode(&mut self) {
        self.filter_mode = false;
        self.filter_input.clear();
        self.filter_error = None;
    }

    /// Apply current filter input and exit filter mode.
    pub fn apply_filter_input(&mut self) {
        let input = self.filter_input.clone();
        self.set_filter(&input);

        // Only exit filter mode if there's no error
        if self.filter_error.is_none() {
            self.filter_mode = false;
            self.filter_input.clear();
        }
    }

    /// Clear current filter.
    pub fn clear_filter(&mut self) {
        self.filter = None;
        self.filter_error = None;
        self.apply_filter();
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
