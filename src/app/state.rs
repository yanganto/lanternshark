//! Application state management.

use super::filter::PacketFilter;
use super::packet_info::PacketInfo;
use ratatui::widgets::TableState;

/// Main application state.
#[derive(Debug)]
pub struct App {
    /// All captured packets (unfiltered)
    pub all_packets: Vec<PacketInfo>,
    /// Indices of filtered packets in all_packets
    pub filtered_indices: Vec<usize>,
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
    /// Visible page height for packet list (updated by UI)
    pub packet_list_height: u16,
}

impl App {
    /// Create a new application state.
    #[must_use]
    pub fn new() -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self {
            all_packets: Vec::new(),
            filtered_indices: Vec::new(),
            selected: 0,
            table_state,
            details_scroll: 0,
            hex_scroll: 0,
            should_quit: false,
            filter: None,
            filter_input: String::new(),
            filter_mode: false,
            filter_error: None,
            packet_list_height: 10, // Default page size
        }
    }

    /// Add a new packet to the list.
    pub fn add_packet(&mut self, packet: PacketInfo) {
        let packet_index = self.all_packets.len();
        self.all_packets.push(packet);

        // Apply filter if active
        if let Some(ref filter) = self.filter {
            if filter.matches(&self.all_packets[packet_index]) {
                self.filtered_indices.push(packet_index);
            }
        } else {
            self.filtered_indices.push(packet_index);
        }
    }

    /// Apply a filter to all captured packets.
    pub fn apply_filter(&mut self) {
        self.filtered_indices.clear();

        if let Some(ref filter) = self.filter {
            for (index, packet) in self.all_packets.iter().enumerate() {
                if filter.matches(packet) {
                    self.filtered_indices.push(index);
                }
            }
        } else {
            self.filtered_indices = (0..self.all_packets.len()).collect();
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
        self.filtered_indices
            .get(self.selected)
            .and_then(|&index| self.all_packets.get(index))
    }

    /// Get filtered packets for display.
    pub fn filtered_packets(&self) -> impl Iterator<Item = &PacketInfo> {
        self.filtered_indices
            .iter()
            .filter_map(|&index| self.all_packets.get(index))
    }

    /// Get the number of filtered packets.
    pub fn filtered_count(&self) -> usize {
        self.filtered_indices.len()
    }

    /// Set the selected packet index.
    pub fn set_selected(&mut self, index: usize) {
        let index = self.filtered_count().saturating_sub(1).min(index);
        self.selected = index;
        self.table_state.select(Some(self.selected));
        self.details_scroll = 0;
        self.hex_scroll = 0;
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

    /// Move selection up by one page.
    pub fn page_up(&mut self) {
        let page_size = self.packet_list_height.max(1) as isize;
        self.move_selection(-page_size);
    }

    /// Move selection down by one page.
    pub fn page_down(&mut self) {
        let page_size = self.packet_list_height.max(1) as isize;
        self.move_selection(page_size);
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
