//! UI rendering components.

use super::{packet_info::PacketInfo, state::App};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
        Wrap,
    },
};

/// Render the main UI.
pub fn render(frame: &mut Frame, app: &mut App) {
    // Show filter bar if in filter mode OR if a filter is currently applied OR if there's a filter error
    let show_filter_bar = app.filter_editing || app.filter.is_some() || app.filter_error.is_some();

    // Use horizontal layout for details and hex dump when terminal is wide enough
    let use_horizontal_layout = frame.area().width >= 148;

    if use_horizontal_layout {
        // Wide terminal: horizontal layout for details and hex dump
        let mut main_constraints = vec![
            Constraint::Fill(6),   // Packet list
            Constraint::Fill(4),   // Details + Hex (combined)
            Constraint::Length(1), // Help bar
        ];
        if show_filter_bar {
            main_constraints.insert(0, Constraint::Length(3)); // Filter input bar
        };

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(main_constraints)
            .split(frame.area());

        let offset = if show_filter_bar {
            render_filter_input(frame, app, chunks[0]);
            1
        } else {
            0
        };
        render_packet_list(frame, app, chunks[offset + 0]);

        // Split the middle area horizontally for details and hex dump
        let bottom_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(0),     // Packet details (takes remaining space)
                Constraint::Length(74), // Hex dump (fixed width)
            ])
            .split(chunks[offset + 1]);

        render_packet_details(frame, app, bottom_chunks[0]);
        render_hex_dump(frame, app, bottom_chunks[1]);
        render_help(frame, chunks[offset + 2]);
    } else {
        // Narrow terminal: vertical layout (original)
        let mut constraints = vec![
            Constraint::Fill(4),   // Packet list
            Constraint::Fill(3),   // Packet details
            Constraint::Fill(3),   // Hex dump
            Constraint::Length(1), // Help bar
        ];
        if show_filter_bar {
            constraints.insert(0, Constraint::Length(3)); // Filter input bar
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(frame.area());

        let offset = if show_filter_bar {
            render_filter_input(frame, app, chunks[0]);
            1
        } else {
            0
        };
        render_packet_list(frame, app, chunks[offset + 0]);
        render_packet_details(frame, app, chunks[offset + 1]);
        render_hex_dump(frame, app, chunks[offset + 2]);
        render_help(frame, chunks[offset + 3]);
    }
}

/// Render the filter input bar.
fn render_filter_input(frame: &mut Frame, app: &App, area: Rect) {
    // Determine text and style based on mode
    if app.filter_editing {
        // In filter mode: show current input being edited
        let style = if app.filter_error.is_some() {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Green)
        };

        let title = if let Some(ref error) = app.filter_error {
            format!("Filter (Error: {error}) - Press Enter to apply, Esc to clear")
        } else {
            "Filter - Press Enter to apply, Esc to clear".to_string()
        };

        let input = Paragraph::new(app.filter_input.value())
            .style(style)
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );

        frame.render_widget(input, area);

        // Show cursor when in filter mode
        let cursor_x = area.x + app.filter_input.visual_cursor() as u16 + 1;
        let cursor_y = area.y + 1;
        frame.set_cursor_position((cursor_x, cursor_y));
    } else {
        // Filter applied but not editing: show current filter
        let title = "Filter Active - Press Enter to edit, Esc to cancel";

        let input = Paragraph::new(app.filter_input.value())
            .style(Style::default().fg(Color::Cyan))
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            );

        frame.render_widget(input, area);
    }
}

/// Render the packet list table.
fn render_packet_list(frame: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(vec![
        "No.",
        "Time",
        "Source",
        "Destination",
        "Protocol",
        "Length",
        "Summary",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .filtered_packets()
        .map(|packet| {
            let time = packet.timestamp.format("%H:%M:%S%.6f").to_string();
            Row::new(vec![
                packet.number.to_string(),
                time,
                packet.source.clone(),
                packet.destination.clone(),
                packet.protocol.clone(),
                packet.length.to_string(),
                packet.info.clone(),
            ])
        })
        .collect();

    // Build title - show filtered count when filter is active
    let title = if app.filter.is_some() {
        format!(
            "Captured Packets ({}/{}) - ↑/↓, j/k, PgUp/PgDn, Home/End",
            app.filtered_count(),
            app.all_packets.len()
        )
    } else {
        format!(
            "Captured Packets ({}) - ↑/↓, j/k, PgUp/PgDn, Home/End",
            app.filtered_count()
        )
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(16),
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ");

    // Update the visible page height for page up/down navigation
    // Height = area height - 2 (borders) - 1 (header)
    app.packet_list_height = area.height.saturating_sub(3);

    frame.render_stateful_widget(table, area, &mut app.table_state);

    // Render scrollbar for packet list
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"))
        .style(Style::default().fg(Color::Cyan));

    let mut scrollbar_state = ScrollbarState::new(app.filtered_count()).position(app.selected);

    frame.render_stateful_widget(
        scrollbar,
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

/// Render the packet details panel.
fn render_packet_details(frame: &mut Frame, app: &App, area: Rect) {
    let text = if let Some(packet) = app.selected_packet() {
        format_packet_details(packet)
    } else {
        Text::from("No packet selected")
    };

    let total_lines = text.lines.len();

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title("Packet Details (w/s to scroll)")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.details_scroll, 0));

    frame.render_widget(paragraph, area);

    // Render scrollbar for packet details
    if total_lines > 0 {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"))
            .style(Style::default().fg(Color::Cyan));

        let mut scrollbar_state =
            ScrollbarState::new(total_lines.saturating_sub(area.height.saturating_sub(2) as usize))
                .position(app.details_scroll as usize);

        frame.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

/// Format packet details for display.
fn format_packet_details(packet: &PacketInfo) -> Text<'static> {
    let mut lines = Vec::new();

    // Display all protocol layers collected via the linked-list traversal
    for layer in &packet.layers {
        lines.push(Line::from(vec![
            Span::styled(
                format!("▼ {}", layer.name),
                Style::default().fg(Color::Green),
            ),
            Span::raw(format!(", {}", layer.summary)),
        ]));

        for detail in &layer.details {
            lines.push(Line::from(format!("  {detail}")));
        }

        // Add spacing between layers
        lines.push(Line::from(""));
    }

    Text::from(lines)
}

/// Render the hex dump panel.
fn render_hex_dump(frame: &mut Frame, app: &App, area: Rect) {
    let text = if let Some(packet) = app.selected_packet() {
        format_hex_dump(&packet.raw)
    } else {
        Text::from("No packet selected")
    };

    let total_lines = text.lines.len();

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title("Packet Bytes (e/d to scroll)")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .scroll((app.hex_scroll, 0));

    frame.render_widget(paragraph, area);

    // Render scrollbar for hex dump
    if total_lines > 0 {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"))
            .style(Style::default().fg(Color::Cyan));

        let mut scrollbar_state =
            ScrollbarState::new(total_lines.saturating_sub(area.height.saturating_sub(2) as usize))
                .position(app.hex_scroll as usize);

        frame.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

/// Format raw bytes as hex dump.
fn format_hex_dump(data: &[u8]) -> Text<'static> {
    let mut lines = Vec::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;

        // Offset
        let mut line_parts = vec![Span::styled(
            format!("{offset:04x}  "),
            Style::default().fg(Color::DarkGray),
        )];

        // Hex bytes
        let mut hex_part = String::new();
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                hex_part.push(' ');
            }
            hex_part.push_str(&format!("{byte:02x} "));
        }

        // Pad if less than 16 bytes
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                if j == 8 {
                    hex_part.push(' ');
                }
                hex_part.push_str("   ");
            }
        }

        line_parts.push(Span::raw(hex_part));

        // ASCII representation
        line_parts.push(Span::raw(" "));
        let mut ascii_part = String::new();
        for byte in chunk {
            let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            ascii_part.push(ch);
        }
        line_parts.push(Span::styled(ascii_part, Style::default().fg(Color::Cyan)));

        lines.push(Line::from(line_parts));
    }

    Text::from(lines)
}

/// Render the help bar.
fn render_help(frame: &mut Frame, area: Rect) {
    const APP_NAME: &'static str = env!("CARGO_PKG_NAME");
    const VERSION: &'static str = env!("CARGO_PKG_VERSION");
    let help_text = Line::from(vec![
        Span::styled(
            format!("{APP_NAME}@{VERSION}"),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "Enter",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" filter ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "Esc",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" clear ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "q",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" quit", Style::default().fg(Color::DarkGray)),
    ]);

    let paragraph = Paragraph::new(help_text);
    frame.render_widget(paragraph, area);
}
