//! UI rendering components.

use super::packet_info::{PacketInfo, ProtocolDetail};
use super::state::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Row, Table, Wrap},
    Frame,
};

/// Render the main UI.
pub fn render(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40), // Packet list
            Constraint::Percentage(30), // Packet details
            Constraint::Percentage(28), // Hex dump
            Constraint::Length(2),       // Help bar
        ])
        .split(frame.area());

    render_packet_list(frame, app, chunks[0]);
    render_packet_details(frame, app, chunks[1]);
    render_hex_dump(frame, app, chunks[2]);
    render_help(frame, chunks[3]);
}

/// Render the packet list table.
fn render_packet_list(frame: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(vec!["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .packets
        .iter()
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
            .title("Captured Packets (↑/↓, Wheel, j/k, PgUp/PgDn, Home/End)")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ");

    frame.render_stateful_widget(table, area, &mut app.table_state);
}

/// Render the packet details panel.
fn render_packet_details(frame: &mut Frame, app: &App, area: Rect) {
    let text = if let Some(packet) = app.selected_packet() {
        format_packet_details(packet)
    } else {
        Text::from("No packet selected")
    };

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
}

/// Format packet details for display.
fn format_packet_details(packet: &PacketInfo) -> Text<'static> {
    let mut lines = Vec::new();

    // Ethernet frame
    lines.push(Line::from(vec![
        Span::styled("▼ Ethernet II", Style::default().fg(Color::Green)),
        Span::raw(format!(", Src: {}, Dst: ", packet.packet.ethernet.source)),
        Span::raw(format!("{}", packet.packet.ethernet.destination)),
    ]));
    lines.push(Line::from(format!(
        "  Destination: {}",
        packet.packet.ethernet.destination
    )));
    lines.push(Line::from(format!(
        "  Source: {}",
        packet.packet.ethernet.source
    )));
    lines.push(Line::from(format!(
        "  Type: {}",
        packet.packet.ethernet.ethertype
    )));
    lines.push(Line::from(""));

    // Protocol-specific details
    match &packet.packet.protocol_detail {
        ProtocolDetail::Arp {
            hardware_type,
            protocol_type,
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        } => {
            lines.push(Line::from(vec![
                Span::styled("▼ Address Resolution Protocol", Style::default().fg(Color::Green)),
                Span::raw(format!(" ({operation})")),
            ]));
            lines.push(Line::from(format!("  Hardware type: {hardware_type}")));
            lines.push(Line::from(format!("  Protocol type: {protocol_type}")));
            lines.push(Line::from(format!("  Operation: {operation}")));
            lines.push(Line::from(format!("  Sender MAC address: {sender_mac}")));
            lines.push(Line::from(format!("  Sender IP address: {sender_ip}")));
            lines.push(Line::from(format!("  Target MAC address: {target_mac}")));
            lines.push(Line::from(format!("  Target IP address: {target_ip}")));
        }
        ProtocolDetail::Ipv4 {
            version,
            header_length,
            total_length,
            ttl,
            protocol,
            source,
            destination,
        } => {
            lines.push(Line::from(vec![
                Span::styled("▼ Internet Protocol Version 4", Style::default().fg(Color::Green)),
                Span::raw(format!(", Src: {source}, Dst: {destination}")),
            ]));
            lines.push(Line::from(format!("  Version: {version}")));
            lines.push(Line::from(format!(
                "  Header Length: {} bytes ({})",
                header_length * 4,
                header_length
            )));
            lines.push(Line::from(format!("  Total Length: {total_length}")));
            lines.push(Line::from(format!("  Time to Live: {ttl}")));
            lines.push(Line::from(format!("  Protocol: {} ({})",
                match *protocol {
                    1 => "ICMP",
                    6 => "TCP",
                    17 => "UDP",
                    _ => "Unknown",
                },
                protocol
            )));
            lines.push(Line::from(format!("  Source: {source}")));
            lines.push(Line::from(format!("  Destination: {destination}")));
        }
        ProtocolDetail::Ipv6 { source, destination } => {
            lines.push(Line::from(vec![
                Span::styled("▼ Internet Protocol Version 6", Style::default().fg(Color::Green)),
            ]));
            lines.push(Line::from(format!("  Source: {source}")));
            lines.push(Line::from(format!("  Destination: {destination}")));
        }
        ProtocolDetail::Rarp => {
            lines.push(Line::from(vec![
                Span::styled("▼ Reverse Address Resolution Protocol", Style::default().fg(Color::Green)),
            ]));
        }
        ProtocolDetail::Unknown { ethertype } => {
            lines.push(Line::from(vec![
                Span::styled("▼ Unknown Protocol", Style::default().fg(Color::Green)),
                Span::raw(format!(" (0x{ethertype:04X})")),
            ]));
        }
    }

    Text::from(lines)
}

/// Render the hex dump panel.
fn render_hex_dump(frame: &mut Frame, app: &App, area: Rect) {
    let text = if let Some(packet) = app.selected_packet() {
        format_hex_dump(&packet.packet.raw)
    } else {
        Text::from("No packet selected")
    };

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title("Packet Bytes (e/d to scroll)")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .scroll((app.hex_scroll, 0));

    frame.render_widget(paragraph, area);
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
        line_parts.push(Span::styled(
            ascii_part,
            Style::default().fg(Color::Cyan),
        ));

        lines.push(Line::from(line_parts));
    }

    Text::from(lines)
}

/// Render the help bar.
fn render_help(frame: &mut Frame, area: Rect) {
    let help_text = Line::from(vec![
        Span::styled("termshark", Style::default().fg(Color::Cyan)),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled("Press ", Style::default().fg(Color::DarkGray)),
        Span::styled("q", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(" or ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+C", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(" to quit", Style::default().fg(Color::DarkGray)),
    ]);

    let paragraph = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(Color::DarkGray)));

    frame.render_widget(paragraph, area);
}
