//! App TUI logic.

mod events;
mod packet_info;
mod state;
mod ui;

use events::handle_events;
use packet_info::PacketInfo;
use pcap::{Activated, Capture as Capturing};
use state::App;
use super::ethernet::EthernetPacket;
use std::{io, path::Path, thread, time::Duration};

/// Main application logic.
///
/// # Errors
///
/// Returns an error if the TUI fails to initialize or render.
pub fn run<T: Activated, P: AsRef<Path>>(mut capture: Capturing<T>, save_file: P) -> Result<(), io::Error> {
    // Initialize terminal
    let mut terminal = ratatui::init();
    terminal.clear()?;

    // Create app state
    let mut app = App::new();
    let mut packet_number = 1;

    // Main event loop
    loop {
        // Try to capture a packet (non-blocking since we've called `setnonblock`)
        if let Ok(packet) = capture.next_packet() {
            // Parse the packet
            if let Ok(ethernet_packet) = EthernetPacket::try_from(&packet) {
                // Create packet info and add to app
                let packet_info = PacketInfo::from_ethernet(&ethernet_packet, packet_number);
                app.add_packet(packet_info);
                packet_number += 1;
            }
        }

        // Render UI
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        // Handle events
        handle_events(&mut app)?;

        // Check if we should quit
        if app.should_quit {
            break;
        }

        // Small delay to prevent busy waiting
        thread::sleep(Duration::from_millis(100));
    }

    // Restore terminal
    ratatui::restore();

    // Save file if needed
    if let Some(file) = save_file.as_ref().to_str() {
        match capture.savefile(file) {
            Err(e) => eprintln!("Failed to save capture to file {file}: {e}"),
            Ok(_) => println!("Capture saved to file {file}"),
        }
    }

    Ok(())
}
