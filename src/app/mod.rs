//! App TUI logic.

mod events;
mod filter;
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
pub fn run<T: Activated, P: AsRef<Path>>(mut capture: Capturing<T>, save_file: Option<P>) -> Result<(), io::Error> {
    // Initialize save file if needed
    let mut save_file = if let Some(file) = save_file {
        let file_path = file.as_ref();
        match capture.savefile(file_path) {
            Err(e) => {
                eprintln!("Failed to open save file {}: {e}", file_path.display());
                None
            }
            Ok(savefile) => {
                println!("Capture will be saved to file {}", file_path.display());
                Some(savefile)
            }
        }
    } else {
        None
    };

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
                // Save to file if needed
                save_file.as_mut().map(|sf| sf.write(&packet));
            }
        }
        // For debugging
        // match capture.next_packet() {
        //     Ok(packet) => match EthernetPacket::try_from(&packet) {
        //         Ok(ethernet_packet) => {
        //             // Create packet info and add to app
        //             let packet_info = PacketInfo::from_ethernet(&ethernet_packet, packet_number);
        //             app.add_packet(packet_info);
        //             packet_number += 1;
        //         }
        //         Err(e) => {
        //             eprintln!("Failed to parse Ethernet packet: {e:?}");
        //         }
        //     }
        //     Err(pcap::Error::NoMorePackets | pcap::Error::TimeoutExpired) => {
        //         // No packets available right now, continue the loop
        //     }
        //     Err(e) => {
        //         eprintln!("Error reading next packet: {e}");
        //     }
        // }

        // Render UI
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        // Handle events
        handle_events(&mut app)?;

        // Check if we should quit
        if app.should_quit {
            break;
        }

        // Small delay to prevent busy waiting
        thread::sleep(Duration::from_millis(10));
    }

    // Restore terminal
    ratatui::restore();

    // Flush save file if needed
    save_file.as_mut().map(|sf| sf.flush());

    Ok(())
}
