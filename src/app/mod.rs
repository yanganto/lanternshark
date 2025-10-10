//! App TUI logic.

use pcap::{Activated, Capture as Capturing};
use ratatui::{DefaultTerminal, Frame};
use super::ethernet::{EthernetPacket, EthernetPacketInner};

/// Main application logic.
pub fn run<T: Activated>(mut capture: Capturing<T>) {
    let mut terminal = ratatui::init();
    while let Ok(packet) = capture.next_packet() {
        let packet = match EthernetPacket::try_from(&packet) {
            Ok(packet) => packet,
            Err(e) => {
                eprintln!("Failed to parse Ethernet packet: {e:?}");
                continue;
            }
        };
        // println!("{packet}");
        // Only print ARP and IPv4 packets for now
        match packet.inner {
            EthernetPacketInner::Arp(arp) => println!("---\n{arp}"),
            EthernetPacketInner::Ipv4(ipv4) => println!("---\n{ipv4}"),
            _ => continue,
        };
    }
    ratatui::restore();
}
