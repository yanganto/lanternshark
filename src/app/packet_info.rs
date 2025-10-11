//! Packet information model for display.

use crate::ethernet::{
    arp::ArpPacket, ipv4::Ipv4Packet, ipv6::Ipv6Packet, rarp::RarpPacket, EtherType,
    EthernetPacket, EthernetPacketInner, MacAddress, packet_detail::PacketDetail,
};
use chrono::DateTime;

/// Display information for a packet.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// Packet number (1-indexed for display)
    pub number: usize,
    /// Timestamp when the packet was captured
    pub timestamp: DateTime<chrono::Utc>,
    /// Source address (MAC or IP depending on packet type)
    pub source: String,
    /// Destination address (MAC or IP depending on packet type)
    pub destination: String,
    /// Protocol name
    pub protocol: String,
    /// Packet length in bytes
    pub length: usize,
    /// Additional information about the packet
    pub info: String,
    /// Protocol full name
    pub protocol_name: String,
    /// Protocol details
    pub details: Vec<String>,
    /// The full Ethernet packet for detailed view
    pub packet: PacketInfoDetail,
}

/// Detailed packet information for the details pane.
#[derive(Debug, Clone)]
pub struct PacketInfoDetail {
    /// Raw packet data
    pub raw: Vec<u8>,
    /// Ethernet frame details
    pub ethernet: EthernetFrameDetail,
}

/// Ethernet frame details.
#[derive(Debug, Clone)]
pub struct EthernetFrameDetail {
    /// Source MAC address
    pub source: MacAddress,
    /// Destination MAC address
    pub destination: MacAddress,
    /// EtherType
    pub ethertype: String,
}

impl PacketInfo {
    /// Create a `PacketInfo` from an `EthernetPacket`.
    #[must_use]
    pub fn from_ethernet(packet: &EthernetPacket, number: usize) -> Self {
        let timestamp = packet.timestamp;
        let length = packet.raw.len();

        let (source, destination, protocol, info, protocol_name, details) = match &packet.inner {
            EthernetPacketInner::Arp(arp) => {
                let source = arp.source();
                let destination = arp.destination();
                let protocol = arp.slug().to_string();
                let info = arp.summary();
                let protocol_name = arp.name().to_string();
                let details = arp.details();
                (source, destination, protocol, info, protocol_name, details)
            }
            EthernetPacketInner::Ipv4(ipv4) => {
                let source = ipv4.source();
                let destination = ipv4.destination();
                let protocol = ipv4.slug().to_string();
                let info = ipv4.summary();
                let protocol_name = ipv4.name().to_string();
                let details = ipv4.details();
                (source, destination, protocol, info, protocol_name, details)
            }
            EthernetPacketInner::Ipv6(_ipv6) => {
                let source = packet.source.to_string();
                let destination = packet.destination.to_string();
                let protocol = "IPv6".to_string();
                let info = "IPv6 packet".to_string();
                let protocol_name = "Internet Protocol Version 6".to_string();
                let details = vec!["IPv6 parsing not yet implemented".to_string()];
                (source, destination, protocol, info, protocol_name, details)
            }
            EthernetPacketInner::Rarp(_rarp) => {
                let source = packet.source.to_string();
                let destination = packet.destination.to_string();
                let protocol = "RARP".to_string();
                let info = "RARP packet".to_string();
                let protocol_name = "Reverse Address Resolution Protocol".to_string();
                let details = vec!["RARP parsing not yet implemented".to_string()];
                (source, destination, protocol, info, protocol_name, details)
            }
            EthernetPacketInner::Unknown(unknown) => {
                let source = packet.source.to_string();
                let destination = packet.destination.to_string();
                let protocol = format!("Unknown (0x{:04X})", unknown.ethertype);
                let info = "Unknown protocol".to_string();
                let protocol_name = format!("Unknown Protocol (0x{:04X})", unknown.ethertype);
                let details = vec![format!("EtherType: 0x{:04X}", unknown.ethertype)];
                (source, destination, protocol, info, protocol_name, details)
            }
        };

        Self {
            number,
            timestamp,
            source,
            destination,
            protocol,
            length,
            info,
            protocol_name,
            details,
            packet: PacketInfoDetail {
                raw: packet.raw.to_vec(),
                ethernet: EthernetFrameDetail {
                    source: packet.source,
                    destination: packet.destination,
                    ethertype: match &packet.inner {
                        EthernetPacketInner::Ipv4(_) => format!("IPv4 (0x{:04x})", Ipv4Packet::ETHER_TYPE),
                        EthernetPacketInner::Arp(_) => format!("ARP (0x{:04x})", ArpPacket::ETHER_TYPE),
                        EthernetPacketInner::Rarp(_) => format!("RARP (0x{:04x})", RarpPacket::ETHER_TYPE),
                        EthernetPacketInner::Ipv6(_) => format!("IPv6 (0x{:04x})", Ipv6Packet::ETHER_TYPE),
                        EthernetPacketInner::Unknown(u) => format!("Unknown (0x{:04X})", u.ethertype),
                    },
                },
            },
        }
    }
}
