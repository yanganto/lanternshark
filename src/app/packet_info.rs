//! Packet information model for display.

use crate::ethernet::{arp::ArpPacket, ipv4::Ipv4Packet, ipv6::Ipv6Packet, rarp::RarpPacket, EtherType, EthernetPacket, EthernetPacketInner, MacAddress};
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
    /// Protocol-specific details
    pub protocol_detail: ProtocolDetail,
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

/// Protocol-specific details.
#[derive(Debug, Clone)]
pub enum ProtocolDetail {
    /// ARP packet details
    Arp {
        /// Hardware type
        hardware_type: String,
        /// Protocol type
        protocol_type: String,
        /// Operation
        operation: String,
        /// Sender MAC
        sender_mac: String,
        /// Sender IP
        sender_ip: String,
        /// Target MAC
        target_mac: String,
        /// Target IP
        target_ip: String,
    },
    /// IPv4 packet details
    Ipv4 {
        /// Version
        version: u8,
        /// Header length
        header_length: u8,
        /// Total length
        total_length: u16,
        /// TTL
        ttl: u8,
        /// Protocol
        protocol: u8,
        /// Source IP
        source: String,
        /// Destination IP
        destination: String,
    },
    /// IPv6 packet details
    Ipv6 {
        /// Source IP
        source: String,
        /// Destination IP
        destination: String,
    },
    /// RARP packet details
    Rarp,
    /// Unknown packet type
    Unknown {
        /// EtherType
        ethertype: u16,
    },
}

impl PacketInfo {
    /// Create a `PacketInfo` from an `EthernetPacket`.
    #[must_use]
    pub fn from_ethernet(packet: &EthernetPacket, number: usize) -> Self {
        let timestamp = packet.timestamp;
        let length = packet.raw.len();

        let (source, destination, protocol, info, protocol_detail) = match &packet.inner {
            EthernetPacketInner::Arp(arp) => {
                let source = format!("{}", arp.sender_mac);
                let destination = format!("{}", arp.target_mac);
                let protocol = "ARP".to_string();
                let info = format!(
                    "{:?}: Who has {}? Tell {}",
                    arp.operation, arp.target_ip, arp.sender_ip
                );
                let detail = ProtocolDetail::Arp {
                    hardware_type: format!("{:?}", arp.hardware_type),
                    protocol_type: format!("{:?}", arp.protocol_type),
                    operation: format!("{:?}", arp.operation),
                    sender_mac: format!("{}", arp.sender_mac),
                    sender_ip: format!("{}", arp.sender_ip),
                    target_mac: format!("{}", arp.target_mac),
                    target_ip: format!("{}", arp.target_ip),
                };
                (source, destination, protocol, info, detail)
            }
            EthernetPacketInner::Ipv4(ipv4) => {
                let source = format!("{}", ipv4.source);
                let destination = format!("{}", ipv4.destination);
                let protocol = "IPv4".to_string();
                let info = format!("Len: {}, TTL: {}", ipv4.total_length, ipv4.ttl);
                let detail = ProtocolDetail::Ipv4 {
                    version: ipv4.version,
                    header_length: ipv4.header_length,
                    total_length: ipv4.total_length,
                    ttl: ipv4.ttl,
                    protocol: match &ipv4.inner {
                        crate::ethernet::ipv4::Ipv4PacketInner::Unknown(u) => u.protocol,
                    },
                    source: format!("{}", ipv4.source),
                    destination: format!("{}", ipv4.destination),
                };
                (source, destination, protocol, info, detail)
            }
            EthernetPacketInner::Ipv6(_ipv6) => {
                let source = format!("{}", packet.source);
                let destination = format!("{}", packet.destination);
                let protocol = "IPv6".to_string();
                let info = "IPv6 packet".to_string();
                let detail = ProtocolDetail::Ipv6 {
                    source: "::".to_string(),
                    destination: "::".to_string(),
                };
                (source, destination, protocol, info, detail)
            }
            EthernetPacketInner::Rarp(_rarp) => {
                let source = format!("{}", packet.source);
                let destination = format!("{}", packet.destination);
                let protocol = "RARP".to_string();
                let info = "RARP packet".to_string();
                let detail = ProtocolDetail::Rarp;
                (source, destination, protocol, info, detail)
            }
            EthernetPacketInner::Unknown(unknown) => {
                let source = format!("{}", packet.source);
                let destination = format!("{}", packet.destination);
                let protocol = format!("Unknown (0x{:04X})", unknown.ethertype);
                let info = "Unknown protocol".to_string();
                let detail = ProtocolDetail::Unknown {
                    ethertype: unknown.ethertype,
                };
                (source, destination, protocol, info, detail)
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
            packet: PacketInfoDetail {
                raw: packet.raw.to_vec(),
                ethernet: EthernetFrameDetail {
                    source: packet.source,
                    destination: packet.destination,
                    ethertype: match &packet.inner {
                        EthernetPacketInner::Ipv4(_) => format!("IPv4 ({:04x})", Ipv4Packet::ETHER_TYPE),
                        EthernetPacketInner::Arp(_) => format!("ARP (0x{:04x})", ArpPacket::ETHER_TYPE),
                        EthernetPacketInner::Rarp(_) => format!("RARP (0x{:04x})", RarpPacket::ETHER_TYPE),
                        EthernetPacketInner::Ipv6(_) => format!("IPv6 (0x{:04x})", Ipv6Packet::ETHER_TYPE),
                        EthernetPacketInner::Unknown(u) => format!("Unknown (0x{:04X})", u.ethertype),
                    },
                },
                protocol_detail,
            },
        }
    }
}
