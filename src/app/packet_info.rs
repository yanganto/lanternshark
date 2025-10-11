//! Packet information model for display.

use crate::ethernet::{
    arp::ArpPacket, ipv4::Ipv4Packet, ipv6::Ipv6Packet, rarp::RarpPacket, EtherType,
    EthernetPacket, EthernetPacketInner, MacAddress, packet_detail::PacketDetail,
};
use chrono::DateTime;

/// Represents a single protocol layer in the stack
#[derive(Debug, Clone)]
pub struct ProtocolLayer {
    /// Human-readable protocol name (e.g., "Internet Control Message Protocol")
    pub name: String,
    /// Protocol slug for the packet list (e.g., "ICMP")
    #[allow(dead_code)]
    pub slug: String,
    /// One-line summary of this layer
    #[allow(dead_code)]
    pub summary: String,
    /// Detailed field information
    pub details: Vec<String>,
}

impl ProtocolLayer {
    /// Create a new protocol layer from a PacketDetail implementor.
    pub fn from_packet_detail(packet: &dyn PacketDetail) -> Self {
        Self {
            name: packet.name().to_string(),
            slug: packet.slug().to_string(),
            summary: packet.summary(),
            details: packet.details(),
        }
    }

    /// Collect all protocol layers by traversing the inner() linked list.
    pub fn collect_from(root: &dyn PacketDetail) -> Vec<Self> {
        let mut layers = Vec::new();
        let mut current: Option<&dyn PacketDetail> = Some(root);

        while let Some(packet) = current {
            layers.push(Self::from_packet_detail(packet));
            current = packet.inner();
        }

        layers
    }
}

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
    /// All protocol layers (collected by traversing inner() links)
    pub layers: Vec<ProtocolLayer>,
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

        // Determine the root protocol and collect all layers via linked list traversal
        let (source, destination, protocol, info, root_protocol) = match &packet.inner {
            EthernetPacketInner::Arp(arp) => {
                (
                    arp.source(),
                    arp.destination(),
                    arp.slug().to_string(),
                    arp.summary(),
                    arp as &dyn PacketDetail,
                )
            }
            EthernetPacketInner::Ipv4(ipv4) => {
                // For IPv4 packets, determine the innermost protocol for the table display
                let (protocol, info) = Self::get_innermost_protocol_info(ipv4);
                (
                    ipv4.source(),
                    ipv4.destination(),
                    protocol,
                    info,
                    ipv4 as &dyn PacketDetail,
                )
            }
            EthernetPacketInner::Ipv6(_ipv6) => {
                (
                    packet.source.to_string(),
                    packet.destination.to_string(),
                    "IPv6".to_string(),
                    "IPv6 packet".to_string(),
                    &DummyProtocolDetail { // Temporary until IPv6 implements PacketDetail
                        slug: "IPV6",
                        name: "Internet Protocol Version 6".to_string(),
                        summary: "IPv6 packet".to_string(),
                        details: vec!["IPv6 parsing not yet implemented".to_string()],
                    } as &dyn PacketDetail,
                )
            }
            EthernetPacketInner::Rarp(_rarp) => {
                (
                    packet.source.to_string(),
                    packet.destination.to_string(),
                    "RARP".to_string(),
                    "RARP packet".to_string(),
                    &DummyProtocolDetail {
                        slug: "RARP",
                        name: "Reverse Address Resolution Protocol".to_string(),
                        summary: "RARP packet".to_string(),
                        details: vec!["RARP parsing not yet implemented".to_string()],
                    } as &dyn PacketDetail,
                )
            }
            EthernetPacketInner::Unknown(unknown) => {
                (
                    packet.source.to_string(),
                    packet.destination.to_string(),
                    format!("Unknown (0x{:04X})", unknown.ethertype),
                    "Unknown protocol".to_string(),
                    &DummyProtocolDetail {
                        slug: "UNKNOWN",
                        name: format!("Unknown Protocol (0x{:04X})", unknown.ethertype),
                        summary: "Unknown protocol".to_string(),
                        details: vec![format!("EtherType: 0x{:04X}", unknown.ethertype)],
                    } as &dyn PacketDetail,
                )
            }
        };

        // Collect all layers by traversing the inner() linked list
        let layers = ProtocolLayer::collect_from(root_protocol);

        Self {
            number,
            timestamp,
            source,
            destination,
            protocol,
            length,
            info,
            layers,
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

    /// Get the innermost protocol info for display in the packet table.
    /// For IPv4 packets, this shows ICMP/TCP/UDP instead of just IPv4.
    fn get_innermost_protocol_info(ipv4: &Ipv4Packet) -> (String, String) {
        // Traverse to the deepest layer
        let mut current: &dyn PacketDetail = ipv4;
        let mut deepest = current;

        while let Some(inner) = current.inner() {
            deepest = inner;
            current = inner;
        }

        (deepest.slug().to_string(), deepest.summary())
    }
}

// Temporary helper for protocols that don't implement PacketDetail yet
struct DummyProtocolDetail {
    slug: &'static str,
    name: String,
    summary: String,
    details: Vec<String>,
}

impl PacketDetail for DummyProtocolDetail {
    fn summary(&self) -> String {
        self.summary.clone()
    }

    fn details(&self) -> Vec<String> {
        self.details.clone()
    }

    fn slug(&self) -> &'static str {
        self.slug
    }

    fn name(&self) -> &'static str {
        // This is a workaround - we leak the string to get a 'static reference
        // since DummyProtocolDetail is only used temporarily during packet creation
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn length(&self) -> usize {
        0
    }
}
