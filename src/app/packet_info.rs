//! Packet information model for display.

use crate::ethernet::{EthernetPacket, PacketDetail};
use chrono::DateTime;

/// Represents a single protocol layer in the stack
#[derive(Debug, Clone)]
pub struct ProtocolLayer {
    /// Human-readable protocol name (e.g., "Internet Control Message Protocol")
    pub name: String,
    /// One-line summary of this layer
    pub summary: String,
    /// Detailed field information
    pub details: Vec<String>,
}

impl ProtocolLayer {
    /// Create a new protocol layer from a PacketDetail implementor.
    pub fn from_packet_detail(packet: &dyn PacketDetail) -> Self {
        Self {
            name: packet.name().to_string(),
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
    /// Raw packet bytes for hex dump display
    pub raw: Vec<u8>,
}

impl PacketInfo {
    /// Create a `PacketInfo` from an `EthernetPacket`.
    #[must_use]
    pub fn from_ethernet(packet: &EthernetPacket, number: usize) -> Self {
        let timestamp = packet.timestamp;
        let length = packet.raw.len();

        // EthernetPacket now implements PacketDetail, so we can start from it
        let root_protocol: &dyn PacketDetail = packet;

        // Traverse to the deepest layer to determine what to show in the table
        let deepest = Self::get_deepest_protocol(packet);
        let protocol = deepest.slug().to_string();
        let info = deepest.summary();

        // Get source and destination from the first layer that has meaningful addresses
        // (traverse the chain until we find non-"N/A" values)
        let (source, destination) = Self::get_addresses(packet);

        // Collect all layers starting from Ethernet, traversing the inner() linked list
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
            raw: packet.raw.to_vec(),
        }
    }

    /// Get the deepest protocol in the stack for display in the packet table.
    /// Traverses the entire chain to find the innermost protocol.
    fn get_deepest_protocol<'a>(packet: &'a EthernetPacket) -> &'a dyn PacketDetail {
        let mut current: &'a dyn PacketDetail = packet;
        let mut deepest = current;

        while let Some(inner) = current.inner() {
            deepest = inner;
            current = inner;
        }

        deepest
    }

    /// Get source and destination addresses from the protocol chain.
    /// Traverses the entire chain and returns the last layer with meaningful addresses.
    /// Prefers in following orders
    /// 1. Transport Layer: IP addresses with service ports
    /// 2. Network layer: IP addresses 
    /// 3. Link layer: Mac addresses 
    fn get_addresses(packet: &EthernetPacket) -> (String, String) {
        let mut current: Option<&dyn PacketDetail> = Some(packet);
        let mut last_valid_addresses: Option<(String, String)> = None;
        let mut last_valid_ports: Option<(u16, u16)> = None;

        while let Some(protocol) = current {
            // Check if this protocol has addresses
            if let (Some(source), Some(destination)) = (protocol.source(), protocol.destination()) {
                last_valid_addresses = Some((source, destination));
            }
            if let (Some(sport), Some(dport)) = (protocol.sport(), protocol.dport()) && last_valid_ports.is_none(){
                last_valid_ports = Some((sport, dport));
            }
            current = protocol.inner();
        }

        match (last_valid_ports, last_valid_addresses) {
            (Some((sport, dport)), Some((source, destination))) => {
                (format!("{source:}:{sport}"), format!("{destination:}:{dport}"))
            },
            (None, Some((source, destination))) => (source, destination),
            _ => (packet.source.to_string(), packet.destination.to_string())
        }
    }
}
