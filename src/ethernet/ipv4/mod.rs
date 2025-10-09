//! IPv4 packet parsing.

/// An IPv4 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet {}

impl Ipv4Packet {
    /// Create a new IPv4 packet from raw data.
    pub fn new(_data: &[u8]) -> Self {
        // Placeholder implementation
        Self {}
    }
}
