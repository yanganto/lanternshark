//! IPv6 packet parsing.

/// An IPv6 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet {}

impl Ipv6Packet {
    /// Create a new IPv6 packet from raw data.
    pub fn new(_raw: &[u8]) -> Self {
        // Placeholder implementation
        Self {}
    }
}
