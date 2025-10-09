//! ARP packet parsing.

/// An ARP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {}

impl ArpPacket {
    /// Create a new ARP packet from raw data.
    pub fn new(_data: &[u8]) -> Self {
        // Placeholder implementation
        Self {}
    }
}
