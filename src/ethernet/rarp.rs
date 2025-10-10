//! RARP packet parsing.

/// An RARP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RarpPacket {}

impl RarpPacket {
    /// Create a new RARP packet from raw data.
    pub fn new(_raw: &[u8]) -> Self {
        // Placeholder implementation
        Self {}
    }
}
