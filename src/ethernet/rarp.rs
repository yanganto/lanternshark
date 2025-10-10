//! RARP packet parsing.

use std::fmt;

/// An RARP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RarpPacket {}

impl RarpPacket {
    /// Create a new RARP packet from raw data.
    #[must_use] 
    pub const fn new(_raw: &[u8]) -> Self {
        // Placeholder implementation
        Self {}
    }
}

impl fmt::Display for RarpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RARP Packet")
    }
}
