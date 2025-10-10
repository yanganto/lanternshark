//! RARP packet parsing.

use std::fmt;
use super::EtherType;

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

impl EtherType for RarpPacket {
    const ETHER_TYPE: u16 = 0x8035;
}

impl fmt::Display for RarpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RARP Packet")
    }
}
