//! IPv6 packet parsing.

use std::fmt;
use super::EtherType;

/// An IPv6 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet {}

impl Ipv6Packet {
    /// Create a new IPv6 packet from raw data.
    #[must_use]
    pub const fn new(_raw: &[u8]) -> Self {
        // Placeholder implementation
        Self {}
    }
}

impl EtherType for Ipv6Packet {
    const ETHER_TYPE: u16 = 0x86DD;
}

impl fmt::Display for Ipv6Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IPv6 Packet")
    }
}
