//! IPv6 packet parsing.

use std::fmt;
use super::{EtherType, PacketDetail};

/// An IPv6 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet<'a> {
    // TODO: Complete the fields.
    /// The raw data field of the IPv6 packet.
    pub data: &'a [u8],
    /// The raw IPv6 packet.
    pub raw: &'a [u8],
}


/// Possible errors when parsing an IPv6 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIpv6Error {}

impl<'a> Ipv6Packet<'a> {
    /// Create a new IPv6 packet from raw data.
    #[must_use]
    pub const fn new(raw: &'a [u8]) -> Result<Self, ParseIpv6Error> {
        // Placeholder implementation
        Ok(Self { data: raw, raw })
    }
}

impl EtherType for Ipv6Packet<'_> {
    const ETHER_TYPE: u16 = 0x86DD;
}

impl fmt::Display for Ipv6Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IPv6 Packet")
    }
}

impl PacketDetail for Ipv6Packet<'_> {
    fn summary(&self) -> String {
        "IPv6 Packet".to_string()
    }

    fn details(&self) -> Vec<String> {
        vec!["IPv6 parsing not yet implemented".to_string()]
    }

    fn slug(&self) -> &'static str {
        "IPV6"
    }

    fn name(&self) -> &'static str {
        "Internet Protocol Version 6"
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}

impl From<ParseIpv6Error> for super::ParseEthernetError {
    fn from(err: ParseIpv6Error) -> Self {
        Self::ParseIpv6Error(err)
    }
}
