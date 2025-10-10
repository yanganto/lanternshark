//! ICMP packet parsing.

use std::fmt;
use super::{Protocol, ParseIpv4Error};

/// A ICMP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpPacket<'a> {
    // TODO: Complete the fields.
    /// The raw data field of the ICMP packet.
    pub data: &'a [u8],
    /// The raw ICMP packet.
    pub raw: &'a [u8],
}

/// Possible errors when parsing a ICMP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIcmpError {}

impl From<ParseIcmpError> for ParseIpv4Error {
    fn from(err: ParseIcmpError) -> Self {
        Self::ParseIcmpError(err)
    }
}

impl<'a> IcmpPacket<'a> {
    /// Create a new ICMP packet from raw data.
    #[must_use]
    pub const fn new(raw: &'a [u8]) -> Result<Self, ParseIcmpError> {
        Ok(Self { data: raw, raw })
    }
}

impl Protocol for IcmpPacket<'_> {
    const PROTOCOL: u8 = 0x01;
}

impl fmt::Display for IcmpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ICMP Packet, {} bytes", self.data.len())
    }
}
