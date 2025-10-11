//! UDP packet parsing.

use std::fmt;
use super::{Protocol, ParseIpv4Error, PacketDetail};

/// A UDP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket<'a> {
    // TODO: Complete the fields.
    /// The raw data field of the UDP packet.
    pub data: &'a [u8],
    /// The raw UDP packet.
    pub raw: &'a [u8],
}

/// Possible errors when parsing a UDP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseUdpError {}

impl From<ParseUdpError> for ParseIpv4Error {
    fn from(err: ParseUdpError) -> Self {
        Self::ParseUdpError(err)
    }
}

impl<'a> UdpPacket<'a> {
    /// Create a new UDP packet from raw data.
    #[must_use]
    pub const fn new(raw: &'a [u8]) -> Result<Self, ParseUdpError> {
        Ok(Self { data: raw, raw })
    }
}

impl Protocol for UdpPacket<'_> {
    const PROTOCOL: u8 = 0x11;
}

impl fmt::Display for UdpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UDP Packet, {} bytes", self.data.len())
    }
}

impl PacketDetail for UdpPacket<'_> {
    fn summary(&self) -> String {
        format!("{} bytes", self.data.len())
    }

    fn details(&self) -> Vec<String> {
        vec![
            "UDP parsing not yet fully implemented".to_string(),
            format!("Data Length: {} bytes", self.data.len()),
        ]
    }

    fn slug(&self) -> &'static str {
        "UDP"
    }

    fn name(&self) -> &'static str {
        "User Datagram Protocol"
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}
