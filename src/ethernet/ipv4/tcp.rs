//! TCP packet parsing.

use std::fmt;
use super::{Protocol, ParseIpv4Error};
use crate::ethernet::packet_detail::PacketDetail;

/// A TCP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpPacket<'a> {
    // TODO: Complete the fields.
    /// The raw data field of the TCP packet.
    pub data: &'a [u8],
    /// The raw TCP packet.
    pub raw: &'a [u8],
}

/// Possible errors when parsing a TCP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseTcpError {}

impl From<ParseTcpError> for ParseIpv4Error {
    fn from(err: ParseTcpError) -> Self {
        Self::ParseTcpError(err)
    }
}

impl<'a> TcpPacket<'a> {
    /// Create a new TCP packet from raw data.
    #[must_use]
    pub const fn new(raw: &'a [u8]) -> Result<Self, ParseTcpError> {
        Ok(Self { data: raw, raw })
    }
}

impl Protocol for TcpPacket<'_> {
    const PROTOCOL: u8 = 0x06;
}

impl fmt::Display for TcpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP Packet, {} bytes", self.data.len())
    }
}

impl PacketDetail for TcpPacket<'_> {
    fn summary(&self) -> String {
        format!("{} bytes", self.data.len())
    }

    fn details(&self) -> Vec<String> {
        vec![
            "TCP parsing not yet fully implemented".to_string(),
            format!("Data Length: {} bytes", self.data.len()),
        ]
    }

    fn slug(&self) -> &'static str {
        "TCP"
    }

    fn name(&self) -> &'static str {
        "Transmission Control Protocol"
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}
