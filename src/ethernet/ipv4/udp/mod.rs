//! UDP packet parsing.

pub mod dns;

use super::{PacketDetail, ParseIpv4Error, Protocol};
use dns::{DnsPacket, ParseDnsError};
use std::fmt;

/// A UDP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dest_port: u16,
    /// Length of the UDP packet including header and data.
    pub length: u16,
    /// Checksum of the UDP packet.
    pub checksum: u16,
    /// The inner packet.
    pub inner: UdpPacketInner<'a>,
    /// The raw data field or leftover data of the UDP packet.
    pub data: &'a [u8],
    /// The raw UDP packet.
    pub raw: &'a [u8],
}

/// Available inner packet types for UDP packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpPacketInner<'a> {
    /// DNS packet.
    Dns(DnsPacket<'a>),
    /// Unknown or unsupported inner packet type.
    Unknown(UnknownUdpPacket<'a>),
}

/// A UDP packet of unknown or unsupported protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownUdpPacket<'a> {
    /// The raw data field or leftover data of the UDP packet.
    pub data: &'a [u8],
}

/// Possible errors when parsing a UDP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseUdpError {
    /// The packet is too short to be a valid UDP packet.
    PacketTooShort,
    /// Error parsing inner DNS packet.
    ParseDnsError(ParseDnsError),
}

impl From<ParseUdpError> for ParseIpv4Error {
    fn from(err: ParseUdpError) -> Self {
        Self::ParseUdpError(err)
    }
}

impl<'a> UdpPacket<'a> {
    /// Create a new UDP packet from raw data.
    ///
    /// # Errors
    ///
    /// See [`ParseUdpError`].
    pub fn new(raw: &'a [u8]) -> Result<Self, ParseUdpError> {
        if raw.len() < 8 {
            return Err(ParseUdpError::PacketTooShort);
        }
        let (header, data) = raw.split_at(8);
        let src_port = u16::from_be_bytes([header[0], header[1]]);
        let dest_port = u16::from_be_bytes([header[2], header[3]]);
        let length = u16::from_be_bytes([header[4], header[5]]);
        let checksum = u16::from_be_bytes([header[6], header[7]]);
        let inner = if src_port == 53 || dest_port == 53 {
            match DnsPacket::new(data) {
                Ok(dns) => UdpPacketInner::Dns(dns),
                Err(e) => return Err(ParseUdpError::ParseDnsError(e)),
            }
        } else {
            UdpPacketInner::Unknown(UnknownUdpPacket { data })
        };

        Ok(Self {
            src_port,
            dest_port,
            length,
            checksum,
            inner,
            data,
            raw,
        })
    }
}

impl Protocol for UdpPacket<'_> {
    const PROTOCOL: u8 = 0x11;
}

impl fmt::Display for UdpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            src_port,
            dest_port,
            data,
            ..
        } = self;
        write!(
            f,
            "UDP: {} bytes from :{src_port} to :{dest_port}",
            data.len()
        )
    }
}

impl PacketDetail for UdpPacket<'_> {
    fn summary(&self) -> String {
        let Self {
            src_port,
            dest_port,
            data,
            ..
        } = self;
        format!("{} bytes from :{src_port} to :{dest_port}", data.len())
    }

    fn details(&self) -> Vec<String> {
        vec![
            format!("Source Port: {}", self.src_port),
            format!("Destination Port: {}", self.dest_port),
            format!("Length: {}", self.length),
            format!("Checksum: 0x{:04x}", self.checksum),
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

    fn inner(&self) -> Option<&dyn PacketDetail> {
        match &self.inner {
            UdpPacketInner::Dns(dns) => Some(dns),
            UdpPacketInner::Unknown(_) => None,
        }
    }
}
