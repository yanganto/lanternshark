//! IPv4 packet parsing.
// https://www.wikiwand.com/en/articles/IPv4

pub mod icmp;
pub mod tcp;
pub mod udp;

use std::{fmt, net::Ipv4Addr};
use super::EtherType;
use super::packet_detail::PacketDetail;
use icmp::{IcmpPacket, ParseIcmpError};
use tcp::{TcpPacket, ParseTcpError};
use udp::{UdpPacket, ParseUdpError};

/// An IPv4 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    /// Version of IP. 4 bits. Should always be 4 for IPv4.
    pub version: u8,
    /// Internet Header length. 4 bits.
    pub header_length: u8,
    /// Differentiated Services Field.
    pub dsf: Ipv4PacketDsf,
    /// Total Length.
    pub total_length: u16,
    /// Identification.
    pub identification: u16,
    /// Flags. 3 bits.
    pub flags: Ipv4PacketFlags,
    /// Fragment Offset. 13 bits.
    pub fragment_offset: u16,
    /// Time to Live.
    pub ttl: u8,
    /// The inner packet. Type is determined by the protocol field (8 bits).
    pub inner: Ipv4PacketInner<'a>,
    /// Header Checksum.
    pub header_checksum: u16,
    /// Source IP address.
    pub source: Ipv4Addr,
    /// Destination IP address.
    pub destination: Ipv4Addr,
    /// Options.
    pub options: &'a [u8],
    /// The raw data field of the packet.
    pub data: &'a [u8],
    /// The raw IPv4 packet.
    pub raw: &'a [u8],
}

/// A IPv4 packet of unknown or unsupported protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownIpv4Packet<'a> {
    /// The raw protocol of the IPv4 packet.
    pub protocol: u8,
    /// The raw data field of the IPv4 packet.
    pub data: &'a [u8],
}

/// Differentiated Services Field (DSF) in an IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4PacketDsf {
    /// Differentiated Services Code Point (DSCP). 6 bits.
    pub dscp: u8,
    /// Explicit Congestion Notification (ECN). 2 bits.
    pub ecn: u8,
}

/// Flags in an IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4PacketFlags {
    /// Reserved; must be zero.
    pub reserved: bool,
    /// Don't Fragment.
    pub dont_fragment: bool,
    /// More Fragments.
    pub more_fragments: bool,
}

/// Trait requiring associated const PROTOCOL for packet types.
pub trait Protocol {
    /// The Protocol value associated with the packet type.
    const PROTOCOL: u8;
}

/// Available inner packet types for IPv4 packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4PacketInner<'a> {
    /// Internet Control Message Protocol (0x01)
    Icmp(IcmpPacket<'a>),
    /// Transmission Control Protocol (0x06)
    Tcp(TcpPacket<'a>),
    /// User Datagram Protocol (0x11)
    Udp(UdpPacket<'a>),
    /// Unknown or unsupported protocol
    Unknown(UnknownIpv4Packet<'a>),
    // Add more protocols here as needed
}

impl Ipv4PacketInner<'_> {
    /// Get the protocol number.
    pub const fn protocol_number(&self) -> u8 {
        match self {
            Self::Icmp(_) => IcmpPacket::PROTOCOL,
            Self::Tcp(_) => TcpPacket::PROTOCOL,
            Self::Udp(_) => UdpPacket::PROTOCOL,
            Self::Unknown(u) => u.protocol,
        }
    }

    /// Get the protocol slug.
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::Icmp(_) => "ICMP",
            Self::Tcp(_) => "TCP",
            Self::Udp(_) => "UDP",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// Possible errors when parsing an IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIpv4Error {
    /// The packet is too short to be a valid IPv4 packet, or shorter than the indicated header length.
    PacketTooShort,
    /// The header length is less than the minimum of 5 (20 bytes).
    HeaderLengthTooShort,
    /// The version is not 4.
    InvalidVersion,
    /// Error parsing inner ICMP packet.
    ParseIcmpError(ParseIcmpError),
    /// Error parsing inner TCP packet.
    ParseTcpError(ParseTcpError),
    /// Error parsing inner UDP packet.
    ParseUdpError(ParseUdpError),

}

impl<'a> Ipv4Packet<'a> {
    /// Create a new IPv4 packet from raw data.
    ///
    /// # Errors
    ///
    /// See [`ParseIpv4Error`].
    pub fn new(raw: &'a [u8]) -> Result<Self, ParseIpv4Error> {
        if raw.len() < 20 {
            return Err(ParseIpv4Error::PacketTooShort);
        }

        let (header, options_and_data) = raw.split_at(20);
        let version_and_ihl = header[0];
        let version = version_and_ihl >> 4;
        if version != 4 {
            return Err(ParseIpv4Error::InvalidVersion);
        }
        let header_length = version_and_ihl & 0x0F;
        if header_length < 5 {
            return Err(ParseIpv4Error::HeaderLengthTooShort);
        }
        let header_length_bytes = (header_length * 4) as usize;
        if raw.len() < header_length_bytes {
            return Err(ParseIpv4Error::PacketTooShort);
        }
        let dsf = Ipv4PacketDsf::new(header[1]);
        let total_length = u16::from_be_bytes([header[2], header[3]]);
        let identification = u16::from_be_bytes([header[4], header[5]]);
        let flags_and_fragment_offset = u16::from_be_bytes([header[6], header[7]]);
        let flags = Ipv4PacketFlags::new((flags_and_fragment_offset >> 13) as u8);
        let fragment_offset = flags_and_fragment_offset & 0x1FFF;
        let ttl = header[8];
        let protocol = header[9];
        let header_checksum = u16::from_be_bytes([header[10], header[11]]);
        let source = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
        let destination = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
        let (options, data) = options_and_data.split_at(header_length_bytes - 20);

        let inner = match protocol {
            IcmpPacket::PROTOCOL => Ipv4PacketInner::Icmp(IcmpPacket::new(data)?),
            TcpPacket::PROTOCOL => Ipv4PacketInner::Tcp(TcpPacket::new(data)?),
            UdpPacket::PROTOCOL => Ipv4PacketInner::Udp(UdpPacket::new(data)?),
            _ => Ipv4PacketInner::Unknown(UnknownIpv4Packet { protocol, data }),
        };

        Ok(Self {
            version,
            header_length,
            dsf,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            inner,
            header_checksum,
            source,
            destination,
            options,
            data,
            raw,
        })
    }
}

impl EtherType for Ipv4Packet<'_> {
    const ETHER_TYPE: u16 = 0x0800;
}

impl fmt::Display for Ipv4Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            total_length,
            identification,
            ttl,
            inner,
            header_checksum,
            source,
            destination,
            ..
        } = self;
        write!(
            f,
            "IPv4 Packet: {source} -> {destination}, ID {identification:#06x}, TTL {ttl}, Header Checksum {header_checksum:#06x}, Total Length {total_length}\n{inner}",
        )
    }
}

impl fmt::Display for Ipv4PacketInner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp(icmp) => icmp.fmt(f),
            Self::Tcp(tcp) => tcp.fmt(f),
            Self::Udp(udp) => udp.fmt(f),
            Self::Unknown(unknown) => unknown.fmt(f),
        }
    }
}

impl fmt::Display for UnknownIpv4Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Unknown Protocol (0x{:02x}): {} bytes",
            self.protocol,
            self.data.len()
        )
    }
}

impl Ipv4PacketDsf {
    /// Create a new Differentiated Services Field from a byte.
    pub const fn new(byte: u8) -> Self {
        Self {
            dscp: byte >> 2,
            ecn: byte & 0x03,
        }
    }
}

impl Ipv4PacketFlags {
    /// Create new IPv4 packet flags from a 3-bit value.
    pub const fn new(bits: u8) -> Self {
        Self {
            reserved: (bits & 0b100) != 0,
            dont_fragment: (bits & 0b010) != 0,
            more_fragments: (bits & 0b001) != 0,
        }
    }
}

impl PacketDetail for Ipv4Packet<'_> {
    fn summary(&self) -> String {
        format!("Len: {}, TTL: {}", self.total_length, self.ttl)
    }

    fn details(&self) -> Vec<String> {
        vec![
            format!("Version: {}", self.version),
            format!("Header Length: {} bytes ({})", self.header_length * 4, self.header_length),
            format!("DSCP: {}, ECN: {}", self.dsf.dscp, self.dsf.ecn),
            format!("Total Length: {}", self.total_length),
            format!("Identification: 0x{:04x}", self.identification),
            format!("Flags: DF={}, MF={}", self.flags.dont_fragment as u8, self.flags.more_fragments as u8),
            format!("Fragment Offset: {}", self.fragment_offset),
            format!("Time to Live: {}", self.ttl),
            format!("Protocol: {} ({})", self.inner.slug(), self.inner.protocol_number()),
            format!("Header Checksum: 0x{:04x}", self.header_checksum),
            format!("Source: {}", self.source),
            format!("Destination: {}", self.destination),
        ]
    }

    fn slug(&self) -> &'static str {
        "IPV4"
    }

    fn name(&self) -> &'static str {
        "Internet Protocol Version 4"
    }

    fn source(&self) -> String {
        self.source.to_string()
    }

    fn destination(&self) -> String {
        self.destination.to_string()
    }

    fn length(&self) -> usize {
        self.raw.len()
    }

    fn inner(&self) -> Option<&dyn PacketDetail> {
        match &self.inner {
            Ipv4PacketInner::Icmp(icmp) => Some(icmp),
            Ipv4PacketInner::Tcp(tcp) => Some(tcp),
            Ipv4PacketInner::Udp(udp) => Some(udp),
            Ipv4PacketInner::Unknown(_) => None,
        }
    }
}

impl From<ParseIpv4Error> for super::ParseEthernetError {
    fn from(err: ParseIpv4Error) -> Self {
        Self::ParseIpv4Error(err)
    }
}
