//! IPv4 packet parsing.
// https://www.wikiwand.com/en/articles/IPv4

use std::{fmt, net::Ipv4Addr};

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

/// Available inner packet types for IPv4 packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4PacketInner<'a> {
    // TODO: Add protocols
    /// Unknown or unsupported protocol
    Unknown(UnknownIpv4Packet<'a>),
}

/// Possible errors when parsing an IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4PacketError {
    /// The packet is too short to be a valid IPv4 packet, or shorter than the indicated header length.
    PacketTooShort,
    /// The header length is less than the minimum of 5 (20 bytes).
    HeaderLengthTooShort,
    /// The version is not 4.
    InvalidVersion,
}

impl<'a> Ipv4Packet<'a> {
    /// Create a new IPv4 packet from raw data.
    pub fn new(raw: &'a [u8]) -> Result<Self, Ipv4PacketError> {
        if raw.len() < 20 {
            return Err(Ipv4PacketError::PacketTooShort);
        }

        let (header, options_and_data) = raw.split_at(20);
        let version_and_ihl = header[0];
        let version = version_and_ihl >> 4;
        if version != 4 {
            return Err(Ipv4PacketError::InvalidVersion);
        }
        let header_length = version_and_ihl & 0x0F;
        if header_length < 5 {
            return Err(Ipv4PacketError::HeaderLengthTooShort);
        }
        let header_length_bytes = (header_length * 4) as usize;
        if raw.len() < header_length_bytes {
            return Err(Ipv4PacketError::PacketTooShort);
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
            _ => Ipv4PacketInner::Unknown(UnknownIpv4Packet {
                protocol,
                data,
            }),
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

impl<'a> fmt::Display for Ipv4Packet<'a> {
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

impl<'a> fmt::Display for Ipv4PacketInner<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ipv4PacketInner::Unknown(packet) => write!(f, "{packet}"),
        }
    }
}

impl fmt::Display for UnknownIpv4Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown Protocol (0x{:02x}): {} bytes", self.protocol, self.data.len())
    }
}

impl Ipv4PacketDsf {
    /// Create a new Differentiated Services Field from a byte.
    pub fn new(byte: u8) -> Self {
        Self {
            dscp: byte >> 2,
            ecn: byte & 0x03,
        }
    }
}

impl Ipv4PacketFlags {
    /// Create new IPv4 packet flags from a 3-bit value.
    pub fn new(bits: u8) -> Self {
        Self {
            reserved: (bits & 0b100) != 0,
            dont_fragment: (bits & 0b010) != 0,
            more_fragments: (bits & 0b001) != 0,
        }
    }
}

impl From<Ipv4PacketError> for super::ParseEthernetError {
    fn from(err: Ipv4PacketError) -> Self {
        Self::Ipv4PacketError(err)
    }
}
