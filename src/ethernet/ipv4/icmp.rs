//! ICMP packet parsing.
// https://www.wikiwand.com/en/articles/Internet_Control_Message_Protocol

use super::{PacketDetail, ParseIpv4Error, Protocol};
use num_enum::{FromPrimitive, IntoPrimitive};
use std::fmt;

/// An ICMP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpPacket<'a> {
    /// The type of the ICMP packet. 8 bits.
    pub icmp_type: IcmpType,
    /// Code of the ICMP packet.
    pub code: u8,
    /// Checksum of the ICMP packet.
    pub checksum: u16,
    /// The rest of the header (varies by type and code).
    pub rest_of_header: u32,
    /// The raw data field or leftover data of the ICMP packet.
    pub data: &'a [u8],
    /// The raw ICMP packet.
    pub raw: &'a [u8],
}

/// Available ICMP types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
pub enum IcmpType {
    /// Echo Reply
    EchoReply = 0,
    /// Destination Unreachable
    DestinationUnreachable = 3,
    /// Echo Request
    EchoRequest = 8,
    /// Time Exceeded
    TimeExceeded = 11,
    /// Parameter Problem
    ParameterProblem = 12,
    /// Unknown or unsupported ICMP type.
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// Possible errors when parsing a ICMP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIcmpError {
    /// The packet length is less than 8 bytes.
    PacketTooShort(usize),
}

impl From<ParseIcmpError> for ParseIpv4Error {
    fn from(err: ParseIcmpError) -> Self {
        Self::ParseIcmpError(err)
    }
}

impl<'a> IcmpPacket<'a> {
    /// Create a new ICMP packet from raw data.
    ///
    /// # Errors
    ///
    /// See [`ParseIcmpError`].
    pub fn new(raw: &'a [u8]) -> Result<Self, ParseIcmpError> {
        if raw.len() < 8 {
            // ICMP header is at least 8 bytes
            return Err(ParseIcmpError::PacketTooShort(raw.len()));
        }
        let (header, data) = raw.split_at(8);
        let (first_header, rest_of_header) = header.split_at(4);
        let icmp_type = IcmpType::from(first_header[0]);
        let code = first_header[1];
        let checksum = u16::from_be_bytes([first_header[2], first_header[3]]);
        let rest_of_header = u32::from_be_bytes([
            rest_of_header[0],
            rest_of_header[1],
            rest_of_header[2],
            rest_of_header[3],
        ]);

        Ok(Self {
            icmp_type,
            code,
            checksum,
            rest_of_header,
            data,
            raw,
        })
    }
}

impl Protocol for IcmpPacket<'_> {
    const PROTOCOL: u8 = 0x01;
}

impl fmt::Display for IcmpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            icmp_type,
            code,
            checksum,
            data,
            ..
        } = self;
        write!(
            f,
            "ICMP: {icmp_type} ({code}), checksum {checksum}, data {} bytes",
            data.len()
        )
    }
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EchoReply => write!(f, "Echo Reply"),
            Self::DestinationUnreachable => write!(f, "Destination Unreachable"),
            Self::EchoRequest => write!(f, "Echo Request"),
            Self::TimeExceeded => write!(f, "Time Exceeded"),
            Self::ParameterProblem => write!(f, "Parameter Problem"),
            Self::Unknown(t) => write!(f, "Unknown (0x{t:02x})"),
        }
    }
}

impl PacketDetail for IcmpPacket<'_> {
    fn summary(&self) -> String {
        format!("{} (Code: {})", self.icmp_type, self.code)
    }

    fn details(&self) -> Vec<String> {
        let type_num: u8 = self.icmp_type.into();
        vec![
            format!("Type: {} ({type_num})", self.icmp_type),
            format!("Code: {}", self.code),
            format!("Checksum: 0x{:04x}", self.checksum),
            format!("Rest of Header: 0x{:08x}", self.rest_of_header),
            format!("Data Length: {} bytes", self.data.len()),
        ]
    }

    fn slug(&self) -> &'static str {
        "ICMP"
    }

    fn name(&self) -> &'static str {
        "Internet Control Message Protocol"
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}
