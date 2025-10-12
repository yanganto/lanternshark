//! IGMP packet parsing.
// https://en.wikipedia.org/w/index.php?title=Internet_Group_Management_Protocol&oldid=109330277#IGMP_version_2.

use num_enum::{FromPrimitive, IntoPrimitive};
use std::{fmt, net::Ipv4Addr};
use super::{Protocol, ParseIpv4Error, PacketDetail};

/// An IGMP packet. (Version 2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpPacket<'a> {
    /// The type of the IGMP packet. 8 bits.
    pub igmp_type: IgmpType,
    /// Maximum response time in 1/10 second units.
    pub max_response_time: u8,
    /// Checksum of the IGMP packet.
    pub checksum: u16,
    /// Group address. 32 bits.
    pub group_address: Ipv4Addr,
    /// The raw data field or leftover data of the IGMP packet.
    pub data: &'a [u8],
    /// The raw IGMP packet.
    pub raw: &'a [u8],
}

/// Available IGMP types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
pub enum IgmpType {
    /// Group Membership Query
    MembershipQuery = 0x11,
    /// Membership Report Version 1
    MembershipReportV1 = 0x12,
    /// Membership Report Version 2
    MembershipReportV2 = 0x16,
    /// Leave Group
    LeaveGroup = 0x17,
    // Multicast Router * not supported yet
    /// Unknown or unsupported IGMP type.
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// Possible errors when parsing a IGMP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIgmpError {
    /// The packet length is less than 8 bytes.
    PacketTooShort(usize),
}

impl From<ParseIgmpError> for ParseIpv4Error {
    fn from(err: ParseIgmpError) -> Self {
        Self::ParseIgmpError(err)
    }
}

impl<'a> IgmpPacket<'a> {
    /// Create a new IGMP packet from raw data.
    ///
    /// # Errors
    ///
    /// See [`ParseIgmpError`].
    #[must_use]
    pub fn new(raw: &'a [u8]) -> Result<Self, ParseIgmpError> {
        if raw.len() < 8 {
            // An IGMP packet should be at least 8 bytes long.
            return Err(ParseIgmpError::PacketTooShort(raw.len()));
        }
        let (header, data) = raw.split_at(8);
        let igmp_type = IgmpType::from(header[0]);
        let max_response_time = header[1];
        let checksum = u16::from_be_bytes([header[2], header[3]]);
        let group_address = Ipv4Addr::new(header[4], header[5], header[6], header[7]);

        Ok(Self {
            igmp_type,
            max_response_time,
            checksum,
            group_address,
            data,
            raw,
        })
    }
}

impl Protocol for IgmpPacket<'_> {
    const PROTOCOL: u8 = 0x02;
}

impl fmt::Display for IgmpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            data,
            ..
        } = self;
        write!(f, "IGMP: {} bytes", data.len())
    }
}

impl fmt::Display for IgmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MembershipQuery => write!(f, "Membership Query"),
            Self::MembershipReportV1 => write!(f, "Membership Report V1"),
            Self::MembershipReportV2 => write!(f, "Membership Report V2"),
            Self::LeaveGroup => write!(f, "Leave Group"),
            Self::Unknown(t) => write!(f, "Unknown (0x{t:02x})"),
        }
    }
}

impl PacketDetail for IgmpPacket<'_> {
    fn summary(&self) -> String {
        let Self {
            igmp_type,
            group_address,
            ..
        } = self;
        let group_info = if *group_address == Ipv4Addr::UNSPECIFIED {
            "general".to_string()
        } else {
            format!("group {}", group_address)
        };
        format!("{igmp_type}, {group_info}")
    }

    fn details(&self) -> Vec<String> {
        let type_num: u8 = self.igmp_type.into();
        vec![
            format!("Type: {} ({type_num})", self.igmp_type),
            format!("Max Response Time: {} (1/10 second units)", self.max_response_time),
            format!("Checksum: 0x{:04x}", self.checksum),
            format!("Group Address: {}", self.group_address),
            format!("Data Length: {} bytes", self.data.len()),
        ]
    }

    fn slug(&self) -> &'static str {
        "IGMP"
    }

    fn name(&self) -> &'static str {
        "Internet Group Management Protocol"
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}
