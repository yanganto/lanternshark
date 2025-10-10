//! ARP packet parsing.
// https://www.wikiwand.com/en/articles/Address_Resolution_Protocol
// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml

use super::MacAddress;
use num_enum::FromPrimitive;
use std::{fmt, net::Ipv4Addr};

/// An ARP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket<'a> {
    /// Hardware type. 16 bits.
    pub hardware_type: HardwareType,
    /// Protocol type. 16 bits.
    pub protocol_type: ProtocolType,
    /// Hardware length.
    pub hardware_length: u8,
    /// Protocol length.
    pub protocol_length: u8,
    /// Operation. 16 bits.
    pub operation: ArpOperation,
    /// Sender MAC address. 48 bits.
    pub sender_mac: MacAddress,
    /// Sender IP address. 32 bits.
    pub sender_ip: Ipv4Addr,
    /// Target MAC address. 48 bits.
    pub target_mac: MacAddress,
    /// Target IP address. 32 bits.
    pub target_ip: Ipv4Addr,
    /// The raw ARP packet.
    pub raw: &'a [u8],
}

/// Available hardware types.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum HardwareType {
    /// Reserved.
    Reserved = 0,
    /// Ethernet (10Mb).
    Ethernet = 1,
    /// IEEE 802 Networks.
    IEEE802Networks = 6,
    /// Unknown or unsupported hardware type.
    #[num_enum(catch_all)]
    Unknown(u16),
}

/// Available protocol types.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum ProtocolType {
    /// Internet Protocol version 4 (IPv4)
    IPv4 = 0x0800,
    // The following should not happen
    // ARP = 0x0806,
    // RARP = 0x8035,
    // IPv6 = 0x86DD,
    /// Unknown or unsupported protocol type.
    #[num_enum(catch_all)]
    Unknown(u16),
}

/// Available operation codes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum ArpOperation {
    /// ARP Request
    Request = 1,
    /// ARP Reply
    Reply = 2,
    /// Unknown or unsupported operation code.
    #[num_enum(catch_all)]
    Unknown(u16),
}

/// Possible errors when parsing an ARP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpPacketError {
    /// The packet length is not 28 bytes.
    PacketLengthInvalid(usize),
}

impl<'a> ArpPacket<'a> {
    /// Create a new ARP packet from raw data.
    ///
    /// # Errors
    ///
    /// See [`ArpPacketError`].
    pub fn new(raw: &'a [u8]) -> Result<Self, ArpPacketError> {
        if raw.len() != 28 {
            return Err(ArpPacketError::PacketLengthInvalid(raw.len()));
        }
        let hardware_type = u16::from_be_bytes([raw[0], raw[1]]);
        let hardware_type = HardwareType::from(hardware_type);
        let protocol_type = u16::from_be_bytes([raw[2], raw[3]]);
        let protocol_type = ProtocolType::from(protocol_type);

        let hardware_length = raw[4];
        let protocol_length = raw[5];
        let opcode = u16::from_be_bytes([raw[6], raw[7]]);
        let operation = ArpOperation::from(opcode);

        let sender_mac = MacAddress([raw[8], raw[9], raw[10], raw[11], raw[12], raw[13]]);
        let sender_ip = Ipv4Addr::new(raw[14], raw[15], raw[16], raw[17]);
        let target_mac = MacAddress([raw[18], raw[19], raw[20], raw[21], raw[22], raw[23]]);
        let target_ip = Ipv4Addr::new(raw[24], raw[25], raw[26], raw[27]);
        Ok(ArpPacket {
            hardware_type,
            protocol_type,
            hardware_length,
            protocol_length,
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
            raw,
        })
    }
}

impl From<ArpPacketError> for super::ParseEthernetError {
    fn from(err: ArpPacketError) -> Self {
        Self::ArpPacketError(err)
    }
}

impl fmt::Display for ArpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            hardware_type,
            protocol_type,
            hardware_length,
            protocol_length,
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
            raw: _,
        } = self;
        write!(
            f,
            "ARP: {operation}, {sender_ip} ({sender_mac}) -> {target_ip} ({target_mac}) [hw_type: {hardware_type}, proto_type: {protocol_type}, hw_len: {hardware_length}, proto_len: {protocol_length}]",
        )
    }
}

impl fmt::Display for HardwareType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reserved => write!(f, "Reserved"),
            Self::Ethernet => write!(f, "Ethernet"),
            Self::IEEE802Networks => write!(f, "IEEE 802 Networks"),
            Self::Unknown(val) => write!(f, "Unknown (0x{val:04x})"),
        }
    }
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IPv4 => write!(f, "IPv4"),
            Self::Unknown(val) => write!(f, "Unknown (0x{val:04x})"),
        }
    }
}

impl fmt::Display for ArpOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request => write!(f, "Request"),
            Self::Reply => write!(f, "Reply"),
            Self::Unknown(val) => write!(f, "Unknown (0x{val:04x})"),
        }
    }
}
