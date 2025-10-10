//! ARP packet parsing.
// https://en.wikipedia.org/wiki/Address_Resolution_Protocol
// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml

use std::{fmt, net::Ipv4Addr};
use num_enum::FromPrimitive;
use super::MacAddress;

/// An ARP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    /// Hardware type.
    pub hardware_type: HardwareType,
    /// Protocol type.
    pub protocol_type: ProtocolType,
    /// Hardware length.
    pub hardware_length: u8,
    /// Protocol length.
    pub protocol_length: u8,
    /// Operation.
    pub operation: ArpOperation,
    /// Sender MAC address.
    pub sender_mac: MacAddress,
    /// Sender IP address.
    pub sender_ip: Ipv4Addr,
    /// Target MAC address.
    pub target_mac: MacAddress,
    /// Target IP address.
    pub target_ip: Ipv4Addr,
}

/// Available hardware types.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum HardwareType {
    Reserved = 0,
    Ethernet = 1,
    IEEE802Networks = 6,
    #[num_enum(catch_all)]
    Unknown(u16),
}

/// Available protocol types.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum ProtocolType {
    IPv4 = 0x0800,
    // The following should not happen
    // ARP = 0x0806,
    // RARP = 0x8035,
    // IPv6 = 0x86DD,
    #[num_enum(catch_all)]
    Unknown(u16),
}

/// Available operation codes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum ArpOperation {
    Request = 1,
    Reply = 2,
    #[num_enum(catch_all)]
    Unknown(u16),
}

impl ArpPacket {
    /// Create a new ARP packet from raw data.
    pub fn new(raw_data: &[u8]) -> Self {
        // todo!("Implement ARP packet parsing");
        let hardware_type = u16::from_be_bytes([raw_data[0], raw_data[1]]);
        let hardware_type = HardwareType::from(hardware_type);
        let protocol_type = u16::from_be_bytes([raw_data[2], raw_data[3]]);
        let protocol_type = ProtocolType::from(protocol_type);

        let hardware_length = raw_data[4];
        let protocol_length = raw_data[5];
        let opcode = u16::from_be_bytes([raw_data[6], raw_data[7]]);
        let operation = ArpOperation::from(opcode);

        let sender_mac = MacAddress([raw_data[8], raw_data[9], raw_data[10], raw_data[11], raw_data[12], raw_data[13]]);
        let sender_ip = Ipv4Addr::new(raw_data[14], raw_data[15], raw_data[16], raw_data[17]);
        let target_mac = MacAddress([raw_data[18], raw_data[19], raw_data[20], raw_data[21], raw_data[22], raw_data[23]]);
        let target_ip = Ipv4Addr::new(raw_data[24], raw_data[25], raw_data[26], raw_data[27]);
        ArpPacket {
            hardware_type,
            protocol_type,
            hardware_length,
            protocol_length,
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }
}

impl fmt::Display for ArpPacket {
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
            HardwareType::Reserved => write!(f, "Reserved"),
            HardwareType::Ethernet => write!(f, "Ethernet"),
            HardwareType::IEEE802Networks => write!(f, "IEEE 802 Networks"),
            HardwareType::Unknown(val) => write!(f, "Unknown (0x{val:04x})"),
        }
    }
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolType::IPv4 => write!(f, "IPv4"),
            ProtocolType::Unknown(val) => write!(f, "Unknown (0x{val:04x})"),
        }
    }
}

impl fmt::Display for ArpOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpOperation::Request => write!(f, "Request"),
            ArpOperation::Reply => write!(f, "Reply"),
            ArpOperation::Unknown(val) => write!(f, "Unknown (0x{val:04x})"),
        }
    }
}
