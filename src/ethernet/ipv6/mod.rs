//! IPv6 packet parsing.
// https://www.wikiwand.com/en/articles/IPv6

use std::{fmt, net::Ipv6Addr};
use super::{EtherType, PacketDetail};

/// An IPv6 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet<'a> {
    /// Version of IP. 4 bits. Should always be 6 for IPv6.
    pub version: u8,
    /// Traffic Class.
    pub traffic_class: u8,
    /// Flow Label. 20 bits.
    pub flow_label: u32,
    /// Payload Length in bytes.
    pub payload_length: u16,
    /// Next Header.
    pub next_header: u8,
    /// Hop Limit.
    pub hop_limit: u8,
    /// Source IP address. 128 bits.
    pub source: Ipv6Addr,
    /// Destination IP address. 128 bits.
    pub destination: Ipv6Addr,
    /// The raw data field of the IPv6 packet.
    pub data: &'a [u8],
    /// The raw IPv6 packet.
    pub raw: &'a [u8],
}

/// Possible errors when parsing an IPv6 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIpv6Error {
    /// The packet is too short to be a valid IPv6 packet.
    PacketTooShort,
    /// The version field is not 6.
    InvalidVersion,
}

impl<'a> Ipv6Packet<'a> {
    /// Create a new IPv6 packet from raw data.
    #[must_use]
    pub fn new(raw: &'a [u8]) -> Result<Self, ParseIpv6Error> {
        if raw.len() < 40 {
            return Err(ParseIpv6Error::PacketTooShort);
        }
        let (header, data) = raw.split_at(40);
        let version = header[0] >> 4;
        if version != 6 {
            return Err(ParseIpv6Error::InvalidVersion);
        }
        let traffic_class = ((header[0] & 0x0F) << 4) | (header[1] >> 4);
        let flow_label = ((header[1] as u32 & 0x0F) << 16)
            | ((header[2] as u32) << 8)
            | (header[3] as u32);
        let payload_length = u16::from_be_bytes([header[4], header[5]]);
        let next_header = header[6];
        let hop_limit = header[7];
        let source = Ipv6Addr::from([
            header[8], header[9], header[10], header[11], header[12], header[13], header[14],
            header[15], header[16], header[17], header[18], header[19], header[20], header[21],
            header[22], header[23],
        ]);
        let destination = Ipv6Addr::from([
            header[24], header[25], header[26], header[27], header[28], header[29], header[30],
            header[31], header[32], header[33], header[34], header[35], header[36], header[37],
            header[38], header[39],
        ]);
        Ok(Self {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            source,
            destination,
            data,
            raw,
        })
    }
}

impl EtherType for Ipv6Packet<'_> {
    const ETHER_TYPE: u16 = 0x86DD;
}

impl fmt::Display for Ipv6Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            flow_label,
            payload_length,
            hop_limit,
            source,
            destination,
            ..
        } = self;
        write!(f, "IPv6: {source} -> {destination}, Flow Label {flow_label:#06x}, Hop Limit {hop_limit}, Payload Length {payload_length}")
    }
}

impl PacketDetail for Ipv6Packet<'_> {
    fn summary(&self) -> String {
        let Self { payload_length, flow_label, hop_limit, .. } = self;
        format!("Flow Label {flow_label:#06x}, Hop Limit {hop_limit}, Payload Length {payload_length}")
    }

    fn details(&self) -> Vec<String> {
        vec![
            format!("Version: {}", self.version),
            format!("Traffic Class: {:#04x}", self.traffic_class),
            format!("Flow Label: {:#06x}", self.flow_label),
            format!("Payload Length: {}", self.payload_length),
            format!("Next Header: {:#04x}", self.next_header),
            format!("Hop Limit: {}", self.hop_limit),
            format!("Source Address: {}", self.source),
            format!("Destination Address: {}", self.destination),
            format!("Data Length: {} bytes", self.data.len()),
            format!("Total Length: {} bytes", self.raw.len()),
        ]
    }

    fn slug(&self) -> &'static str {
        "IPV6"
    }

    fn name(&self) -> &'static str {
        "Internet Protocol Version 6"
    }

    fn source(&self) -> Option<String> {
        Some(self.source.to_string())
    }

    fn destination(&self) -> Option<String> {
        Some(self.destination.to_string())
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}

impl From<ParseIpv6Error> for super::ParseEthernetError {
    fn from(err: ParseIpv6Error) -> Self {
        Self::ParseIpv6Error(err)
    }
}
