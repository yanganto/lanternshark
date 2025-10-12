//! Ethernet packet parsing.

pub mod arp;
pub mod ipv4;
pub mod ipv6;
mod packet_detail;

use arp::{ArpPacket, ParseArpError};
use ipv4::{Ipv4Packet, ParseIpv4Error};
use ipv6::{Ipv6Packet, ParseIpv6Error};
use pcap::Packet;
pub use packet_detail::PacketDetail;

use chrono::DateTime;
use std::fmt;

/// An Ethernet packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetPacket<'a> {
    /// The timestamp of the packet.
    pub timestamp: DateTime<chrono::Utc>,
    /// The destination MAC address. 48 bits.
    pub destination: MacAddress,
    /// The source MAC address. 48 bits.
    pub source: MacAddress,
    /// The inner packet. Type is determined by the `EtherType` field (16 bits).
    pub inner: EthernetPacketInner<'a>,
    /// The raw data field or leftover data of the packet.
    pub data: &'a [u8],
    /// The raw Ethernet packet.
    pub raw: &'a [u8],
}

/// A MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

/// Trait requiring associated const ETHER_TYPE for packet types.
pub trait EtherType {
    /// The EtherType value associated with the packet type.
    const ETHER_TYPE: u16;
}

/// An Ethernet packet of unknown or unsupported type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownEthernetPacket<'a> {
    /// The raw type of the Ethernet packet.
    pub ethertype: u16,
    /// The raw data field or leftover data of the Ethernet packet.
    pub data: &'a [u8],
    /// The raw Ethernet packet.
    pub raw: &'a [u8],
}

/// Available inner packet types for Ethernet frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthernetPacketInner<'a> {
    /// Internet Protocol version 4 (0x0800)
    Ipv4(Ipv4Packet<'a>),
    /// Address Resolution Protocol (0x0806)
    Arp(ArpPacket<'a>),
    /// Internet Protocol version 6 (0x86DD)
    Ipv6(Ipv6Packet<'a>),
    // TODO: 0x8100 — VLAN-tagged frame (IEEE 802.1Q)?
    /// Unknown or unsupported `EtherType`
    Unknown(UnknownEthernetPacket<'a>),
    // Add more EtherTypes as needed
}

/// Possible errors when parsing an Ethernet packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseEthernetError {
    /// The timestamp is out of range.
    TimestampOutOfRange,
    /// The packet is too short to be a valid Ethernet frame.
    PacketTooShort,
    /// Error parsing inner ARP packet.
    ParseArpError(ParseArpError),
    /// Error parsing inner IPv4 packet.
    ParseIpv4Error(ParseIpv4Error),
    /// Error parsing inner IPv6 packet.
    ParseIpv6Error(ParseIpv6Error),
}

impl<'a> EthernetPacket<'a> {
    /// Create a new Ethernet packet from header and raw data.
    ///
    /// # Errors
    ///
    /// See [`ParseEthernetError`].
    pub fn new(header: &pcap::PacketHeader, raw: &'a [u8]) -> Result<Self, ParseEthernetError> {
        let seconds = header.ts.tv_sec; // `as i64` is required, since on Windows `tv_sec` is `c_long` which is `i32`
        let nanos = header.ts.tv_usec * 1000;
        let nanos = nanos
            .try_into()
            .map_err(|_| ParseEthernetError::TimestampOutOfRange)?;
        let timestamp = DateTime::from_timestamp(seconds, nanos)
            .ok_or(ParseEthernetError::TimestampOutOfRange)?;
        if raw.len() < 14 {
            return Err(ParseEthernetError::PacketTooShort);
        }
        let (header, data) = raw.split_at(14);
        let destination = MacAddress([
            header[0], header[1], header[2], header[3], header[4], header[5],
        ]);
        let source = MacAddress([
            header[6], header[7], header[8], header[9], header[10], header[11],
        ]);
        let ethertype_raw = u16::from_be_bytes([header[12], header[13]]);
        let ethertype = match ethertype_raw {
            Ipv4Packet::ETHER_TYPE => EthernetPacketInner::Ipv4(Ipv4Packet::new(data)?), // Placeholder for actual IPv4 packet parsing
            ArpPacket::ETHER_TYPE => EthernetPacketInner::Arp(ArpPacket::new(data)?), // Placeholder for actual ARP packet parsing
            Ipv6Packet::ETHER_TYPE => EthernetPacketInner::Ipv6(Ipv6Packet::new(data)?), // Placeholder for actual IPv6 packet parsing
            _ => EthernetPacketInner::Unknown(UnknownEthernetPacket {
                ethertype: ethertype_raw,
                data,
                raw,
            }),
        };

        Ok(Self {
            timestamp,
            destination,
            source,
            inner: ethertype,
            data,
            raw,
        })
    }
}

impl<'a> TryFrom<&Packet<'a>> for EthernetPacket<'a> {
    type Error = ParseEthernetError;
    fn try_from(packet: &Packet<'a>) -> Result<Self, ParseEthernetError> {
        EthernetPacket::new(packet.header, packet.data)
    }
}

impl fmt::Display for EthernetPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            timestamp,
            destination,
            source,
            inner,
            data,
            raw: _,
        } = self;
        write!(
            f,
            "[{timestamp}] {source} -> {destination}, {} bytes\n{inner}",
            data.len()
        )
    }
}

impl fmt::Display for EthernetPacketInner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(ipv4) => ipv4.fmt(f),
            Self::Arp(arp) => arp.fmt(f),
            Self::Ipv6(ipv6) => ipv6.fmt(f),
            Self::Unknown(unknown) => unknown.fmt(f),
        }
    }
}

impl fmt::Display for UnknownEthernetPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Unknown Ethernet Packet (0x{:04x}): {} bytes",
            self.ethertype,
            self.data.len()
        )
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

impl PacketDetail for EthernetPacket<'_> {
    fn summary(&self) -> String {
        format!(
            "Src: {}, Dst: {}",
            self.source, self.destination
        )
    }

    fn details(&self) -> Vec<String> {
        let (slug, ether_type) = match &self.inner {
            EthernetPacketInner::Ipv4(ipv4) => (ipv4.slug(), Ipv4Packet::ETHER_TYPE),
            EthernetPacketInner::Arp(arp) => (arp.slug(), ArpPacket::ETHER_TYPE),
            EthernetPacketInner::Ipv6(ipv6) => (ipv6.slug(), Ipv6Packet::ETHER_TYPE),
            EthernetPacketInner::Unknown(unknown) => (unknown.slug(), unknown.ethertype),
        };
        vec![
            format!("Destination: {}", self.destination),
            format!("Source: {}", self.source),
            format!("Type: {slug} (0x{ether_type:04x})"),
        ]
    }

    fn slug(&self) -> &'static str {
        "ETHERNET"
    }

    fn name(&self) -> &'static str {
        "Ethernet II"
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

    fn inner(&self) -> Option<&dyn PacketDetail> {
        match &self.inner {
            EthernetPacketInner::Ipv4(ipv4) => Some(ipv4),
            EthernetPacketInner::Arp(arp) => Some(arp),
            EthernetPacketInner::Ipv6(ipv6) => Some(ipv6),
            EthernetPacketInner::Unknown(_) => None,
        }
    }
}

impl PacketDetail for UnknownEthernetPacket<'_> {
    fn summary(&self) -> String {
        format!("Unknown Ethernet Packet (0x{:04x})", self.ethertype)
    }

    fn details(&self) -> Vec<String> {
        vec![
            format!("EtherType: 0x{:04x}", self.ethertype),
            format!("Data Length: {} bytes", self.data.len()),
        ]
    }

    fn slug(&self) -> &'static str {
        "UNKNOWN"
    }

    fn name(&self) -> &'static str {
        "Unknown Protocol"
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap::PacketHeader;

    static HEADER: PacketHeader = PacketHeader {
        ts: libc::timeval {
            tv_sec: 5,
            tv_usec: 100,
        },
        caplen: 5,
        len: 5,
    };

    static DATA: [u8; 60] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination MAC
        0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, // Source MAC
        0x08, 0x00, // EtherType (IPv4)
        // Payload (46 bytes to make total length at least 60 bytes)
        0x45, 0x00, 0x00, 0x2e, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x00,
        0x68, 0xc0, 0xa8, 0x00, 0x01, 0x00, 0x50, 0xd4, 0x31, 0x5e, 0x6b, 0xc3, 0x7c, 0x00, 0x00,
        0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0xe6, 0x32, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01,
        0x03,
    ];

    #[test]
    fn test_parse_ethernet_packet() {
        let eth_packet =
            EthernetPacket::new(&HEADER, &DATA).expect("Failed to parse Ethernet packet");

        assert_eq!(eth_packet.timestamp.timestamp(), HEADER.ts.tv_sec as i64);
        assert_eq!(
            eth_packet.timestamp.timestamp_subsec_micros(),
            HEADER.ts.tv_usec as u32
        );
        assert_eq!(
            eth_packet.destination,
            MacAddress([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        );
        assert_eq!(
            eth_packet.source,
            MacAddress([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e])
        );
        assert!(matches!(eth_packet.inner, EthernetPacketInner::Ipv4(_)));
        assert_eq!(eth_packet.data, &DATA[14..]);
    }
}
