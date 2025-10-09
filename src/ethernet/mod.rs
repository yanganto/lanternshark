//! Ethernet packet parsing.

mod arp;
mod ipv4;
mod ipv6;
mod rarp;

use arp::ArpPacket;
use ipv4::Ipv4Packet;
use ipv6::Ipv6Packet;
use rarp::RarpPacket;

use chrono::DateTime;
use std::fmt;

/// An Ethernet packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetPacket<'a> {
    /// The timestamp of the packet.
    pub timestamp: DateTime<chrono::Utc>,
    /// The destination MAC address.
    pub destination: MacAddress,
    /// The source MAC address.
    pub source: MacAddress,
    /// The inner packet type.
    pub inner: EtherTypes,
    /// The raw data part of the packet.
    pub raw_data: &'a [u8],
}

/// A MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress([u8; 6]);

/// Available inner packet types for Ethernet frames.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtherTypes {
    /// IPv4 (0x0800)
    Ipv4(Ipv4Packet),
    /// ARP (0x0806)
    Arp(ArpPacket),
    /// RARP (0x8035)
    Rarp(RarpPacket),
    /// IPv6 (0x86DD)
    Ipv6(Ipv6Packet),
    /// Unknown or unsupported EtherType
    Unknown(u16),
    // TODO: add more EtherTypes as needed
}

/// Possible errors when parsing an Ethernet packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseEthernetError {
    /// The timestamp is out of range.
    TimestampOutOfRange,
    /// The packet is too short to be a valid Ethernet frame.
    PacketTooShort,
}

impl<'a> TryFrom<&pcap::Packet<'a>> for EthernetPacket<'a> {
    type Error = ParseEthernetError;
    fn try_from(packet: &pcap::Packet<'a>) -> Result<Self, ParseEthernetError> {
        let seconds = packet.header.ts.tv_sec as i64; // `as i64` is required, since on Windows `tv_sec` is `c_long` which is `i32`
        let nanos = (packet.header.ts.tv_usec as i64) * 1000;
        let nanos = nanos
            .try_into()
            .map_err(|_| ParseEthernetError::TimestampOutOfRange)?;
        let timestamp = DateTime::from_timestamp(seconds, nanos)
            .ok_or(ParseEthernetError::TimestampOutOfRange)?;
        if packet.data.len() < 14 {
            return Err(ParseEthernetError::PacketTooShort);
        }
        let (header, data) = packet.data.split_at(14);
        let destination = MacAddress(header[0..6].try_into().unwrap()); // safe unwrap due to length check above
        let source = MacAddress(header[6..12].try_into().unwrap()); // safe unwrap due to length check above
        let ethertype_raw = u16::from_be_bytes([header[12], header[13]]);
        let ethertype = match ethertype_raw {
            0x0800 => EtherTypes::Ipv4(Ipv4Packet::new(data)), // Placeholder for actual IPv4 packet parsing
            0x0806 => EtherTypes::Arp(ArpPacket::new(data)),   // Placeholder for actual ARP packet parsing
            0x8035 => EtherTypes::Rarp(RarpPacket::new(data)), // Placeholder for actual RARP packet parsing
            0x86DD => EtherTypes::Ipv6(Ipv6Packet::new(data)), // Placeholder for actual IPv6 packet parsing
            _ => EtherTypes::Unknown(ethertype_raw),
        };

        Ok(Self {
            timestamp,
            destination,
            source,
            inner: ethertype,
            raw_data: data,
        })
    }
}

impl<'a> fmt::Display for EthernetPacket<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            timestamp,
            destination,
            source,
            inner: ethertype,
            raw_data: data,
        } = self;
        write!(
            f,
            "[{timestamp}] {source} -> {destination}, {ethertype:?}, {} bytes",
            data.len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use pcap::{Packet, PacketHeader};

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
        let raw_packet = Packet::new(&HEADER, &DATA);
        let eth_packet =
            EthernetPacket::try_from(&raw_packet).expect("Failed to parse Ethernet packet");

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
        assert!(matches!(eth_packet.inner, EtherTypes::Ipv4(_)));
        assert_eq!(eth_packet.raw_data, &DATA[14..]);
    }
}
