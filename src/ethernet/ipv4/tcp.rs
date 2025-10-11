//! TCP packet parsing.
// https://www.wikiwand.com/en/articles/Transmission_Control_Protocol

use std::fmt;
use super::{Protocol, ParseIpv4Error, PacketDetail};

/// A TCP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpPacket<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dest_port: u16,
    /// Sequence number.
    pub sequence_number: u32,
    /// Acknowledgment number.
    pub acknowledgment_number: u32,
    /// Data offset (header length). 4 bits.
    pub data_offset: u8,
    // Reserved bits. 4 bits. Not used currently.
    /// Flags. 8 bits.
    pub flags: TcpPacketFlags,
    /// Receive window size.
    pub window_size: u16,
    /// Checksum.
    pub checksum: u16,
    /// Urgent pointer.
    pub urgent_pointer: u16,
    /// Options. Length varies from 0 to 40 bytes.
    pub options: &'a [u8],
    /// The raw data field of the TCP packet.
    pub data: &'a [u8],
    /// The raw TCP packet.
    pub raw: &'a [u8],
}

/// Flags in a TCP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpPacketFlags {
    /// Congestion window reduced (CWR) flag.
    pub cwr: bool,
    /// ECN-Echo flag.
    pub ece: bool,
    /// Urgent pointer field significant (URG) flag.
    pub urg: bool,
    /// Acknowledgment field significant (ACK) flag.
    pub ack: bool,
    /// Push function (PSH) flag.
    pub psh: bool,
    /// Reset the connection (RST) flag.
    pub rst: bool,
    /// Synchronize sequence numbers (SYN) flag.
    pub syn: bool,
    /// No more data from sender (FIN) flag.
    pub fin: bool,
}

/// Possible errors when parsing a TCP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseTcpError {
    /// The packet is too short to be a valid TCP packet, or the header length exceeds the packet length.
    PacketTooShort,
    /// The data offset is invalid (less than 5 or greater than 15).
    InvalidDataOffset,
}

impl From<ParseTcpError> for ParseIpv4Error {
    fn from(err: ParseTcpError) -> Self {
        Self::ParseTcpError(err)
    }
}

impl<'a> TcpPacket<'a> {
    /// Create a new TCP packet from raw data.
    #[must_use]
    pub fn new(raw: &'a [u8]) -> Result<Self, ParseTcpError> {
        if raw.len() < 20 {
            return Err(ParseTcpError::PacketTooShort);
        }
        let (header, options_and_data) = raw.split_at(20);
        let src_port = u16::from_be_bytes([header[0], header[1]]);
        let dest_port = u16::from_be_bytes([header[2], header[3]]);
        let sequence_number = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let acknowledgment_number = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        let data_offset_and_reserved = header[12];
        let data_offset = data_offset_and_reserved >> 4;
        if data_offset < 5 || data_offset > 15 {
            return Err(ParseTcpError::InvalidDataOffset);
        }
        let flags = TcpPacketFlags::from(header[13]);
        let window_size = u16::from_be_bytes([header[14], header[15]]);
        let checksum = u16::from_be_bytes([header[16], header[17]]);
        let urgent_pointer = u16::from_be_bytes([header[18], header[19]]);
        let header_length_bytes = (data_offset * 4) as usize;
        if raw.len() < header_length_bytes {
            return Err(ParseTcpError::PacketTooShort);
        }
        let (options, data) = options_and_data.split_at(header_length_bytes - 20);
        Ok(Self {
            src_port,
            dest_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            options,
            data,
            raw,
        })
    }
}

impl Protocol for TcpPacket<'_> {
    const PROTOCOL: u8 = 0x06;
}

impl fmt::Display for TcpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { sequence_number, src_port, dest_port, data, .. } = self;
        write!(f, "TCP: #{sequence_number}, port {src_port} to {dest_port}, data {} bytes", data.len())
    }
}

impl PacketDetail for TcpPacket<'_> {
    fn summary(&self) -> String {
        let Self { sequence_number, src_port, dest_port, data, .. } = self;
        format!("#{sequence_number}, {} bytes of data from :{src_port} to :{dest_port}", data.len())
    }

    fn details(&self) -> Vec<String> {
        vec![
            format!("Source Port: {}", self.src_port),
            format!("Destination Port: {}", self.dest_port),
            format!("Sequence Number: {}", self.sequence_number),
            format!("Acknowledgment Number: {}", self.acknowledgment_number),
            format!("Data Offset: {} ({} bytes)", self.data_offset, self.data_offset * 4),
            format!("Flags: {}", self.flags),
            format!("  CWR: {}", self.flags.cwr),
            format!("  ECE: {}", self.flags.ece),
            format!("  URG: {}", self.flags.urg),
            format!("  ACK: {}", self.flags.ack),
            format!("  PSH: {}", self.flags.psh),
            format!("  RST: {}", self.flags.rst),
            format!("  SYN: {}", self.flags.syn),
            format!("  FIN: {}", self.flags.fin),
            format!("Window Size: {}", self.window_size),
            format!("Checksum: 0x{:04x}", self.checksum),
            format!("Urgent Pointer: {}", self.urgent_pointer),
            format!("Options Length: {} bytes", self.options.len()),
            format!("Data Length: {} bytes", self.data.len()),
        ]
    }

    fn slug(&self) -> &'static str {
        "TCP"
    }

    fn name(&self) -> &'static str {
        "Transmission Control Protocol"
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}

impl From<u8> for TcpPacketFlags {
    fn from(byte: u8) -> Self {
        Self {
            cwr: byte & 0b1000_0000 != 0,
            ece: byte & 0b0100_0000 != 0,
            urg: byte & 0b0010_0000 != 0,
            ack: byte & 0b0001_0000 != 0,
            psh: byte & 0b0000_1000 != 0,
            rst: byte & 0b0000_0100 != 0,
            syn: byte & 0b0000_0010 != 0,
            fin: byte & 0b0000_0001 != 0,
        }
    }
}

impl fmt::Display for TcpPacketFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0b{:08b}",
            (self.cwr as u8) << 7
                | (self.ece as u8) << 6
                | (self.urg as u8) << 5
                | (self.ack as u8) << 4
                | (self.psh as u8) << 3
                | (self.rst as u8) << 2
                | (self.syn as u8) << 1
                | (self.fin as u8),
        )
    }
}

impl Default for TcpPacketFlags {
    fn default() -> Self {
        Self {
            cwr: false,
            ece: false,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false,
        }
    }
}
