//! DNS packet parsing.

use super::{PacketDetail, ParseUdpError};
use std::fmt;
use num_enum::{FromPrimitive, IntoPrimitive};

/// A DNS packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPacket<'a> {
    /// Transaction ID.
    pub transaction_id: u16,
    /// Flags.
    pub flags: DnsPacketFlags,
    /// Number of questions.
    pub question_count: u16,
    /// Number of answers.
    pub answer_count: u16,
    /// Number of authority resource records.
    pub authority_count: u16,
    /// Number of additional resource records.
    pub additional_count: u16,
    /// The raw data field or leftover data of the DNS packet.
    pub data: &'a [u8],
    /// The raw DNS packet.
    pub raw: &'a [u8],
}

/// Flags in a DNS packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsPacketFlags {
    /// Is this a query (false) or a response (true)?
    pub is_response: bool,
    /// Operation code. 4 bits.
    pub opcode: DnsOperationCode,
    /// Authoritative answer.
    pub authoritative: bool,
    /// Truncation.
    pub truncated: bool,
    /// Recursion desired.
    pub recursion_desired: bool,
    /// Recursion available.
    pub recursion_available: bool,
    // Reserved. 1 bit. Not used.
    /// Authentic data.
    pub authentic_data: bool,
    /// Checking disabled.
    pub checking_disabled: bool,
    /// Response code. 4 bits.
    pub response_code: DnsResponseCode,
}

/// Operation codes in a DNS packet. See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
pub enum DnsOperationCode {
    /// Standard query (QUERY).
    Query = 0,
    /// Inverse query (IQUERY).
    InverseQuery = 1,
    /// Server status request (STATUS).
    Status = 2,
    /// Unknown or unsupported operation code.
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// Responses codes in a DNS packet. See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
pub enum DnsResponseCode {
    /// No error.
    NoError = 0,
    /// Format error.
    FormatError = 1,
    /// Server failure.
    ServerFailure = 2,
    /// Nonexistent domain.
    NonExistentDomain = 3,
    /// Unknown or unsupported response code.
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// Possible errors when parsing a DNS packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseDnsError {
    /// The packet is too short to be a valid DNS packet.
    PacketTooShort,
}

impl From<ParseDnsError> for ParseUdpError {
    fn from(err: ParseDnsError) -> Self {
        Self::ParseDnsError(err)
    }
}

impl<'a> DnsPacket<'a> {
    /// Create a new DNS packet from raw data.
    ///
    /// # Errors
    ///
    /// See [`ParseDnsError`].
    pub fn new(raw: &'a [u8]) -> Result<Self, ParseDnsError> {
        if raw.len() < 12 {
            return Err(ParseDnsError::PacketTooShort);
        }
        let (header, data) = raw.split_at(12);
        let transaction_id = u16::from_be_bytes([header[0], header[1]]);
        let flags = DnsPacketFlags::from([header[2], header[3]]);
        let question_count = u16::from_be_bytes([header[4], header[5]]);
        let answer_count = u16::from_be_bytes([header[6], header[7]]);
        let authority_count = u16::from_be_bytes([header[8], header[9]]);
        let additional_count = u16::from_be_bytes([header[10], header[11]]);
        Ok(Self {
            transaction_id,
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
            data,
            raw,
        })
    }
}

impl fmt::Display for DnsPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
            ..
        } = self;
        write!(
            f,
            "DNS: {flags} Q:{question_count} A:{answer_count} NS:{authority_count} AR:{additional_count}"
        )
    }
}

impl PacketDetail for DnsPacket<'_> {
    fn summary(&self) -> String {
        let Self {
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
            ..
        } = self;
        format!("{flags} Q:{question_count} A:{answer_count} NS:{authority_count} AR:{additional_count}")
    }

    fn details(&self) -> Vec<String> {
        vec![
            format!("Transaction ID: 0x{:04x}", self.transaction_id),
            format!("Flags: {}", self.flags),
            format!("  QR: {}", if self.flags.is_response { "Response" } else { "Query" }),
            format!("  OPCODE: {}", self.flags.opcode),
            format!("  AA: {}", self.flags.authoritative),
            format!("  TC: {}", self.flags.truncated),
            format!("  RD: {}", self.flags.recursion_desired),
            format!("  RA: {}", self.flags.recursion_available),
            format!("  AD: {}", self.flags.authentic_data),
            format!("  CD: {}", self.flags.checking_disabled),
            format!("  RCODE: {}", self.flags.response_code),
            format!("Questions: {}", self.question_count),
            format!("Answers: {}", self.answer_count),
            format!("Authority RRs: {}", self.authority_count),
            format!("Additional RRs: {}", self.additional_count),
            format!("Data length: {} bytes", self.data.len()),
        ]
    }

    fn slug(&self) -> &'static str {
        "DNS"
    }

    fn name(&self) -> &'static str {
        "Domain Name System"
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}

impl fmt::Display for DnsOperationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsOperationCode::Query => write!(f, "QUERY"),
            DnsOperationCode::InverseQuery => write!(f, "IQUERY"),
            DnsOperationCode::Status => write!(f, "STATUS"),
            DnsOperationCode::Unknown(code) => write!(f, "Unknown (0x{code:02x})"),
        }
    }
}

impl From<[u8; 2]> for DnsPacketFlags {
    fn from(bytes: [u8; 2]) -> Self {
        let is_response = (bytes[0] & 0b1000_0000) != 0;
        let opcode = DnsOperationCode::from_primitive((bytes[0] & 0b0111_1000) >> 3);
        let authoritative = (bytes[0] & 0b0000_0100) != 0;
        let truncated = (bytes[0] & 0b0000_0010) != 0;
        let recursion_desired = (bytes[0] & 0b0000_0001) != 0;
        let recursion_available = (bytes[1] & 0b1000_0000) != 0;
        let authentic_data = (bytes[1] & 0b0010_0000) != 0;
        let checking_disabled = (bytes[1] & 0b0001_0000) != 0;
        let response_code = DnsResponseCode::from_primitive(bytes[1] & 0b0000_1111);
        Self {
            is_response,
            opcode,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            authentic_data,
            checking_disabled,
            response_code,
        }
    }
}

impl fmt::Display for DnsPacketFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.is_response {
            flags.push("QR");
        }
        if self.authoritative {
            flags.push("AA");
        }
        if self.truncated {
            flags.push("TC");
        }
        if self.recursion_desired {
            flags.push("RD");
        }
        if self.recursion_available {
            flags.push("RA");
        }
        if self.authentic_data {
            flags.push("AD");
        }
        if self.checking_disabled {
            flags.push("CD");
        }
        write!(f, "OPCODE={} RCODE={} [{}]", self.opcode, self.response_code, flags.join(", "))
    }
}

impl fmt::Display for DnsResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "NoError"),
            Self::FormatError => write!(f, "FormError"),
            Self::ServerFailure => write!(f, "ServFail"),
            Self::NonExistentDomain => write!(f, "NXDomain"),
            Self::Unknown(code) => write!(f, "Unknown (0x{code:02x})"),
        }
    }
}
