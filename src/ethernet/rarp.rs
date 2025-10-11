//! RARP packet parsing.

use std::fmt;
use super::{EtherType, PacketDetail};

/// An RARP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RarpPacket<'a> {
    // TODO: Complete the fields.
    /// The raw data field of the RARP packet.
    pub data: &'a [u8],
    /// The raw RARP packet.
    pub raw: &'a [u8],
}

/// Possible errors when parsing an RARP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseRarpError {}

impl<'a> RarpPacket<'a> {
    /// Create a new RARP packet from raw data.
    #[must_use]
    pub const fn new(raw: &'a [u8]) -> Result<Self, ParseRarpError> {
        // Placeholder implementation
        Ok(Self { data: raw, raw })
    }
}

impl EtherType for RarpPacket<'_> {
    const ETHER_TYPE: u16 = 0x8035;
}

impl fmt::Display for RarpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RARP Packet")
    }
}

impl PacketDetail for RarpPacket<'_> {
    fn summary(&self) -> String {
        "RARP Packet".to_string()
    }

    fn details(&self) -> Vec<String> {
        vec!["RARP parsing not yet implemented".to_string()]
    }

    fn slug(&self) -> &'static str {
        "RARP"
    }

    fn name(&self) -> &'static str {
        "Reverse Address Resolution Protocol"
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}

impl From<ParseRarpError> for super::ParseEthernetError {
    fn from(err: ParseRarpError) -> Self {
        Self::ParseRarpError(err)
    }
}
