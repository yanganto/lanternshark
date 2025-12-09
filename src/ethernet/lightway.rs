//! Lightway packet parsing.
use std::sync::atomic::{AtomicU16, Ordering};
use crate::{ethernet::{PacketDetail, ipv4::{tcp::ParseTcpError, udp::ParseUdpError}}};

static mut PORT: AtomicU16 = AtomicU16::new(27690);

/// Set port lightway using
pub fn set(port: u16) {
    unsafe {
        (*(&raw mut PORT)).store(port, Ordering::Release);
    }
}

/// Get port lightway using
pub fn port() -> u16 {
    unsafe {
        (*(&raw mut PORT)).load(Ordering::Relaxed)
    }
}

/// The tranport layer protocol Lightway runs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LightwayMode {
    /// Run Lightway over UDP
    Udp,
    /// Run Lightway over TCP
    Tcp,
}

/// A lightway packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightwayPacket<'a> {
    /// The tranport layer where lightway runs
    pub mode: LightwayMode,

    /// Major version
    pub major_version: u8,

    /// minor version
    pub minor_version: u8,

    /// Aggressive mode
    pub aggressive: bool,

    /// The express data
    pub express_data: u8,

    /// The reserved 
    pub reserved: &'a [u8; 2],

    /// The session data.
    pub data: &'a [u8],

    /// The raw data.
    pub raw: &'a [u8],
}

/// Possible errors when parsing a lightway packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseLightwayError {
    /// The Magic number of Lightway is incorrect.
    MagicNumberIncorrect,
    /// The packet is too short to be a valid DNS packet.
    PacketTooShort,
}

impl From<ParseLightwayError> for ParseUdpError {
    fn from(err: ParseLightwayError) -> Self {
        Self::ParseLightwayError(err)
    }
}

impl From<ParseLightwayError> for ParseTcpError {
    fn from(err: ParseLightwayError) -> Self {
        Self::ParseLightwayError(err)
    }
}

impl<'a> LightwayPacket<'a> {
    /// Create a new DNS packet from raw data.
    ///
    /// # Errors
    ///
    /// See [`ParseLightwayError`].
    pub fn new(raw: &'a [u8], is_tcp: bool) -> Result<Self, ParseLightwayError> {
        if raw.len() < 8 {
            return Err(ParseLightwayError::PacketTooShort);
        }
        let (header, res) = raw.split_at(6);
        if header[0] != b'H' || header[1] != b'e' {
            return Err(ParseLightwayError::MagicNumberIncorrect);
        }
        let (reserved, data) = res.split_at(2);
        Ok(Self {
            mode: if is_tcp { LightwayMode::Tcp } else { LightwayMode::Udp },
            major_version: header[2],
            minor_version: header[3],
            aggressive: header[4] == 1u8,
            express_data: header[5] ,
            reserved: <&[u8; 2]>::try_from(reserved).unwrap(),
            data,
            raw
        })
    }
}

impl PacketDetail for LightwayPacket<'_> {
    fn summary(&self) -> String {
        let Self {
            major_version,
            minor_version,
            aggressive,
            express_data,
            ..
        } = self;
        format!(
            "V{major_version}.{minor_version} {} express data: {express_data:02X} data len: {}",
            if *aggressive { "aggressive" } else { "normal" },
            self.data.len()
        )
    }

    fn details(&self) -> Vec<String> {
        vec![
             format!("Lightway Version: {}.{}", self.major_version, self.minor_version),
        ]
    }

    fn slug(&self) -> &'static str {
        match self.mode {
            LightwayMode::Tcp => "LW-TCP",
            LightwayMode::Udp => "LW-UDP",
        }
    }

    fn name(&self) -> &'static str {
        match self.mode {
            LightwayMode::Tcp => "Lightway(TCP)",
            LightwayMode::Udp => "Lightway(UDP)",
        }
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}
