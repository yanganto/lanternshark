//! HTTP packet parsing.
// https://www.wikiwand.com/en/articles/HTTP#HTTP/1.1_request_messages

use super::{PacketDetail, ParseTcpError};
use std::{fmt, io::Error as IoError, str::from_utf8};

/// An HTTP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPacket<'a> {
    /// Request method.
    pub method: &'a str,
    /// Request path.
    pub path: &'a str,
    /// HTTP version.
    pub version: &'a str,
    /// Headers as key-value pairs.
    pub headers: Vec<(&'a str, &'a str)>,
    /// The raw data field or leftover data of the HTTP packet.
    pub data: &'a [u8],
    /// The raw HTTP packet.
    pub raw: &'a [u8],
}

/// Possible errors when parsing an HTTP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseHttpError {
    /// The packet does not contain a valid HTTP request line.
    InvalidRequestLine,
    /// The packet is not properly encoded in UTF-8.
    InvalidUtf8,
    /// IO error while reading lines.
    IoError,
}

impl From<ParseHttpError> for ParseTcpError {
    fn from(err: ParseHttpError) -> Self {
        Self::ParseHttpError(err)
    }
}

impl From<IoError> for ParseHttpError {
    fn from(_: IoError) -> Self {
        Self::IoError
    }
}

impl<'a> HttpPacket<'a> {
    /// Create a new HTTP packet from raw data.
    ///
    /// # Errors
    ///
    /// See [`ParseHttpError`].
    pub fn new(raw: &'a [u8]) -> Result<Self, ParseHttpError> {
        // Find the header/body separator in raw bytes (double CRLF or double LF)
        let separator = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 4)
            .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|pos| pos + 2))
            .unwrap_or(raw.len());

        // Split header and data at byte level
        let header_bytes = &raw[..separator.min(raw.len())];
        let data = &raw[separator.min(raw.len())..];

        // Now parse only the header section as UTF-8
        let header_text = from_utf8(header_bytes).map_err(|_| ParseHttpError::InvalidUtf8)?;
        let mut lines = header_text.lines();

        // Parse request line
        let request_line = lines.next().ok_or(ParseHttpError::InvalidRequestLine)?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().ok_or(ParseHttpError::InvalidRequestLine)?;
        let path = parts.next().ok_or(ParseHttpError::InvalidRequestLine)?;
        let version = parts.next().ok_or(ParseHttpError::InvalidRequestLine)?;
        let version = version
            .strip_prefix("HTTP/")
            .ok_or(ParseHttpError::InvalidRequestLine)?;

        // Parse headers
        let mut headers = Vec::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                break; // End of headers
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.push((key.trim(), value.trim()));
            }
        }

        Ok(Self {
            method,
            path,
            version,
            headers,
            data,
            raw,
        })
    }
}

impl fmt::Display for HttpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            method,
            path,
            version,
            ..
        } = self;
        write!(f, "HTTP: {method} {path} HTTP/{version}")
    }
}

impl PacketDetail for HttpPacket<'_> {
    fn summary(&self) -> String {
        let Self {
            method,
            path,
            version,
            ..
        } = self;
        format!("{method} {path} HTTP/{version}")
    }

    fn details(&self) -> Vec<String> {
        let mut result = vec![
            format!("Method: {}", self.method),
            format!("Path: {}", self.path),
            format!("Version: HTTP/{}", self.version),
            format!("Headers: {} headers", self.headers.len()),
        ];
        let headers = self.headers.iter().map(|(k, v)| format!("  {k}: {v}"));
        result.extend(headers);
        result
    }

    fn slug(&self) -> &'static str {
        "HTTP"
    }

    fn name(&self) -> &'static str {
        "Hypertext Transfer Protocol"
    }

    fn length(&self) -> usize {
        self.raw.len()
    }
}
