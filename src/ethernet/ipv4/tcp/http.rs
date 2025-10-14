//! HTTP packet parsing.
// https://www.wikiwand.com/en/articles/HTTP#HTTP/1.1_request_messages
// https://www.wikiwand.com/en/articles/HTTP#HTTP/1.1_response_messages

use super::{PacketDetail, ParseTcpError};
use std::{fmt, io::Error as IoError, str::from_utf8};

/// An HTTP packet (either request or response).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpPacket<'a> {
    /// HTTP request message.
    Request(HttpRequest<'a>),
    /// HTTP response message.
    Response(HttpResponse<'a>),
}

/// An HTTP request message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest<'a> {
    /// Request method (GET, POST, etc.).
    pub method: &'a str,
    /// Request path.
    pub path: &'a str,
    /// HTTP version.
    pub version: &'a str,
    /// Headers as key-value pairs.
    pub headers: Vec<(&'a str, &'a str)>,
    /// The message body data.
    pub data: &'a [u8],
    /// The raw HTTP packet.
    pub raw: &'a [u8],
}

/// An HTTP response message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse<'a> {
    /// HTTP version.
    pub version: &'a str,
    /// Status code (200, 404, etc.).
    pub status_code: u16,
    /// Reason phrase (OK, Not Found, etc.).
    pub reason_phrase: &'a str,
    /// Headers as key-value pairs.
    pub headers: Vec<(&'a str, &'a str)>,
    /// The message body data.
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

        // Parse the first line (status line or request line)
        let first_line = lines.next().ok_or(ParseHttpError::InvalidRequestLine)?.trim();

        // Determine if this is a request or response
        let packet = if first_line.starts_with("HTTP/") {
            // Response: "HTTP/1.1 200 OK"
            let first_whitespace = first_line.find(char::is_whitespace).ok_or(ParseHttpError::InvalidRequestLine)?;
            let version_part = &first_line[..first_whitespace];
            let version = version_part
                .strip_prefix("HTTP/")
                .ok_or(ParseHttpError::InvalidRequestLine)?;

            let rest = &first_line[first_whitespace..].trim_start();
            let second_whitespace = rest.find(char::is_whitespace).ok_or(ParseHttpError::InvalidRequestLine)?;
            let status_code_str = &rest[..second_whitespace];
            let status_code = status_code_str
                .parse()
                .map_err(|_| ParseHttpError::InvalidRequestLine)?;

            let reason_phrase = rest[second_whitespace..].trim_start();

            // Parse headers
            let headers = Self::parse_headers(&mut lines);

            HttpPacket::Response(HttpResponse {
                version,
                status_code,
                reason_phrase,
                headers,
                data,
                raw,
            })
        } else {
            // Request: "GET /path HTTP/1.1"
            let mut parts = first_line.split_whitespace();
            let method = parts.next().ok_or(ParseHttpError::InvalidRequestLine)?;
            let path = parts.next().ok_or(ParseHttpError::InvalidRequestLine)?;
            let version_part = parts.next().ok_or(ParseHttpError::InvalidRequestLine)?;
            let version = version_part
                .strip_prefix("HTTP/")
                .ok_or(ParseHttpError::InvalidRequestLine)?;

            // Parse headers
            let headers = Self::parse_headers(&mut lines);

            HttpPacket::Request(HttpRequest {
                method,
                path,
                version,
                headers,
                data,
                raw,
            })
        };

        Ok(packet)
    }

    /// Parse HTTP headers from lines.
    fn parse_headers<'b>(
        lines: &mut impl Iterator<Item = &'b str>,
    ) -> Vec<(&'b str, &'b str)> {
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
        headers
    }
}

impl fmt::Display for HttpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpPacket::Request(req) => {
                write!(f, "HTTP: {} {} HTTP/{}", req.method, req.path, req.version)
            }
            HttpPacket::Response(resp) => {
                write!(
                    f,
                    "HTTP: HTTP/{} {} {}",
                    resp.version, resp.status_code, resp.reason_phrase
                )
            }
        }
    }
}

impl PacketDetail for HttpPacket<'_> {
    fn summary(&self) -> String {
        match self {
            HttpPacket::Request(req) => {
                format!("{} {} HTTP/{}", req.method, req.path, req.version)
            }
            HttpPacket::Response(resp) => {
                format!(
                    "HTTP/{} {} {}",
                    resp.version, resp.status_code, resp.reason_phrase
                )
            }
        }
    }

    fn details(&self) -> Vec<String> {
        match self {
            HttpPacket::Request(req) => {
                let mut result = vec![
                    "Type: Request".to_string(),
                    format!("Method: {}", req.method),
                    format!("Path: {}", req.path),
                    format!("Version: HTTP/{}", req.version),
                    format!("Headers: {} headers", req.headers.len()),
                ];
                let headers = req.headers.iter().map(|(k, v)| format!("  {k}: {v}"));
                result.extend(headers);
                if !req.data.is_empty() {
                    result.push(format!("Body: {} bytes", req.data.len()));
                }
                result
            }
            HttpPacket::Response(resp) => {
                let mut result = vec![
                    "Type: Response".to_string(),
                    format!("Version: HTTP/{}", resp.version),
                    format!("Status: {} {}", resp.status_code, resp.reason_phrase),
                    format!("Headers: {} headers", resp.headers.len()),
                ];
                let headers = resp.headers.iter().map(|(k, v)| format!("  {k}: {v}"));
                result.extend(headers);
                if !resp.data.is_empty() {
                    result.push(format!("Body: {} bytes", resp.data.len()));
                }
                result
            }
        }
    }

    fn slug(&self) -> &'static str {
        "HTTP"
    }

    fn name(&self) -> &'static str {
        "Hypertext Transfer Protocol"
    }

    fn length(&self) -> usize {
        match self {
            HttpPacket::Request(req) => req.raw.len(),
            HttpPacket::Response(resp) => resp.raw.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_request() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let packet = HttpPacket::new(data).unwrap();

        match packet {
            HttpPacket::Request(req) => {
                assert_eq!(req.method, "GET");
                assert_eq!(req.path, "/index.html");
                assert_eq!(req.version, "1.1");
                assert_eq!(req.headers.len(), 2);
                assert_eq!(req.headers[0], ("Host", "example.com"));
                assert_eq!(req.headers[1], ("User-Agent", "test"));
                assert_eq!(req.data, b"");
            }
            HttpPacket::Response(_) => panic!("Expected request, got response"),
        }
    }

    #[test]
    fn test_parse_http_response() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!";
        let packet = HttpPacket::new(data).unwrap();

        match packet {
            HttpPacket::Response(resp) => {
                assert_eq!(resp.version, "1.1");
                assert_eq!(resp.status_code, 200);
                assert_eq!(resp.reason_phrase, "OK");
                assert_eq!(resp.headers.len(), 2);
                assert_eq!(resp.headers[0], ("Content-Type", "text/html"));
                assert_eq!(resp.headers[1], ("Content-Length", "13"));
                assert_eq!(resp.data, b"Hello, World!");
            }
            HttpPacket::Request(_) => panic!("Expected response, got request"),
        }
    }

    #[test]
    fn test_parse_http_response_with_multiword_reason() {
        let data = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n";
        let packet = HttpPacket::new(data).unwrap();

        match packet {
            HttpPacket::Response(resp) => {
                assert_eq!(resp.version, "1.1");
                assert_eq!(resp.status_code, 404);
                assert_eq!(resp.reason_phrase, "Not Found");
            }
            HttpPacket::Request(_) => panic!("Expected response, got request"),
        }
    }

    #[test]
    fn test_parse_http_request_with_post_body() {
        let data = b"POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}";
        let packet = HttpPacket::new(data).unwrap();

        match packet {
            HttpPacket::Request(req) => {
                assert_eq!(req.method, "POST");
                assert_eq!(req.path, "/api/data");
                assert_eq!(req.data, b"{\"key\":\"value\"}");
            }
            HttpPacket::Response(_) => panic!("Expected request, got response"),
        }
    }

    #[test]
    fn test_parse_http_with_binary_body() {
        // Response with binary data (non-UTF8 in body)
        let mut data = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]); // Binary data

        let packet = HttpPacket::new(&data).unwrap();

        match packet {
            HttpPacket::Response(resp) => {
                assert_eq!(resp.status_code, 200);
                assert_eq!(resp.data, &[0xFF, 0xFE, 0xFD, 0xFC]);
            }
            HttpPacket::Request(_) => panic!("Expected response, got request"),
        }
    }

    #[test]
    fn test_parse_http_response_with_lots_of_spaces() {
        let data = b"HTTP/1.1    200    OK\r\nContent-Type: text/html\r\n\r\nHello!";
        let packet = HttpPacket::new(data).unwrap();

        match packet {
            HttpPacket::Response(resp) => {
                assert_eq!(resp.version, "1.1");
                assert_eq!(resp.status_code, 200);
                assert_eq!(resp.reason_phrase, "OK");
                assert_eq!(resp.data, b"Hello!");
            }
            HttpPacket::Request(_) => panic!("Expected response, got request"),
        }
    }

    #[test]
    fn test_parse_invalid_http() {
        // Invalid request line
        let data = b"INVALID REQUEST LINE\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            HttpPacket::new(data).unwrap_err(),
            ParseHttpError::InvalidRequestLine
        );

        // Invalid UTF-8 in the header
        let data = b"GET /index.html?\xFF HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            HttpPacket::new(data).unwrap_err(),
            ParseHttpError::InvalidUtf8
        );
    }
}
