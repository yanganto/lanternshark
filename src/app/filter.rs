//! Packet filtering functionality.

use super::packet_info::PacketInfo;
use std::fmt;

/// Packet filter supporting GitHub-like syntax.
///
/// # Syntax Examples
///
/// - `protocol:tcp` - Filter by protocol
/// - `protocol:tcp,udp` - Multiple protocols (OR)
/// - `source:192.168.1.1` - Exact source IP
/// - `dest:8.8.8.8` - Destination IP
/// - `length:>1000` - Minimum length
/// - `length:<500` - Maximum length
/// - `length:100-1500` - Length range
/// - `contains:HTTP` - Contains text in info/protocol
///
/// Multiple filters are combined with AND logic.
#[derive(Debug, Default, Clone)]
pub struct PacketFilter {
    /// Protocols to match (OR logic within this list)
    protocols: Vec<String>,
    /// Source addresses to match (OR logic)
    sources: Vec<String>,
    /// Destination addresses to match (OR logic)
    destinations: Vec<String>,
    /// Minimum packet length (inclusive)
    min_length: Option<usize>,
    /// Maximum packet length (inclusive)
    max_length: Option<usize>,
    /// Text that must appear in info or protocol fields
    contains_text: Option<String>,
}

impl PacketFilter {
    /// Parse a filter from user input string.
    ///
    /// Format: `key:value key:value ...`
    ///
    /// Supported keys:
    /// - `protocol`, `proto`: Protocol name(s)
    /// - `source`, `src`: Source address(es)
    /// - `destination`, `dest`, `dst`: Destination address(es)
    /// - `length`, `len`: Packet length (supports >, <, ranges)
    /// - `contains`: Text search in packet info
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Ok(Self::default());
        }

        let mut filter = Self::default();

        for part in input.split_whitespace() {
            if let Some((key, value)) = part.split_once(':') {
                match key.to_lowercase().as_str() {
                    "protocol" | "proto" => {
                        filter
                            .protocols
                            .extend(value.split(',').map(|s| s.trim().to_lowercase()));
                    }
                    "source" | "src" => {
                        filter
                            .sources
                            .extend(value.split(',').map(|s| s.trim().to_string()));
                    }
                    "destination" | "dest" | "dst" => {
                        filter
                            .destinations
                            .extend(value.split(',').map(|s| s.trim().to_string()));
                    }
                    "length" | "len" => {
                        Self::parse_length_filter(value, &mut filter)?;
                    }
                    "contains" => {
                        filter.contains_text = Some(value.to_string());
                    }
                    _ => {
                        return Err(format!(
                            "Unknown filter key: '{key}'. Supported: protocol, source, destination, length, contains",
                        ));
                    }
                }
            } else {
                return Err(format!(
                    "Invalid filter format: '{part}'. Expected 'key:value'",
                ));
            }
        }

        Ok(filter)
    }

    /// Check if a packet matches this filter.
    ///
    /// All filter conditions must be satisfied (AND logic).
    /// Within a condition (e.g., multiple protocols), any match is accepted (OR logic).
    pub fn matches(&self, packet: &PacketInfo) -> bool {
        // Protocol filter (OR within list)
        if !self.protocols.is_empty() {
            let proto_lower = packet.protocol.to_lowercase();
            if !self.protocols.iter().any(|p| proto_lower.contains(p)) {
                return false;
            }
        }

        // Source filter (OR within list)
        if !self.sources.is_empty() {
            if !self.sources.iter().any(|s| packet.source == *s) {
                return false;
            }
        }

        // Destination filter (OR within list)
        if !self.destinations.is_empty() {
            if !self.destinations.iter().any(|d| packet.destination == *d) {
                return false;
            }
        }

        // Length filters (AND logic for min/max)
        if let Some(min) = self.min_length {
            if packet.length < min {
                return false;
            }
        }
        if let Some(max) = self.max_length {
            if packet.length > max {
                return false;
            }
        }

        // Text contains filter (searches in info and protocol)
        if let Some(ref text) = self.contains_text {
            let text_lower = text.to_lowercase();
            if !packet.info.to_lowercase().contains(&text_lower)
                && !packet.protocol.to_lowercase().contains(&text_lower)
            {
                return false;
            }
        }

        true
    }

    /// Parse length filter syntax.
    ///
    /// Supports:
    /// - `>100` - Minimum length
    /// - `<500` - Maximum length
    /// - `100-500` - Range (inclusive)
    /// - `100` - Exact length
    fn parse_length_filter(value: &str, filter: &mut Self) -> Result<(), String> {
        let value = value.trim();

        if value.starts_with('>') {
            filter.min_length = Some(
                value[1..]
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid length value: '{value}'"))?,
            );
        } else if value.starts_with('<') {
            filter.max_length = Some(
                value[1..]
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid length value: '{value}'"))?,
            );
        } else if value.contains('-') {
            let parts: Vec<&str> = value.split('-').collect();
            if parts.len() == 2 {
                let min: usize = parts[0]
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid length range: '{value}'"))?;
                let max: usize = parts[1]
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid length range: '{value}'"))?;
                if min > max {
                    return Err(format!("Invalid range: min ({min}) > max ({max})"));
                }
                filter.min_length = Some(min);
                filter.max_length = Some(max);
            } else {
                return Err(format!(
                    "Invalid length range: '{value}'. Expected 'min-max'",
                ));
            }
        } else {
            let len: usize = value
                .parse()
                .map_err(|_| format!("Invalid length value: '{value}'"))?;
            filter.min_length = Some(len);
            filter.max_length = Some(len);
        }

        Ok(())
    }
}

impl fmt::Display for PacketFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if !self.protocols.is_empty() {
            parts.push(format!("protocol:{}", self.protocols.join(",")));
        }

        if !self.sources.is_empty() {
            parts.push(format!("source:{}", self.sources.join(",")));
        }

        if !self.destinations.is_empty() {
            parts.push(format!("dest:{}", self.destinations.join(",")));
        }

        if let Some(min) = self.min_length {
            if let Some(max) = self.max_length {
                if min == max {
                    parts.push(format!("length:{min}", ));
                } else {
                    parts.push(format!("length:{min}-{max}"));
                }
            } else {
                parts.push(format!("length:>{min}"));
            }
        } else if let Some(max) = self.max_length {
            parts.push(format!("length:<{max}"));
        }

        if let Some(ref text) = self.contains_text {
            parts.push(format!("contains:{text}"));
        }

        write!(f, "{}", parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_protocol() {
        let filter = PacketFilter::parse("protocol:tcp").unwrap();
        assert_eq!(filter.protocols, vec!["tcp"]);
    }

    #[test]
    fn test_parse_multiple_protocols() {
        let filter = PacketFilter::parse("protocol:tcp,udp,icmp").unwrap();
        assert_eq!(filter.protocols, vec!["tcp", "udp", "icmp"]);
    }

    #[test]
    fn test_parse_source() {
        let filter = PacketFilter::parse("source:192.168.1.1").unwrap();
        assert_eq!(filter.sources, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_parse_length_greater() {
        let filter = PacketFilter::parse("length:>100").unwrap();
        assert_eq!(filter.min_length, Some(100));
        assert_eq!(filter.max_length, None);
    }

    #[test]
    fn test_parse_length_less() {
        let filter = PacketFilter::parse("length:<500").unwrap();
        assert_eq!(filter.min_length, None);
        assert_eq!(filter.max_length, Some(500));
    }

    #[test]
    fn test_parse_length_range() {
        let filter = PacketFilter::parse("length:100-1500").unwrap();
        assert_eq!(filter.min_length, Some(100));
        assert_eq!(filter.max_length, Some(1500));
    }

    #[test]
    fn test_parse_combined() {
        let filter = PacketFilter::parse("protocol:tcp source:192.168.1.1 length:>100").unwrap();
        assert_eq!(filter.protocols, vec!["tcp"]);
        assert_eq!(filter.sources, vec!["192.168.1.1"]);
        assert_eq!(filter.min_length, Some(100));
    }
}
