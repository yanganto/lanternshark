//! Trait for packet detail formatting.

/// Trait for formatting packet details in a uniform way.
pub trait PacketDetail {
    /// Get a brief summary of the packet (one-line description).
    /// This is used in the packet list's "Summary" column.
    fn summary(&self) -> String;

    /// Get detailed information about the packet as a list of lines.
    /// Each line represents a field or property of the packet.
    /// This is used in the packet details panel.
    fn details(&self) -> Vec<String>;

    /// Get the protocol slug (short identifier in uppercase).
    /// Example: "ICMP", "TCP", "IPV4", "ARP"
    fn slug(&self) -> &'static str;

    /// Get the full protocol name.
    /// Example: "Internet Control Message Protocol"
    fn name(&self) -> &'static str;

    /// Get the source address as a string (if applicable).
    /// Returns None if the packet type doesn't have a source address.
    fn source(&self) -> String {
        "N/A".to_string()
    }

    /// Get the destination address as a string (if applicable).
    /// Returns None if the packet type doesn't have a destination address.
    fn destination(&self) -> String {
        "N/A".to_string()
    }

    /// Get the packet length in bytes.
    fn length(&self) -> usize;

    /// Get the inner protocol layer, if any.
    /// This allows traversing the packet layers like a linked list.
    /// Example: IPv4 → ICMP, TCP → HTTP
    fn inner(&self) -> Option<&dyn PacketDetail> {
        None
    }
}
