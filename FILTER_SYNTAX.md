# Filter Syntax Guide

The packet filter uses a GitHub-like syntax with `key:value` pairs. Multiple filters can be combined with space-separated syntax, and they are evaluated with AND logic between different keys and OR logic within the same key.

## Basic Syntax

```
key:value key2:value2
```

## Supported Filters

### Protocol Filter

Filter packets by protocol name. Supports multiple protocols (OR logic).

**Keys:** `protocol`, `proto`

**Examples:**
- `protocol:tcp` - Show only TCP packets
- `protocol:tcp,udp` - Show TCP or UDP packets
- `proto:icmp` - Show only ICMP packets
- `protocol:arp,rarp` - Show ARP or RARP packets

### Source Address Filter

Filter packets by exact source IP address. Supports multiple addresses.

**Keys:** `source`, `src`

**Examples:**
- `source:192.168.1.1` - Exact source IP match
- `source:192.168.1.1,10.0.0.1` - Multiple source IPs (OR)
- `src:8.8.8.8` - Match packets from Google DNS

### Destination Address Filter

Filter packets by exact destination IP address. Same syntax as source filter.

**Keys:** `destination`, `dest`, `dst`

**Examples:**
- `dest:8.8.8.8` - Exact destination IP match
- `destination:192.168.1.1,192.168.1.2` - Multiple destinations (OR)
- `dst:1.1.1.1` - Match packets to Cloudflare DNS

### Length Filter

Filter packets by size in bytes. Supports comparisons and ranges.

**Keys:** `length`, `len`

**Examples:**
- `length:1500` - Exact length match
- `length:>1000` - Packets larger than 1000 bytes
- `length:<500` - Packets smaller than 500 bytes
- `len:100-1500` - Packets between 100 and 1500 bytes (inclusive)

### Text Search Filter

Search for text in packet protocol or info fields. Case-sensitive.

**Keys:** `contains`

**Examples:**
- `contains:HTTP` - Packets containing "HTTP" in info/protocol
- `contains:SYN` - Packets containing "SYN"
- `contains:DNS` - Packets containing "DNS"

## Combining Filters

Multiple filters are combined with AND logic. All conditions must be satisfied.

**Examples:**

1. **TCP packets from specific source:**
   ```
   protocol:tcp source:192.168.1.100
   ```

2. **Large UDP packets:**
   ```
   protocol:udp length:>1000
   ```

3. **HTTP traffic between specific hosts:**
   ```
   contains:HTTP source:192.168.1.100 dest:10.0.0.50
   ```

4. **Small ICMP or ARP packets:**
   ```
   protocol:icmp,arp length:<100
   ```

5. **Complex filter:**
   ```
   protocol:tcp,udp source:192.168.1.1 length:100-1500 contains:DNS
   ```
   This shows TCP or UDP packets from 192.168.1.1, between 100-1500 bytes, containing "DNS".

## Keyboard Shortcuts

- **/** or **Ctrl+F** - Enter filter mode
- **Enter** - Apply the filter
- **Esc** - Cancel filter editing
- **Ctrl+X** - Clear current filter
- **Backspace** - Delete last character while editing

## Filter Display

When a filter is active:
- The filter bar is always visible showing the current filter
- The filter bar title shows `(X/Y)` where X is filtered count and Y is total
- Press **/** to edit the filter (cursor appears in the filter bar)
- Press **Ctrl+X** to clear the filter
- Errors in filter syntax are shown in red in the filter input bar

## Tips

1. **Exact matches:** All IP addresses must match exactly (no wildcards)
2. **Multiple values:** Use commas within a single key for OR logic
3. **Case sensitivity:** Protocol names and text searches are case-sensitive
4. **Real-time filtering:** Filters apply to new packets as they arrive
5. **Error messages:** Invalid syntax shows helpful error messages
6. **Visual feedback:** The filter bar shows when filtering is active

## Common Use Cases

### Debug Network Issues
```
source:192.168.1.100 dest:8.8.8.8
```
Track communication between specific hosts.

### Monitor Large Transfers
```
length:>5000
```
See packets larger than 5KB.

### HTTP/HTTPS Traffic
```
protocol:tcp contains:HTTP
```
Watch web traffic.

### Monitor Specific Hosts
```
source:192.168.1.10,192.168.1.20
```
Filter to see traffic from specific internal hosts.

### DNS Queries
```
protocol:udp contains:DNS
```
Monitor DNS activity.
