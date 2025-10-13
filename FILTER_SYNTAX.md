# Filter Syntax Guide

The packet filter uses a simple, intuitive syntax. Use `key:value` pairs for specific filters, and plain text for searching packet content.

## Basic Syntax

```
searchterm key:value key2:value2
```

Any text without a colon (`:`) is treated as a search term and will match against both the packet summary and raw packet data.

## Supported Filters

### Search Terms (No Key Required)

Search for text in packet summary fields (protocol, info) and raw packet data. Multiple search terms can be used (all must match - AND logic).

**Examples:**
- `HTTP` - Packets containing "HTTP"
- `GET` - Packets containing "GET"
- `HTTP proto:tcp` - TCP packets containing "HTTP"
- `DNS 192.168.1.1` - Packets to/from 192.168.1.1 containing "DNS"

**Note:** Search is case-insensitive and searches both:
1. Summary/info fields (protocol name, packet description)
2. Raw packet data (actual bytes in the packet)

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

## Combining Filters

Multiple filters are combined with AND logic. All conditions must be satisfied.

**Examples:**

1. **Search for the text "HTTP":**
   ```
   HTTP
   ```

2. **TCP packets from specific source:**
   ```
   protocol:tcp source:192.168.1.100
   ```

3. **Search for "HTTP" in TCP packets:**
   ```
   HTTP proto:tcp
   ```

4. **Large UDP packets:**
   ```
   protocol:udp length:>1000
   ```

5. **Search between specific hosts:**
   ```
   GET source:192.168.1.100 dest:10.0.0.50
   ```

6. **Small ICMP or ARP packets:**
   ```
   protocol:icmp,arp length:<100
   ```

7. **Complex filter:**
   ```
   DNS proto:tcp,udp source:192.168.1.1 length:100-1500
   ```
   This shows TCP or UDP packets from 192.168.1.1, between 100-1500 bytes, containing "DNS" in the data.

## Keyboard Shortcuts

- **Enter** - Enter filter mode (when not in filter mode) OR apply the filter (when in filter mode)
- **Esc** - Cancel filter editing (when in filter mode) OR clear active filter (when not in filter mode)
- **Backspace** - Delete last character while editing

## Filter Display

When a filter is active:
- The filter bar is always visible showing the current filter
- The filter bar title shows `(X/Y)` where X is filtered count and Y is total
- Press **Enter** to edit the filter (cursor appears in the filter bar)
- Press **Esc** to clear the filter
- Errors in filter syntax are shown in red in the filter input bar

## Tips

1. **Simple searches**: Just type the text you're looking for (e.g., `HTTP`, `DNS`, `google`)
2. **Multiple values:** Use commas within a single key for OR logic
3. **Case insensitive:** Search terms match case-insensitively in both summary and raw data
4. **Real-time filtering:** Filters apply to new packets as they arrive
5. **Error messages:** Invalid syntax shows helpful error messages
6. **Visual feedback:** The filter bar shows when filtering is active

## Common Use Cases

### Find HTTP Traffic
```
HTTP
```
Simple search for any packet containing "HTTP".

### Find Specific Text in Packets
```
google.com
```
Search for "google.com" in packet data.

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

### HTTP Traffic Only
```
HTTP proto:tcp
```
Watch TCP packets containing HTTP data.

### Monitor Specific Hosts
```
source:192.168.1.10,192.168.1.20
```
Filter to see traffic from specific internal hosts.

### DNS Queries
```
DNS
```
Monitor DNS activity (searches in packet data and info fields).
