# ✅ TODO

## Planned

- Filter
- Implement `Display` for `PacketDetail`, replacing original implementatitons
- Scroll each panel with wheel / Tabbing through sections and use the same hotkeys
- Upper-case hex
- Ellipsis when there's no space for text
- Fix Src/Dst column length (would truncate for IPv6 (and MAC?) addrs)
- `PgUp`/`PgDn` scrolls one page instead of 10 entries
- Adapting hex dump width to window width

## Not Planned (for now?)

- Implement all registered protocols
- Tabbing through sections and use the same hotkeys
- Collapsible details (remembers state for individual protocol across packets)
- Statistics: capture.stats()
- TCP stream tracing
- HTTP reassembling
- WireShark filtering syntax, possibly via [`wirefilter`](https://github.com/cloudflare/wirefilter)
