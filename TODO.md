# ✅ TODO

## Planned

- Sniffing mode
    - `termshark sniff <types>`
    - `apple`: Sniff MDNS packets for info of apple devices
    - `ftp`: Sniff ftp login attemps
    - `http`: Sniff http form posts
- [HTTP](https://www.wikiwand.com/en/articles/HTTP#HTTP/1.1_request_messages)
- Upper-case hex
- Scroll each panel with wheel / Tabbing through sections and use the same hotkeys

## Not Planned (for now?)

- Ellipsis when there's no space for text (Could be solved by [ratatui#1913](https://github.com/ratatui/ratatui/issues/1913))
- Stacking details panel and hex dump panel horizontally when wide enough
- Implement all registered protocols
- Tabbing through sections and use the same hotkeys
- Collapsible details (remembers state for individual protocol across packets)
- Statistics: capture.stats()
- TCP stream tracing
- HTTP reassembling
- WireShark filtering syntax, possibly via [`wirefilter`](https://github.com/cloudflare/wirefilter)
