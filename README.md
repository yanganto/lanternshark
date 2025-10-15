# 🦈 TermShark

[![GitHub License](https://img.shields.io/github/license/PRO-2684/termshark?logo=opensourceinitiative)](https://github.com/PRO-2684/termshark/blob/main/LICENSE)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/PRO-2684/termshark/release.yml?logo=githubactions)](https://github.com/PRO-2684/termshark/blob/main/.github/workflows/release.yml)
[![GitHub Release](https://img.shields.io/github/v/release/PRO-2684/termshark?logo=githubactions)](https://github.com/PRO-2684/termshark/releases)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/PRO-2684/termshark/total?logo=github)](https://github.com/PRO-2684/termshark/releases)
[![Crates.io Version](https://img.shields.io/crates/v/termshark?logo=rust)](https://crates.io/crates/termshark)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/termshark?logo=rust)](https://crates.io/crates/termshark)
[![docs.rs](https://img.shields.io/docsrs/termshark?logo=rust)](https://docs.rs/termshark)

WireShark in the terminal. Note that this is a toy project, with a lot of features missing.

## 📥 Installation

### Prerequisits

- Linux: Install `libpcap-dev` on Debian, or `libpcap-devel` on Fedora.
- Windows: Install [Npcap](https://npcap.com/#download).
    - If you got an error that looks like "wpcap.dll not found", try to add `C:\Windows\System32\Npcap` to your PATH and restart your shell.
- MacOSX: `libpcap` should already be installed.

### Using [`binstall`](https://github.com/cargo-bins/cargo-binstall)

```shell
cargo binstall termshark
```

### Downloading from Releases

Navigate to the [Releases page](https://github.com/PRO-2684/termshark/releases) and download respective binary for your platform. Make sure to give it execute permissions.

### Compiling from Source

You'll also need [Npcap SDK](https://npcap.com/#download) on Windows.

```shell
git clone https://github.com/PRO-2684/termshark.git
cd termshark
cargo build --release
# The binary will be available at ./target/release/termshark
```

## 📖 Usage


### 🚀 Quick Start

```bash
sudo ./termshark capture # To capture from default device
```

Alternatively, you can [configure with `setcap`](https://github.com/rust-pcap/pcap?tab=readme-ov-file#linux), if you want to capture without root.

### ⌨️ Keyboard Control

#### Navigation

- **↑/↓** or **j/k**: Select previous/next packet
- **Page Up/Down**: Scroll one page at a time (adaptive to terminal size)
- **Home**: Jump to first packet
- **End**: Jump to last packet
- **w/s**: Scroll packet details panel up/down
- **e/d**: Scroll hex dump panel up/down

#### Filtering

- **Enter**: Edit or apply filter
- **Esc**: Clear filter input, exit editing or disable filter
- Arrows, backspace, delete etc.: Edit the filter, see `keyevent_to_input_request` in [`event.rs`](./src/app/events.rs) for more details.

#### Application

- **q** or **Ctrl+C**: Quit the application

### 🔍 Filter Syntax

The filter uses a GitHub-like syntax, i.e. search terms and `key:value` pairs:

```text
searchterm protocol:tcp source:192.168.1.1 length:>1000
```

**Supported filters:**
- `protocol` / `proto`: Filter by protocol (e.g., `tcp`, `udp`, `icmp`)
- `source` / `src`: Filter by source IP address (exact match)
- `destination` / `dest` / `dst`: Filter by destination IP address (exact match)
- `length` / `len`: Filter by packet length (supports `>`, `<`, ranges)

**Examples:**

```text
protocol:tcp,udp           # TCP or UDP packets
source:192.168.1.100       # From specific source
protocol:tcp length:>1000  # Large TCP packets
HTTP source:192.168.1.1    # Traffic containing "HTTP" from source
```

See [`FILTER_SYNTAX.md`](./docs/FILTER_SYNTAX.md) for detailed documentation.

### ▶️ CLI Reference

```bash
$ termshark --help
Usage: termshark <command> [<args>]

🦈 WireShark in the terminal.

Options:
  --help, help      display usage information

Commands:
  capture           Capture and inspect packets from a device.
  list              List available devices.
  load              Load and inspect packets from a file.
```

## 💡 Demos & Samples

<details><summary>📽️ Demo asciicast</summary>

[![asciicast](https://asciinema.org/a/qgBIPexnCMOzXZbhqdusL27P7.svg)](https://asciinema.org/a/qgBIPexnCMOzXZbhqdusL27P7)

</details>

Here's a list of sample packets for testing. All of them are [taken from WireShark wiki](https://wiki.wireshark.org/SampleCaptures), so feel free to visit it for more.

- [`HTTP.pcap`](./samples/HTTP.pcap): From [`http.cap`](https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap)
- [`ICMP.pcap`](./samples/ICMP.pcap): From [`ipv4frags.pcap`](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ipv4frags.pcap)
- [`IGMP.pcap`](./samples/IGMP.pcap): From [`IGMP-dataset.pcap`](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/IGMP-dataset.pcap)

## 🎉 Credits

- [`pcap`](https://github.com/rust-pcap/pcap) for interacting with `libpcap`
- [`argh`](https://github.com/google/argh) for command line argument parsing
- [`ratatui`](https://github.com/ratatui/ratatui) for TUI
<!-- - [`wirefilter`](https://github.com/cloudflare/wirefilter) for filtering packets -->
