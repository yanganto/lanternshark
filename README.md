# termshark

[![GitHub License](https://img.shields.io/github/license/PRO-2684/termshark?logo=opensourceinitiative)](https://github.com/PRO-2684/termshark/blob/main/LICENSE)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/PRO-2684/termshark/release.yml?logo=githubactions)](https://github.com/PRO-2684/termshark/blob/main/.github/workflows/release.yml)
[![GitHub Release](https://img.shields.io/github/v/release/PRO-2684/termshark?logo=githubactions)](https://github.com/PRO-2684/termshark/releases)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/PRO-2684/termshark/total?logo=github)](https://github.com/PRO-2684/termshark/releases)
[![Crates.io Version](https://img.shields.io/crates/v/termshark?logo=rust)](https://crates.io/crates/termshark)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/termshark?logo=rust)](https://crates.io/crates/termshark)
[![docs.rs](https://img.shields.io/docsrs/termshark?logo=rust)](https://docs.rs/termshark)

WireShark in the terminal. Note that this is a toy project, with majority features missing.

## 📥 Installation

### Using [`binstall`](https://github.com/cargo-bins/cargo-binstall)

```shell
cargo binstall termshark
```

### Downloading from Releases

Navigate to the [Releases page](https://github.com/PRO-2684/termshark/releases) and download respective binary for your platform. Make sure to give it execute permissions.

### Compiling from Source

Refer to [`pcap` docs](https://github.com/rust-pcap/pcap?tab=readme-ov-file#installing-dependencies) for requirements on dependencies.

```shell
git clone https://github.com/PRO-2684/termshark.git
cd termshark
cargo build --release
# The binary will be available at ./target/release/termshark
```

## 📖 Usage

### ▶️ Running TUI

```bash
sudo ./termshark capture # To capture from default device
```

Alternatively, you can [configure with `setcap`](https://github.com/rust-pcap/pcap?tab=readme-ov-file#linux), if you want to capture without root.

### ⌨️ Keyboard Control

- **↑/↓** / **j/k**: Select previous/next packet
- **Page Up/Down**: Fast scroll (10 packets at a time)
- **Home**: Jump to first packet
- **End**: Jump to last packet
- **w/s**: Scroll packet details panel up/down
- **e/d**: Scroll hex dump panel up/down
- **q** or **Ctrl+C**: Quit the application

## 💡 Samples

Here's a list of sample packets for testing. All of them are [taken from WireShark wiki](https://wiki.wireshark.org/SampleCaptures), so feel free to visit it for more.

- [`HTTP.pcap`](./samples/HTTP.pcap): From [`http.cap`](https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap)
- [`ICMP.pcap`](./samples/ICMP.pcap): From [`ipv4frags.pcap`](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ipv4frags.pcap)
- [`IGMP.pcap`](./samples/IGMP.pcap): From [`IGMP-dataset.pcap`](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/IGMP-dataset.pcap)

## 🎉 Credits

- [`pcap`](https://github.com/rust-pcap/pcap) for interacting with `libpcap`
- [`argh`](https://github.com/google/argh) for command line argument parsing
- [`ratatui`](https://github.com/ratatui/ratatui) for TUI
<!-- - [`wirefilter`](https://github.com/cloudflare/wirefilter) for filtering packets -->
