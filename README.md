# termshark

[![GitHub License](https://img.shields.io/github/license/PRO-2684/termshark?logo=opensourceinitiative)](https://github.com/PRO-2684/termshark/blob/main/LICENSE)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/PRO-2684/termshark/release.yml?logo=githubactions)](https://github.com/PRO-2684/termshark/blob/main/.github/workflows/release.yml)
[![GitHub Release](https://img.shields.io/github/v/release/PRO-2684/termshark?logo=githubactions)](https://github.com/PRO-2684/termshark/releases)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/PRO-2684/termshark/total?logo=github)](https://github.com/PRO-2684/termshark/releases)

WireShark in the terminal. Primarily as my hand-in for the course "Software and System Security".

## 📥 Installation

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

## 📃 References

- [ARP](https://www.wikiwand.com/en/articles/Address_Resolution_Protocol), [ARP parameters](https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml)
- [IPv4](https://www.wikiwand.com/en/articles/IPv4)

## 🎉 Credits

- [`pcap`](https://github.com/rust-pcap/pcap) for interacting with `libpcap`
- [`argh`](https://github.com/google/argh) for command line argument parsing
- [`ratatui`](https://github.com/ratatui/ratatui) for TUI
<!-- - [`wirefilter`](https://github.com/cloudflare/wirefilter) for filtering packets -->
