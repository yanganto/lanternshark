# sniffer

[![GitHub License](https://img.shields.io/github/license/PRO-2684/sniffer?logo=opensourceinitiative)](https://github.com/PRO-2684/sniffer/blob/main/LICENSE)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/PRO-2684/sniffer/release.yml?logo=githubactions)](https://github.com/PRO-2684/sniffer/blob/main/.github/workflows/release.yml)
[![GitHub Release](https://img.shields.io/github/v/release/PRO-2684/sniffer?logo=githubactions)](https://github.com/PRO-2684/sniffer/releases)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/PRO-2684/sniffer/total?logo=github)](https://github.com/PRO-2684/sniffer/releases)

My traffic sniffer for the course "Software and System Security"。

## 📥 Installation

### Downloading from Releases

Navigate to the [Releases page](https://github.com/PRO-2684/sniffer/releases) and download respective binary for your platform. Make sure to give it execute permissions.

### Compiling from Source

Refer to [`pcap` docs](https://github.com/rust-pcap/pcap?tab=readme-ov-file#installing-dependencies) for requirements on dependencies.

```shell
git clone https://github.com/PRO-2684/Sniffer.git
cd Sniffer
cargo build --release
# The binary will be available at ./target/release/sniffer
```

## 📖 Usage

Note: You may need to [configure with `setcap`](https://github.com/rust-pcap/pcap?tab=readme-ov-file#linux), if you want to capture without root.

## 🎉 Credits

- [`pcap`](https://github.com/rust-pcap/pcap)
- [`argh`](https://github.com/google/argh)
<!-- - [`ratatui`](https://github.com/ratatui/ratatui) -->
