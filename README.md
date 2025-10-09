# sniffer

[![GitHub License](https://img.shields.io/github/license/PRO-2684/sniffer?logo=opensourceinitiative)](https://github.com/PRO-2684/sniffer/blob/main/LICENSE)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/PRO-2684/sniffer/release.yml?logo=githubactions)](https://github.com/PRO-2684/sniffer/blob/main/.github/workflows/release.yml)
[![GitHub Release](https://img.shields.io/github/v/release/PRO-2684/sniffer?logo=githubactions)](https://github.com/PRO-2684/sniffer/releases)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/PRO-2684/sniffer/total?logo=github)](https://github.com/PRO-2684/sniffer/releases)
[![Crates.io Version](https://img.shields.io/crates/v/sniffer?logo=rust)](https://crates.io/crates/sniffer)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/sniffer?logo=rust)](https://crates.io/crates/sniffer)
[![docs.rs](https://img.shields.io/docsrs/sniffer?logo=rust)](https://docs.rs/sniffer)

My traffic sniffer for the course "Software and System Security"

## ⚙️ Automatic Releases Setup

1. [Create a new GitHub repository](https://github.com/new) with the name `sniffer` and push this generated project to it.
2. Enable Actions for the repository, and grant "Read and write permissions" to the workflow [here](https://github.com/PRO-2684/sniffer/settings/actions).
3. [Generate an API token on crates.io](https://crates.io/settings/tokens/new), with the following setup:

    - `Name`: `sniffer`
    - `Expiration`: `No expiration`
    - `Scopes`: `publish-new`, `publish-update`
    - `Crates`: `sniffer`

4. [Add a repository secret](https://github.com/PRO-2684/sniffer/settings/secrets/actions/new) named `CARGO_TOKEN` with the generated token as its value.
5. Consider removing this section and updating this README with your own project information.

[Trusted Publishing](https://crates.io/docs/trusted-publishing) is a recent feature added to crates.io. To utilize it, first make sure you've already successfully published the crate. Then, follow these steps:

1. Configuring Trusted Publishing - see the section on [crates.io documentation](https://crates.io/docs/trusted-publishing#Configuring-Trusted-Publishing:~:text=Configuring%20Trusted%20Publishing).
2. Modify `.github/workflows/release.yml` like

## 📥 Installation

### Using [`binstall`](https://github.com/cargo-bins/cargo-binstall)

```shell
cargo binstall sniffer
```

### Downloading from Releases

Navigate to the [Releases page](https://github.com/PRO-2684/sniffer/releases) and download respective binary for your platform. Make sure to give it execute permissions.

### Compiling from Source

```shell
cargo install sniffer
```

## 💡 Examples

TODO

## 📖 Usage

TODO

## 🎉 Credits

TODO
