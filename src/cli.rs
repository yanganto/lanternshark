//! Command line interface logic.
use argh::FromArgs;
use std::path::PathBuf;

/// 🦈 WireShark in the terminal.
#[derive(FromArgs, PartialEq, Debug)]
pub struct Cli {
    /// the subcommand to run
    #[argh(subcommand)]
    pub subcommand: SubCommands,

    /// the key binding config
    #[argh(option, short = 'k')]
    pub key_config: Option<PathBuf>,
}

/// The available subcommands.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
pub enum SubCommands {
    /// Capture and inspect packets from a device.
    Capture(Capture),
    /// List available devices.
    List(List),
    /// Load and inspect packets from a file.
    Load(Load),
    /// Show key config example
    Config(Config),
}

/// Capture and inspect packets from a device.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "capture")]
pub struct Capture {
    /// the device to capture from, can be specified with either the address or the name; if not specified, the first device will be used
    #[argh(option, short = 'd')]
    pub device: Option<String>,
    /// the file to save captured packets to
    #[argh(option, short = 's')]
    pub save_file: Option<String>,
}

/// List available devices.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "list")]
pub struct List {}

/// Load and inspect packets from a file.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "load")]
pub struct Load {
    /// the file to load from
    #[argh(positional)]
    pub file: String,
}

/// Show or save key config example
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "key-config-example")]
pub struct Config {
    /// the file to save config example
    #[argh(positional)]
    pub path: Option<PathBuf>,
}
