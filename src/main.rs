#![warn(clippy::all, clippy::nursery, clippy::pedantic, clippy::cargo)]

use argh::FromArgs;
use sniffer::{describe_device, find_device};

#[derive(FromArgs, PartialEq, Debug)]
/// A simple network traffic sniffer and analyzer.
struct App {
    #[argh(subcommand)]
    subcommand: SubCommands,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommands {
    Capture(Capture),
    List(List),
    Load(Load),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Capture and inspect packets from a device.
#[argh(subcommand, name = "capture")]
struct Capture {
    #[argh(option, short = 'd')]
    /// the device to capture from, can be specified with either the address or the name; if not specified, the first device will be used
    device: Option<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// List available devices.
#[argh(subcommand, name = "list")]
struct List {}

#[derive(FromArgs, PartialEq, Debug)]
/// Load and inspect packets from a file.
#[argh(subcommand, name = "load")]
struct Load {
    #[argh(switch)]
    /// whether to fooey
    fooey: bool,
}

fn main() -> Result<(), pcap::Error> {
    let app: App = argh::from_env();
    match app.subcommand {
        SubCommands::Capture(capture) => {
            let device = find_device(capture.device.as_deref())?;
            println!("Capturing on device:");
            for line in describe_device(&device) {
                println!("  {line}");
            }
            println!("TODO");
        }
        SubCommands::List(_) => {
            println!("Available devices:");
            let devices = pcap::Device::list()?;
            for device in devices {
                println!("---");
                for line in describe_device(&device) {
                    println!("{line}");
                }
            }
        }
        SubCommands::Load(_load) => {
            println!("TODO");
        }
    }
    Ok(())
}
