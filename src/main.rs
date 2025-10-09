#![warn(clippy::all, clippy::nursery, clippy::pedantic, clippy::cargo)]

use argh::FromArgs;
use pcap::{Activated, Capture as Capturing, Device};
use sniffer::{describe_device, find_device, EthernetPacket};

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
    #[argh(positional)]
    /// the file to load from
    file: String,
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
            println!("---");
            let cap = device.open()?;
            handle_packets(cap);
        }
        SubCommands::List(_) => {
            println!("Available devices:");
            let devices = Device::list()?;
            for device in devices {
                println!("---");
                for line in describe_device(&device) {
                    println!("{line}");
                }
            }
        }
        SubCommands::Load(load) => {
            let file = load.file;
            println!("Loading from file: {file}");
            println!("---");
            let cap = Capturing::from_file(file)?;
            handle_packets(cap);
        }
    }
    Ok(())
}

fn handle_packets<T: Activated>(mut capture: Capturing<T>) {
    while let Ok(packet) = capture.next_packet() {
        let ethernet_packet = EthernetPacket::try_from(&packet);
        match ethernet_packet {
            Ok(eth_pkt) => println!("{eth_pkt}"),
            Err(e) => eprintln!("Failed to parse Ethernet packet: {e:?}"),
        }
    }
}
