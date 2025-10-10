#![warn(clippy::all, clippy::nursery, clippy::pedantic, clippy::cargo)]

use pcap::{Capture as Capturing, Device};
use sniffer::{
    app::run,
    cli::{Cli, SubCommands},
    describe_device,
    find_device,
};

fn main() -> Result<(), pcap::Error> {
    let cli: Cli = argh::from_env();
    match cli.subcommand {
        SubCommands::Capture(capture) => {
            let device = find_device(capture.device.as_deref())?;
            println!("Capturing on device:");
            for line in describe_device(&device) {
                println!("  {line}");
            }
            let capture = device.open()?;
            run(capture);
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
            let capture = Capturing::from_file(file)?;
            run(capture);
        }
    }
    Ok(())
}
