#![warn(clippy::all, clippy::nursery, clippy::pedantic, clippy::cargo)]

use crossterm_keybind::KeyBindTrait;
use pcap::{Capture as Capturing, Device};
use termshark::{
    app::{key_config::KeyEvent, run},
    cli::{Cli, SubCommands},
    describe_device, find_device,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli: Cli = argh::from_env();
    KeyEvent::init_and_load(cli.key_config)?;
    match cli.subcommand {
        SubCommands::Capture(capture_args) => {
            let device = find_device(capture_args.device.as_deref())?;
            println!("Capturing on device:");
            for line in describe_device(&device) {
                println!("  {line}");
            }
            let capture = device.open()?.setnonblock()?;
            run(capture, capture_args.save_file)?;
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
            run(capture, None::<String>)?;
        }
        SubCommands::Config(_) => {
            println!("{}", KeyEvent::config_example());
        }
    }
    Ok(())
}
