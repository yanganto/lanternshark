//! # `sniffer` library crate
//!
//! If you are reading this, you are reading the documentation for the `sniffer` library crate. For the cli, kindly refer to the README file.

#![deny(missing_docs)]
#![warn(clippy::all, clippy::nursery, clippy::pedantic, clippy::cargo)]

use pcap::{ConnectionStatus, Device};

/// Describe the given device.
pub fn describe_device(device: &Device) -> Vec<String> {
    let Device {
        name,
        desc,
        addresses,
        flags: _,
    } = device;
    let mut result = vec![format!("Name: {}", name)];
    if let Some(desc) = desc {
        result.push(format!("Description: {}", desc));
    }
    let status = &device.flags.connection_status;
    let status_line = match status {
        ConnectionStatus::Unknown => "Status: 🟡 Unknown".to_string(),
        ConnectionStatus::Connected => "Status: 🟢 Connected".to_string(),
        ConnectionStatus::Disconnected => "Status: 🔴 Disconnected".to_string(),
        ConnectionStatus::NotApplicable => "Status: 🟣 Not Applicable".to_string(),
    };
    result.push(status_line);
    if !addresses.is_empty() {
        result.push("Addresses:".to_string());
        for addr in addresses {
            result.push(format!("- {}", addr.addr));
        }
    }
    result
}

/// Find an available device. If `name_or_addr` is `None`, return the first [`Connected`](ConnectionStatus::Connected) device.
pub fn find_device(name_or_addr: Option<&str>) -> Result<Device, pcap::Error> {
    let devices = Device::list()?;
    let device = if let Some(name_or_addr) = name_or_addr {
        devices
            .into_iter()
            .find(|d| {
                d.name == name_or_addr
                    || d.addresses
                        .iter()
                        .any(|addr| addr.addr.to_string() == name_or_addr)
            })
            .ok_or_else(|| pcap::Error::PcapError("Specified device not found".to_string()))?
    } else {
        devices
            .into_iter()
            .find(|d| d.flags.connection_status == ConnectionStatus::Connected)
            .ok_or_else(|| pcap::Error::PcapError("No connected device found".to_string()))?
    };
    Ok(device)
}
