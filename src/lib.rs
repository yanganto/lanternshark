#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::nursery, clippy::pedantic, clippy::cargo)]

mod ethernet;
pub use ethernet::*;

use pcap::{ConnectionStatus, Device, Error};

/// Describe the given device.
#[must_use]
pub fn describe_device(device: &Device) -> Vec<String> {
    let Device {
        name,
        desc,
        addresses,
        flags: _,
    } = device;
    let mut result = vec![format!("Name: {}", name)];
    if let Some(desc) = desc {
        result.push(format!("Description: {desc}"));
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

/// Find an available device. If `name_or_addr` is `None`, return the default device.
///
/// # Errors
///
/// Returns [`Error::PcapError`] if specified device is not found or no default device is found; Also propagates errors from calling pcap functions.
pub fn find_device(name_or_addr: Option<&str>) -> Result<Device, Error> {
    let device = if let Some(name_or_addr) = name_or_addr {
        Device::list()?
            .into_iter()
            .find(|d| {
                d.name == name_or_addr
                    || d.addresses
                        .iter()
                        .any(|addr| addr.addr.to_string() == name_or_addr)
            })
            .ok_or_else(|| Error::PcapError("Specified device not found".to_string()))?
    } else {
        Device::lookup()?.ok_or_else(|| Error::PcapError("No default device found".to_string()))?
    };
    Ok(device)
}
