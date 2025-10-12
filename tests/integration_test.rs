use std::path::Path;

use termshark::ethernet::{EthernetPacket, ParseEthernetError};
use pcap::Capture;

fn test_ethernet_packet<P: AsRef<Path>>(path: P) -> Result<u32, ParseEthernetError> {
    // Open a pcap capture from a test file
    let mut cap = Capture::from_file(path).unwrap();
    let mut cnt = 0;

    // Read every packet in the capture
    while let Ok(packet) = cap.next_packet() {
        // ...And try to parse it
        let _eth_packet = EthernetPacket::try_from(&packet)?;
        cnt += 1;
    }

    Ok(cnt)
}

#[test]
fn test_ethernet_parsing() -> Result<(), ParseEthernetError> {
    // Test all files under `samples`
    let samples_dir = Path::new("samples");
    for entry in std::fs::read_dir(samples_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("pcap") {
            println!("Testing file: {}", path.display());
            let cnt = test_ethernet_packet(&path)?;
            println!("Parsed {} Ethernet packets", cnt);
        }
    }

    Ok(())
}
