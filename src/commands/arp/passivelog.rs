use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;

// Invoke as echo <interface name>
pub fn passive_log(interface_name: &str) -> anyhow::Result<()> {
    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == interface_name)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("Unhandled channel type"),
        Err(e) => anyhow::bail!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();

                if packet.get_ethertype() == EtherTypes::Arp {
                    if let Some(packet) = ArpPacket::new(packet.payload()) {
                        match packet.get_operation() {
                            ArpOperations::Reply => {
                                println!(
                                    "Who is {}? Tell {}.",
                                    packet.get_target_proto_addr(),
                                    packet.get_sender_hw_addr()
                                );
                            }
                            ArpOperations::Request => {
                                println!(
                                    "IP {} is at {}.",
                                    packet.get_sender_proto_addr(),
                                    packet.get_sender_hw_addr()
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                anyhow::bail!("An error occurred while reading: {}", e);
            }
        }
    }
}
