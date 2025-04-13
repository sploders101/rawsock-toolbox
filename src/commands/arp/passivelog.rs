use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;

use super::utils::get_rawsock;

pub fn passive_log(interface_name: &str) -> anyhow::Result<()> {
    let (_interface, _tx, mut rx) = get_rawsock(interface_name, None)?;

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
