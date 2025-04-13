use std::{net::Ipv4Addr, time::Duration};

use anyhow::Context;
use pnet::{
    datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
    },
    util::MacAddr,
};
use procfs::ProcResult;

pub fn get_rawsock(
    interface_name: &str,
    read_timeout: Option<Duration>,
) -> anyhow::Result<(
    NetworkInterface,
    Box<dyn DataLinkSender>,
    Box<dyn DataLinkReceiver>,
)> {
    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == interface_name)
        .next()
        .context("Interface not found")?;

    // Create a new channel, dealing with layer 2 packets
    let (tx, rx) = match datalink::channel(
        &interface,
        datalink::Config {
            read_timeout,
            promiscuous: true,
            ..Default::default()
        },
    ) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("Unhandled channel type"),
        Err(e) => anyhow::bail!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    return Ok((interface, tx, rx));
}

pub fn arptable_lookup(target_address: Ipv4Addr) -> ProcResult<Option<MacAddr>> {
    let arptable = procfs::net::arp()?;

    for entry in arptable {
        if entry.ip_address == target_address {
            return Ok(match entry.hw_address {
                Some(mac) => Some(MacAddr(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])),
                None => None,
            });
        }
    }

    return Ok(None);
}

/// Gets the mac address for a givem target_address. If necessary, this will send an arp
/// request to acquire it. `ip_address` and `hw_address` hold our addresses, used for building
/// the packet.
///
/// This is a crude implementation for CLI utilities which continuously parses proc tables.
pub fn get_mac_from_ipv4(
    ip_address: Ipv4Addr,
    hw_address: MacAddr,
    target_address: Ipv4Addr,
    rawsock_sender: &mut Box<dyn DataLinkSender>,
) -> anyhow::Result<Option<MacAddr>> {
    if let Ok(Some(mac)) = arptable_lookup(target_address) {
        return Ok(Some(mac));
    }

    for _ in 0..5 {
        let arp_request = create_arp_request_v4_eth(target_address, ip_address, hw_address);
        rawsock_sender
            .send_to(&arp_request, None)
            .context("send_to returned None")??;

        std::thread::sleep(Duration::from_millis(200));

        if let Ok(Some(mac)) = arptable_lookup(ip_address) {
            return Ok(Some(mac));
        }
    }

    return Ok(None);
}

pub fn create_arp_request_v4_eth(
    target_address: Ipv4Addr,
    ip_address: Ipv4Addr,
    hw_address: MacAddr,
) -> [u8; ETH_HEADER_LEN + ARP_PACKET_LEN] {
    let mut raw_packet = [0u8; ETH_HEADER_LEN + ARP_PACKET_LEN];
    let mut packet = MutableEthernetPacket::new(&mut raw_packet).unwrap();
    packet.set_destination(MacAddr::broadcast());
    packet.set_source(hw_address);
    packet.set_ethertype(EtherTypes::Arp);
    drop(packet);
    create_arp_request_v4(
        target_address,
        ip_address,
        hw_address,
        &mut raw_packet[14..],
    );
    return raw_packet;
}

pub fn create_arp_request_v4(
    target_address: Ipv4Addr,
    ip_address: Ipv4Addr,
    hw_address: MacAddr,
    raw_packet: &mut [u8],
) {
    let mut packet = MutableArpPacket::new(raw_packet).unwrap();

    packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    packet.set_protocol_type(EtherTypes::Ipv4);
    packet.set_hw_addr_len(6);
    packet.set_proto_addr_len(4);
    packet.set_operation(ArpOperations::Request);
    packet.set_sender_hw_addr(hw_address);
    packet.set_sender_proto_addr(ip_address);
    packet.set_target_hw_addr(MacAddr::broadcast());
    packet.set_target_proto_addr(target_address);
}

pub const ETH_HEADER_LEN: usize = 14;

pub fn create_arp_reply_v4_eth(
    target_address: Option<(Ipv4Addr, MacAddr)>,
    spoof_address: Ipv4Addr,
    hw_address: MacAddr,
) -> [u8; ETH_HEADER_LEN + ARP_PACKET_LEN] {
    let mut raw_packet = [0u8; ETH_HEADER_LEN + ARP_PACKET_LEN];
    let mut packet = MutableEthernetPacket::new(&mut raw_packet).unwrap();
    packet.set_destination(
        target_address
            .map(|(_ip, mac)| mac)
            .unwrap_or(MacAddr::broadcast()),
    );
    packet.set_source(hw_address);
    packet.set_ethertype(EtherTypes::Arp);
    drop(packet);
    create_arp_reply_v4(
        target_address,
        spoof_address,
        hw_address,
        &mut raw_packet[14..],
    );
    return raw_packet;
}

pub const ARP_PACKET_LEN: usize = 28;
pub fn create_arp_reply_v4(
    target_address: Option<(Ipv4Addr, MacAddr)>,
    spoof_address: Ipv4Addr,
    hw_address: MacAddr,
    raw_packet: &mut [u8],
) {
    let mut packet = MutableArpPacket::new(raw_packet).unwrap();

    packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    packet.set_protocol_type(EtherTypes::Ipv4);
    packet.set_hw_addr_len(6);
    packet.set_proto_addr_len(4);
    packet.set_operation(ArpOperations::Reply);
    packet.set_sender_hw_addr(hw_address);
    packet.set_sender_proto_addr(spoof_address);
    match target_address {
        Some((v4_addr, mac_addr)) => {
            packet.set_target_hw_addr(mac_addr);
            packet.set_target_proto_addr(v4_addr);
        }
        None => {
            packet.set_target_hw_addr(MacAddr::broadcast());
            packet.set_target_proto_addr(spoof_address);
        }
    }
}
