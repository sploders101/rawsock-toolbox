use std::{
    collections::BTreeMap,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use anyhow::Context;
use pnet::{
    packet::{
        arp::ArpPacket,
        ethernet::{EtherTypes, EthernetPacket},
        Packet,
    },
    util::MacAddr,
};

use super::utils::{
    create_arp_reply_v4_eth, create_arp_request_v4_eth, get_mac_from_ipv4, get_rawsock,
};

pub fn send_arp_request(interface: &str, target_ip: Option<Ipv4Addr>) -> anyhow::Result<()> {
    let (interface, mut sender, mut receiver) =
        get_rawsock(interface, Some(Duration::from_secs(1)))?;
    let mac_addr = interface
        .mac
        .context("Interface is missing a mac address")?;
    let ip_addr = interface
        .ips
        .iter()
        .filter(|ip| {
            ip.is_ipv4()
                && target_ip
                    .map(|target_ip| ip.contains(IpAddr::V4(target_ip)))
                    .unwrap_or(true)
        })
        .map(|ip| match ip {
            pnet::ipnetwork::IpNetwork::V4(addr) => addr,
            _ => unreachable!(),
        })
        .next()
        .context("Missing IP address. An IP is required for target resolution.")?;
    if let Some(target_ip) = target_ip {
        let packet = create_arp_request_v4_eth(target_ip, ip_addr.ip(), mac_addr);
        sender
            .send_to(&packet, None)
            .context("send_to returned None")??;

        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(1) {
            let packet = receiver.next()?;
            let packet = EthernetPacket::new(&packet).unwrap();
            if packet.get_ethertype() != EtherTypes::Arp || packet.get_destination() != mac_addr {
                continue;
            }
            let arp_packet = ArpPacket::new(packet.payload()).unwrap();
            if arp_packet.get_sender_proto_addr() != target_ip {
                continue;
            }
            println!("{} is at {}", target_ip, arp_packet.get_sender_hw_addr());
            return Ok(());
        }
        println!("Couldn't find {}", target_ip);
    } else {
        for target_ip in ip_addr.iter() {
            let packet = create_arp_request_v4_eth(target_ip, ip_addr.ip(), mac_addr);
            sender
                .send_to(&packet, None)
                .context("send_to returned None")??;
        }

        let mut table = BTreeMap::<Ipv4Addr, MacAddr>::new();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            let packet = match receiver.next() {
                Ok(packet) => packet,
                Err(err) if err.kind() == ErrorKind::TimedOut => continue,
                Err(err) => return Err(err.into()),
            };
            let packet = EthernetPacket::new(&packet).unwrap();
            if packet.get_ethertype() != EtherTypes::Arp || packet.get_destination() != mac_addr {
                continue;
            }
            let arp_packet = ArpPacket::new(packet.payload()).unwrap();
            let arp_ip = arp_packet.get_sender_proto_addr();
            let arp_mac = arp_packet.get_sender_hw_addr();
            if let Some(existing_mac) = table.insert(arp_ip, arp_mac) {
                if existing_mac != arp_mac {
                    println!("Possible spoofing attack for {}.", arp_ip);
                }
            }
        }

        for (ip, mac) in table {
            println!("{ip} is at {mac}");
        }
    }

    return Ok(());
}

pub fn send_gratuitous_arp(
    interface: &str,
    target_ip: Option<Ipv4Addr>,
    spoof_address: Ipv4Addr,
) -> anyhow::Result<()> {
    let (interface, mut sender, _receiver) = get_rawsock(interface, None)?;
    let mac_addr = interface
        .mac
        .context("Interface is missing a mac address")?;
    match target_ip {
        Some(target_ip) => {
            let ip_addr = interface
                .ips
                .iter()
                .filter(|ip| ip.is_ipv4() && ip.contains(IpAddr::V4(target_ip)))
                .map(|ip| match ip {
                    pnet::ipnetwork::IpNetwork::V4(addr) => addr,
                    _ => unreachable!(),
                })
                .next()
                .context("Missing IP address. An IP is required for target resolution.")?;
            let target_mac = get_mac_from_ipv4(ip_addr.ip(), mac_addr, target_ip, &mut sender)
                .context("Couldn't look up mac")?
                .context("Couldn't find mac address for target")?;
            let packet =
                create_arp_reply_v4_eth(Some((target_ip, target_mac)), spoof_address, mac_addr);
            sender
                .send_to(&packet, None)
                .context("send_to returned None")??;
        }
        None => {
            let packet = create_arp_reply_v4_eth(None, spoof_address, mac_addr);
            sender
                .send_to(&packet, None)
                .context("send_to returned None")??;
        }
    }

    return Ok(());
}
