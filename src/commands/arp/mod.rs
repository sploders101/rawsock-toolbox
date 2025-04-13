use std::net::Ipv4Addr;

use send::{send_arp_request, send_gratuitous_arp};

mod passivelog;
mod send;
mod utils;

#[derive(clap::Subcommand, Debug, Clone)]
pub enum ArpSubcommand {
    PassiveLog {
        interface: String,
    },
    /// Sends a single ARP request. It's currently only for testing, but may be
    /// extended later to parse and print replies.
    SendRequest {
        /// The network interface to send the packet on
        interface: String,

        /// The IP address the packet should be requesting
        #[arg(short = 'i', long)]
        target_ip: Option<Ipv4Addr>,
    },
    /// Sends a single gratuitous arp packet.
    ///
    /// The arp packet can be targeted or broadcast. If no `--target-*` option is
    /// specified, the packet will be broadcast to the network.
    SendReply {
        /// The network interface you want to send the ARP packet on.
        interface: String,

        /// The IP address you want to send the spoofed packet to.
        /// This will perform an ARP lookup to obtain the MAC before sending the
        /// spoofed packet.
        #[arg(short = 'i', long)]
        target_ip: Option<Ipv4Addr>,

        // TODO: See if ARP can resolve an IP from a MAC
        // /// The MAC address you want to send the spoofed packet to.
        // #[arg(short = 'm', long)]
        // target_mac: Option<MacAddr>,
        /// The address you want to impersonate
        spoof_address: Ipv4Addr,
    },
}

pub fn run(subcommand: ArpSubcommand) -> anyhow::Result<()> {
    return match subcommand {
        ArpSubcommand::PassiveLog { interface } => passivelog::passive_log(&interface),
        ArpSubcommand::SendRequest {
            interface,
            target_ip,
        } => send_arp_request(&interface, target_ip),
        ArpSubcommand::SendReply {
            interface,
            target_ip,
            spoof_address,
        } => send_gratuitous_arp(&interface, target_ip, spoof_address),
    };
}
