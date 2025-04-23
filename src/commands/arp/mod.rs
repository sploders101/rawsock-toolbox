use std::net::Ipv4Addr;

use send::{send_arp_request, send_gratuitous_arp};
use spoof::ArpSpoofer;

mod passivelog;
mod send;
mod spoof;
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
    /// This command impersonates devices on the network. Its intended use is for
    /// targeted packet captures without the need to reconfigure network switches
    /// or tap an ethernet cable.
    ///
    /// WARNING: This attack is *very* noisy, and while I haven't personally seen any
    /// defense mechanisms for this, it wouldn't be that hard to detect.
    ///
    /// More info:
    /// https://github.com/sploders101/rawsock-toolbox/blob/main/docs/arp-spoofing.md
    Spoof {
        /// The network interface with which to execute the attack
        interface: String,

        /// The primary target of the ARP spoofing attack
        #[arg(short = 'i', long)]
        target_ip: Ipv4Addr,

        /// The peers for whom you want to capture the target's traffic
        #[arg(short = 'p', long)]
        peer: Vec<Ipv4Addr>,

        /// The gateway IP. This is used to forward packets destined for other networks
        #[arg(short = 'g', long)]
        gateway: Ipv4Addr,

        /// Whether to send ARP replies to peers as well to capture responses
        #[arg(short = 'b', long, default_value_t = false)]
        bidirectional: bool,
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
        ArpSubcommand::Spoof {
            interface,
            target_ip,
            peer,
            gateway,
            bidirectional,
        } => {
            let mut spoofer = ArpSpoofer::new(&interface, target_ip, bidirectional, gateway)?;
            for peer in peer {
                spoofer.add_peer(peer);
            }
            loop {
                spoofer.tick()?;
            }
        }
    };
}
