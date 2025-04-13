use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser, Debug, Clone)]
struct Args {
    #[command(subcommand)]
    command: RawsockSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
enum RawsockSubcommand {
    Arp {
        #[command(subcommand)]
        command: commands::arp::ArpSubcommand,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    return match args.command {
        RawsockSubcommand::Arp { command } => commands::arp::run(command),
    };
}
