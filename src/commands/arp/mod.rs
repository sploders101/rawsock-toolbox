mod passivelog;

#[derive(clap::Subcommand, Debug, Clone)]
pub enum ArpSubcommand {
    PassiveLog { interface: String },
}

pub fn run(subcommand: ArpSubcommand) -> anyhow::Result<()> {
    match subcommand {
        ArpSubcommand::PassiveLog { interface } => passivelog::passive_log(&interface),
    }
}
