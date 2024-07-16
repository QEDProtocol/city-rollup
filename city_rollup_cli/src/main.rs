mod subcommand;

use shadow_rs::shadow;

shadow!(build);

use clap::Parser;

use crate::subcommand::apiserver;
use crate::subcommand::l2worker;
use crate::subcommand::orchestrator;
use crate::subcommand::rpcserver;
use crate::subcommand::dumpblock;
use crate::subcommand::qbench;
use crate::subcommand::inspectdump;
use crate::subcommand::Cli;
use crate::subcommand::Commands;

fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    city_common::logging::setup_env_logger();

    let cli = Cli::parse();
    match cli.command {
        Commands::RPCServer(args) => {
            rpcserver::run(args)?;
        },
        Commands::L2Worker(args) => {
            l2worker::run(args)?;
        }
        Commands::Orchestrator(args) => {
            orchestrator::run(args)?;
        }
        Commands::APIServer(args) => {
            apiserver::run(args)?;
        }
        Commands::DumpBlock(args) => {
            dumpblock::run(args)?;
        }
        Commands::QBench(args) => {
            qbench::run(args)?;
        }
        Commands::InspectDump(args) => {
            inspectdump::run(args)?;
        }
    };
    Ok::<_, anyhow::Error>(())
}
