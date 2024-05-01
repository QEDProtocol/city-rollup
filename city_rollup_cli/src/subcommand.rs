use clap::command;
use clap::Parser;
use clap::Subcommand;

#[cfg(debug_assertions)]
pub mod l2transfer;
pub mod rpcserver;
#[cfg(debug_assertions)]
pub mod worker;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    RPCServer(city_common::cli::args::RPCServerArgs),
    #[cfg(debug_assertions)]
    Worker(city_common::cli::args::RollupProvingWorkerArgs),
    #[cfg(debug_assertions)]
    L2Transfer(city_common::cli::args::L2TransferArgs),
}
