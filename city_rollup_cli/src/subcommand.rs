use clap::command;
use clap::Parser;
use clap::Subcommand;

pub mod l2worker;
pub mod orchestrator;
pub mod rpcserver;
pub mod apiserver;
pub mod dumpblock;
pub mod qbench;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    RPCServer(city_common::cli::args::RPCServerArgs),
    L2Worker(city_common::cli::args::L2WorkerArgs),
    Orchestrator(city_common::cli::args::OrchestratorArgs),
    APIServer(city_common::cli::args::APIServerArgs),
    DumpBlock(city_common::cli::args::L2DumpProofStoreArgs),
    QBench(city_common::cli::args::QBenchArgs),
}
