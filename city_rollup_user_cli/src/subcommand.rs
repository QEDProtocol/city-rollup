use clap::command;
use clap::Parser;
use clap::Subcommand;

pub mod get_public_key;
pub mod random_wallet;
pub mod sign_hash;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    GetPublicKey(city_common::cli::user_args::GetPublicKeyArgs),
    RandomWallet(city_common::cli::user_args::RandomWalletArgs),
    SignHash(city_common::cli::user_args::SignHashArgs),
}
