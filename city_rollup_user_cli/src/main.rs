mod error;
mod subcommand;

use shadow_rs::shadow;

shadow!(build);

use clap::Parser;
use error::Result;

use crate::subcommand::get_public_key;
use crate::subcommand::random_wallet;
use crate::subcommand::sign_hash;
use crate::subcommand::Cli;
use crate::subcommand::Commands;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    //city_common::setup_logger();

    let cli = Cli::parse();
    match cli.command {
        Commands::GetPublicKey(args) => get_public_key::run(args).await?,
        Commands::RandomWallet(args) => random_wallet::run(args).await?,
        Commands::SignHash(args) => sign_hash::run(args).await?,
    }

    Ok(())
}
