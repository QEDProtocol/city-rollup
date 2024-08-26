use crate::error::Result;
use city_common::cli::user_args::RandomWalletArgs;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_circuit::wallet::memory::CityMemoryWallet;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct RandomWalletOutputJSON {
    public_key: QHashOut<GoldilocksField>,
    private_key: QHashOut<GoldilocksField>,
}
pub async fn run(_: RandomWalletArgs) -> Result<()> {
    let private_key = QHashOut::<GoldilocksField>::rand();
    let mut debug_wallet = CityMemoryWallet::<PoseidonGoldilocksConfig, 2>::new_fast_setup();
    let public_key = debug_wallet.add_zk_private_key(private_key);

    let random_wallet = RandomWalletOutputJSON {
        public_key,
        private_key,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&random_wallet)
            .map_err(|e| anyhow::format_err!("{}", e.to_string()))?
    );

    Ok(())
}
