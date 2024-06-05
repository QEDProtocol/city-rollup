use crate::error::Result;
use city_common::cli::user_args::RandomWalletArgs;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::introspection::rollup::signature::SimpleL2PrivateKey;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct RandomWalletOutputJSON {
    public_key: QHashOut<GoldilocksField>,
    private_key: QHashOut<GoldilocksField>,
}
pub async fn run(_: RandomWalletArgs) -> Result<()> {
    let private_key_base = QHashOut::<GoldilocksField>::rand();
    let private_key = SimpleL2PrivateKey::new(private_key_base);

    let public_key = private_key.get_public_key::<PoseidonHash>();

    let random_wallet = RandomWalletOutputJSON {
        public_key,
        private_key: private_key_base,
    };
    tracing::info!(
        "L2 wallet: {}",
        serde_json::to_string_pretty(&random_wallet)
            .map_err(|e| anyhow::format_err!("{}", e.to_string()))?
    );

    Ok(())
}
