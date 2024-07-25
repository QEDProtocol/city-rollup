use anyhow::Result;
use city_common::cli::user_args::L1RefundArgs;
use city_crypto::{
    hash::base_types::hash256::Hash256, signature::secp256k1::wallet::MemorySecp256K1Wallet,
};
use city_rollup_circuit::worker::{prover::QWorkerStandardProver, toolbox::root::CRWorkerToolboxRootCircuits};
use city_rollup_common::{
    introspection::{
        rollup::{
            constants::get_network_magic_for_str, introspection::RefundSpendIntrospectionHint,
        },
        sighash::{SigHashPreimage, SIGHASH_ALL},
        transaction::{BTCTransaction, BTCTransactionInput, BTCTransactionOutput},
    },
    link::{
        data::{AddressToBTCScript, BTCAddress160},
        link_api::BTCLinkAPI,
        traits::QBitcoinAPISync,
    },
    qworker::memory_proof_store::SimpleProofStoreMemory,
};
use city_rollup_core_orchestrator::debug::scenario::sighash::finalizer::SigHashFinalizer;
use city_rollup_rpc_provider::{CityRpcProvider, RpcProvider};
use city_store::store::sighash::SigHashMerkleTree;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type PS = SimpleProofStoreMemory;

pub async fn run(args: L1RefundArgs) -> Result<()> {
    let provider = RpcProvider::new(&args.rpc_address);
    let mut wallet = MemorySecp256K1Wallet::new();

    let api = BTCLinkAPI::new_str(&args.bitcoin_rpc, &args.electrs_api);
    let from = BTCAddress160::from_p2pkh_key(
        wallet.add_private_key(Hash256::from_hex_string(&args.private_key)?)?,
    );

    let txid = Hash256::from_hex_string(&args.txid)?;
    let funding_transactions = api
        .get_funding_transactions_with_vout(BTCAddress160::new_p2sh(from.address), |utxo| {
            utxo.txid == txid
        })?;

    if funding_transactions.is_empty() {
        return Err(anyhow::anyhow!("specified utxo not found"));
    }

    let funding_transaction = &funding_transactions[0].transaction;

    let outputs = [vec![BTCTransactionOutput {
        script: from.to_btc_script(),
        value: funding_transaction.outputs[0].value,
    }]]
    .concat();

    let base_tx = BTCTransaction {
        version: 2,
        inputs: vec![BTCTransactionInput {
            hash: funding_transaction.get_hash(),
            sequence: 0xffffffff,
            script: vec![],
            index: 0,
        }],
        outputs,
        locktime: 0,
    };
    let base_sighash_preimage = SigHashPreimage {
        transaction: base_tx,
        sighash_type: SIGHASH_ALL,
    };

    let hint = RefundSpendIntrospectionHint {
        sighash_preimage: base_sighash_preimage,
        funding_transaction: funding_transaction.clone(),
    };

    let network_magic = get_network_magic_for_str(args.network.to_string())?;
    let sighash_whitelist_tree = SigHashMerkleTree::new();
    let toolbox =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, sighash_whitelist_tree.root);
    let block_state = provider.get_latest_block_state().await?;
    let checkpoint_id = block_state.checkpoint_id + 1;

    let mut proof_store = SimpleProofStoreMemory::new();
    let sighash_jobs = SigHashFinalizer::finalize_refund_sighashes::<PS>(
        &mut proof_store,
        &sighash_whitelist_tree,
        checkpoint_id,
        &[hint],
    )?;

    let mut worker = QWorkerStandardProver::new();

    for job in sighash_jobs.sighash_introspection_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox, *job)?;
    }
    for job in sighash_jobs.sighash_final_gl_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox, *job)?;
    }
    for job in sighash_jobs.sighash_root_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox, *job)?;
    }
    for job in sighash_jobs.wrap_sighash_final_bls12381_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox, *job)?;
    }


    Ok(())
}
