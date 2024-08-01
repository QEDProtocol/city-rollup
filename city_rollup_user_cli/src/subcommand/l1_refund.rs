use anyhow::Result;
use city_common::{cli::user_args::L1RefundArgs, config::rollup_constants::REFUND_SCRIPT_BASE_FEE_AMOUNT};
use city_crypto::{
    hash::{base_types::hash256::Hash256, core::btc::btc_hash160}, signature::secp256k1::wallet::MemorySecp256K1Wallet,
};
use city_rollup_circuit::worker::{prover::QWorkerStandardProver, toolbox::root::CRWorkerToolboxRootCircuits};
use city_rollup_common::{
    block_template::{data::CityGroth16ProofData, BLOCK_GROTH16_ENCODED_VERIFIER_DATA}, introspection::{
        rollup::{
            constants::get_network_magic_for_str, introspection::RefundSpendIntrospectionHint,
        },
        sighash::{SigHashPreimage, SIGHASH_ALL},
        transaction::{BTCTransaction, BTCTransactionInput, BTCTransactionOutput},
    }, link::{
        data::{AddressToBTCScript, BTCAddress160},
        link_api::BTCLinkAPI,
        traits::QBitcoinAPISync,
    }, qworker::{memory_proof_store::SimpleProofStoreMemory, proof_store::QProofStoreReaderSync}
};
use city_rollup_core_orchestrator::debug::scenario::sighash::finalizer::SigHashFinalizer;
use city_rollup_rpc_provider::{CityRpcProvider, RpcProvider};
use city_store::store::sighash::SigHashMerkleTree;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

const D: usize = 2;
const MAX_CHECKPOINT_ID: u64 = 0xffffffff;
type C = PoseidonGoldilocksConfig;
type PS = SimpleProofStoreMemory;

pub async fn run(args: L1RefundArgs) -> Result<()> {
    let provider = RpcProvider::new(&args.rpc_address);
    let mut wallet = MemorySecp256K1Wallet::new();

    let api = BTCLinkAPI::new_str(&args.bitcoin_rpc, &args.electrs_api);
    let public_key = wallet.add_private_key(Hash256::from_hex_string(&args.private_key)?)?;
    eprintln!("DEBUGPRINT[1]: l1_refund.rs:35: public_key={:#?}", public_key);
    let from = BTCAddress160::from_p2pkh_key(public_key);

    let txid = Hash256::from_hex_string(&args.txid)?;

    let deposit_block_script = hex::decode(if let Some(checkpoint_id) = args.deposit_checkpoint_id {
        provider
            .get_city_block_script(checkpoint_id)
            .await?
    } else {
        provider
            .get_city_block_script(MAX_CHECKPOINT_ID)
            .await?
    })?;
    let deposit_address = btc_hash160(&deposit_block_script);

    let funding_transactions = api
        .get_funding_transactions_with_vout(BTCAddress160::new_p2sh(deposit_address), |utxo| {
            utxo.txid == txid
        })?;

    if funding_transactions.is_empty() {
        return Err(anyhow::anyhow!("specified utxo not found"));
    }

    let funding_transaction = &funding_transactions[0].transaction;
    // todo: check from
    eprintln!("DEBUGPRINT[1]: l1_refund.rs:58: transaction={:#?}", funding_transaction);

    let outputs = [vec![BTCTransactionOutput {
        script: from.to_btc_script(),
        value: funding_transaction.outputs[0].value.checked_sub(REFUND_SCRIPT_BASE_FEE_AMOUNT).unwrap(),
    }]]
    .concat();

    let mut base_tx = BTCTransaction {
        version: 2,
        inputs: vec![BTCTransactionInput {
            hash: funding_transaction.get_hash(),
            sequence: 0xffffffff,
            script: deposit_block_script,
            index: 0,
        }],
        outputs,
        locktime: 0,
    };
    eprintln!("DEBUGPRINT[1]: l1_refund.rs:73: funding_transaction.inputs[0].script.clone()={:#?}", funding_transaction.inputs[0].script.clone());
    let base_sighash_preimage = SigHashPreimage {
        transaction: base_tx.clone(),
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

    eprintln!("DEBUGPRINT[2]: l1_refund.rs:94 (before let mut proof_store = SimpleProofStoreMe…)");
    let mut proof_store = SimpleProofStoreMemory::new();
    let sighash_jobs = SigHashFinalizer::finalize_refund_sighashes::<PS>(
        &mut proof_store,
        checkpoint_id,
        &[hint.clone()],
    )?;

    eprintln!("DEBUGPRINT[3]: l1_refund.rs:103 (before let mut worker = QWorkerStandardProver::…)");
    let mut worker = QWorkerStandardProver::new();

    eprintln!("DEBUGPRINT[4]: l1_refund.rs:106 (before for job in sighash_jobs.sighash_introspe…)");
    for job in sighash_jobs.sighash_introspection_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox, *job)?;
    }
    eprintln!("DEBUGPRINT[5]: l1_refund.rs:110 (before for job in sighash_jobs.sighash_final_gl…)");
    for job in sighash_jobs.sighash_final_gl_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox, *job)?;
    }
    eprintln!("DEBUGPRINT[6]: l1_refund.rs:114 (before for job in sighash_jobs.sighash_root_job…)");
    for job in sighash_jobs.sighash_root_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox, *job)?;
    }
    eprintln!("DEBUGPRINT[7]: l1_refund.rs:118 (before for job in sighash_jobs.wrap_sighash_fin…)");
    for job in sighash_jobs.wrap_sighash_final_bls12381_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox, *job)?;
    }

    eprintln!("DEBUGPRINT[8]: l1_refund.rs:123 (before let g16_proof_output_id = sighash_jobs.w…)");
    let g16_proof_output_id = sighash_jobs.wrap_sighash_final_bls12381_job_ids[0].get_output_id();
    eprintln!("DEBUGPRINT[9]: l1_refund.rs:125 (before let g16_proof: CityGroth16ProofData = bi…)");
    let g16_proof: CityGroth16ProofData = bincode::deserialize(&proof_store.get_bytes_by_id(g16_proof_output_id)?)?;

    let script = g16_proof.encode_witness_script(&BLOCK_GROTH16_ENCODED_VERIFIER_DATA[0], &hint.sighash_preimage.transaction.inputs[0].script);
    base_tx.inputs[0].script = script;

    let txid = api.send_transaction(&base_tx)?;
    println!("txid={}", txid);

    Ok(())
}
