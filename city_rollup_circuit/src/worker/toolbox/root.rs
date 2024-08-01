use std::borrow::BorrowMut;

use city_common_circuit::{
    circuits::{
        simple_wrapper::dynamic::SimpleWrapperDynamic, traits::qstandard::QStandardCircuit,
    }, field::cubic::CubicExtendable
};
use city_crypto::{
    field::{qfield::QRichField, serialized_2d_felt_bls12381::Serialized2DFeltBLS12381},
    hash::{
        merkle::treeprover::TPCircuitFingerprintConfig, qhashout::QHashOut,
        traits::hasher::MerkleZeroHasher,
    },
};
use city_rollup_common::{
    block_template::{config::GROTH16_DISABLED_DEV_MODE, data::CityGroth16ProofData},
    qworker::{
        fingerprints::CRWorkerToolboxRootCircuitFingerprints,
        job_id::{ProvingJobCircuitType, QProvingJobDataID},
        proof_store::QProofStoreReaderSync,
        verifier::QWorkerVerifyHelper,
    },
};
use plonky2::{
    hash::hash_types::HashOut,
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    block_circuits::{
        root_aggregators::{
            add_process_withdrawals_add_l1_deposit::CRAggAddProcessL1WithdrawalAddL1DepositCircuit,
            user_register_claim_deposits_l2_transfer::CRAggUserRegisterClaimDepositL2TransferCircuit,
        },
        root_state_transition::block_state_transition::CRBlockStateTransitionCircuit,
    },
    sighash_circuits::{
        sighash_final_gl::CRSigHashFinalGLCircuit, sighash_refund::CRSigHashRefundCircuit, sighash_refund_final_gl::CRSigHashRefundFinalGLCircuit, sighash_root::CRSigHashRootCircuit, sighash_wrapper::CRSigHashWrapperCircuit
    },
    worker::traits::{
        QWorkerCircuitCustomWithDataSync, QWorkerCircuitMutCustomWithDataSync,
        QWorkerGenericProver, QWorkerGenericProverGroth16, QWorkerGenericProverMut,
    },
};

use super::circuits::CRWorkerToolboxCoreCircuits;

pub struct CRWorkerToolboxRootCircuits<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: CubicExtendable + QRichField,
{
    pub core: CRWorkerToolboxCoreCircuits<C, D>,
    // block aggreagtors
    pub block_agg_register_claim_deposit_transfer:
        CRAggUserRegisterClaimDepositL2TransferCircuit<C, D>,
    pub block_agg_add_process_withdrawal_add_deposit:
        CRAggAddProcessL1WithdrawalAddL1DepositCircuit<C, D>,
    pub block_state_transition: CRBlockStateTransitionCircuit<C, D>,
    pub sighash_wrapper: CRSigHashWrapperCircuit<C, D>,
    pub sighash_refund: CRSigHashRefundCircuit<C, D>,
    pub sighash_final_gl: CRSigHashFinalGLCircuit<C, D>,
    pub sighash_refund_final_gl: CRSigHashRefundFinalGLCircuit<C, D>,
    pub sighash_root: CRSigHashRootCircuit<C, D>,
    pub fingerprints: CRWorkerToolboxRootCircuitFingerprints<C::F>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> CRWorkerToolboxRootCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: CubicExtendable + QRichField,
{
    pub fn new(network_magic: u64, sighash_whitelist_root: QHashOut<C::F>) -> Self {
        let core = CRWorkerToolboxCoreCircuits::<C, D>::new(network_magic);
        let sighash_wrapper = CRSigHashWrapperCircuit::<C, D>::new(sighash_whitelist_root);
        let sighash_refund = CRSigHashRefundCircuit::<C, D>::new();

        let block_agg_register_claim_deposit_transfer =
            CRAggUserRegisterClaimDepositL2TransferCircuit::<C, D>::new(
                core.fingerprints.op_register_user,
                core.fingerprints.op_claim_l1_deposit,
                core.fingerprints.op_l2_transfer,
                core.agg_state_transition.get_common_circuit_data_ref(),
                core.agg_state_transition
                    .get_verifier_config_ref()
                    .constants_sigmas_cap
                    .height(),
            );
        let block_agg_add_process_withdrawal_add_deposit =
            CRAggAddProcessL1WithdrawalAddL1DepositCircuit::<C, D>::new(
                core.fingerprints.op_add_l1_withdrawal,
                core.fingerprints.op_process_l1_withdrawal,
                core.fingerprints.op_add_l1_deposit,
                core.agg_state_transition.get_common_circuit_data_ref(),
                core.agg_state_transition
                    .get_verifier_config_ref()
                    .constants_sigmas_cap
                    .height(),
                core.agg_state_transition_with_events
                    .get_common_circuit_data_ref(),
                core.agg_state_transition_with_events
                    .get_verifier_config_ref()
                    .constants_sigmas_cap
                    .height(),
            );

        let block_state_transition = CRBlockStateTransitionCircuit::<C, D>::new(
            &block_agg_register_claim_deposit_transfer.get_common_circuit_data_ref(),
            &block_agg_register_claim_deposit_transfer.get_verifier_config_ref(),
            &block_agg_add_process_withdrawal_add_deposit.get_common_circuit_data_ref(),
            &block_agg_add_process_withdrawal_add_deposit.get_verifier_config_ref(),
        );
        let sighash_final_gl = CRSigHashFinalGLCircuit::<C, D>::new(
            block_state_transition.get_verifier_config_ref(),
            block_state_transition.get_common_circuit_data_ref(),
            sighash_wrapper.get_verifier_config_ref(),
            sighash_wrapper.get_common_circuit_data_ref(),
        );
        let sighash_refund_final_gl = CRSigHashRefundFinalGLCircuit::new(
            sighash_refund.get_verifier_config_ref(),
            sighash_refund.get_common_circuit_data_ref(),
            sighash_final_gl.get_common_circuit_data_ref().degree()
        );
        let sighash_root = CRSigHashRootCircuit::<C, D>::new(
            sighash_final_gl.get_verifier_config_ref().constants_sigmas_cap.height(),
            sighash_final_gl.get_fingerprint(),
            sighash_refund_final_gl.get_fingerprint(),
            sighash_final_gl.get_common_circuit_data_ref(),
        );

        let fingerprints = CRWorkerToolboxRootCircuitFingerprints::<C::F> {
            network_magic,
            block_agg_register_claim_deposit_transfer: block_agg_register_claim_deposit_transfer
                .get_fingerprint(),
            block_agg_add_process_withdrawal_add_deposit:
                block_agg_add_process_withdrawal_add_deposit.get_fingerprint(),
            block_state_transition: block_state_transition.get_fingerprint(),
        };

        Self {
            core,
            block_agg_register_claim_deposit_transfer,
            block_agg_add_process_withdrawal_add_deposit,
            block_state_transition,
            sighash_wrapper,
            sighash_refund,
            sighash_final_gl,
            sighash_refund_final_gl,
            fingerprints,
            sighash_root,
        }
    }
    pub fn print_op_common_data(&self) {
        self.core.print_op_common_data();

        self.block_agg_register_claim_deposit_transfer
            .print_config_with_name("block_agg_register_claim_deposit_transfer");
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QWorkerVerifyHelper<C, D>
    for CRWorkerToolboxRootCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: CubicExtendable + QRichField,
{
    fn get_verifier_triplet_for_circuit_type(
        &self,
        circuit_type: ProvingJobCircuitType,
    ) -> (
        &CommonCircuitData<C::F, D>,
        &VerifierOnlyCircuitData<C, D>,
        QHashOut<C::F>,
    ) {
        match circuit_type {
            ProvingJobCircuitType::AggUserRegisterClaimDepositL2Transfer => self
                .block_agg_register_claim_deposit_transfer
                .get_verifier_triplet(),
            ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit => self
                .block_agg_add_process_withdrawal_add_deposit
                .get_verifier_triplet(),
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => {
                self.block_state_transition.get_verifier_triplet()
            }
            ProvingJobCircuitType::GenerateSigHashIntrospectionProof => {
                self.sighash_wrapper.get_verifier_triplet()
            }
            ProvingJobCircuitType::GenerateRefundSigHashIntrospectionProof => {
                self.sighash_refund.get_verifier_triplet()
            }
            ProvingJobCircuitType::GenerateFinalSigHashProof => {
                self.sighash_final_gl.get_verifier_triplet()
            }
            ProvingJobCircuitType::GenerateSigHashRootProof => {
                self.sighash_root.get_verifier_triplet()
            }
            ProvingJobCircuitType::GenerateRefundFinalSigHashProof => {
                self.sighash_refund_final_gl.get_verifier_triplet()
            }
            other => self.core.get_verifier_triplet_for_circuit_type(other),
        }
    }

    fn get_tree_prover_fingerprint_config(
        &self,
        circuit_type: ProvingJobCircuitType,
    ) -> anyhow::Result<TPCircuitFingerprintConfig<C::F>> {
        self.core.get_tree_prover_fingerprint_config(circuit_type)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QWorkerGenericProver<S, C, D> for CRWorkerToolboxRootCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: CubicExtendable + QRichField,
{
    fn worker_prove(
        &self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let circuit_type = job_id.circuit_type;
        match circuit_type {
            ProvingJobCircuitType::AggUserRegisterClaimDepositL2Transfer => self
                .block_agg_register_claim_deposit_transfer
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit => self
                .block_agg_add_process_withdrawal_add_deposit
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateSigHashIntrospectionProof => self
                .sighash_wrapper
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateRefundSigHashIntrospectionProof => self
                .sighash_refund
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => self
                .block_state_transition
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateFinalSigHashProof => self
                .sighash_final_gl
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateSigHashRootProof => self
                .sighash_root
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateRefundFinalSigHashProof => self
                .sighash_refund_final_gl
                .prove_q_worker_custom(self, store, job_id),
            _ => self.core.worker_prove(store, job_id),
        }
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QWorkerGenericProverMut<S, C, D> for CRWorkerToolboxRootCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: CubicExtendable + QRichField,
{
    fn worker_prove_mut(
        &mut self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let circuit_type = job_id.circuit_type;
        match circuit_type {
            ProvingJobCircuitType::AggUserRegisterClaimDepositL2Transfer => self
                .block_agg_register_claim_deposit_transfer
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit => self
                .block_agg_add_process_withdrawal_add_deposit
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateSigHashIntrospectionProof => (self.sighash_wrapper)
                .borrow_mut()
                .prove_q_worker_mut_custom(store, job_id),
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => self
                .block_state_transition
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateFinalSigHashProof => self
                .sighash_final_gl
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateSigHashRootProof => self
                .sighash_root
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateRefundFinalSigHashProof => self
                .sighash_refund_final_gl
                .prove_q_worker_custom(self, store, job_id),
            _ => self.core.worker_prove(store, job_id),
        }
    }
}

impl<S: QProofStoreReaderSync> QWorkerGenericProverGroth16<S, PoseidonGoldilocksConfig, 2>
    for CRWorkerToolboxRootCircuits<PoseidonGoldilocksConfig, 2>
{
    fn worker_prove_groth16(
        &self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<CityGroth16ProofData> {
        tracing::info!("job_id: {:?}", job_id);
        let input_data = store.get_bytes_by_id(job_id)?;
        let input_proof_id = bincode::deserialize::<QProvingJobDataID>(&input_data)?;
        let (common_data, verifier_data, fingerprint) =
            self.get_verifier_triplet_for_circuit_type(input_proof_id.circuit_type);

        tracing::info!("input_proof_id: {:?}", input_proof_id);
        let inner_proof = store.get_proof_by_id(input_proof_id.get_output_id())?;

        /*
        let wrapper = SimpleWrapper::<PoseidonGoldilocksConfig, 2>::new(common_data, verifier_data);
        let wrapper_proof = wrapper.prove_base(&inner_proof)?;
        */
        let wrapper = SimpleWrapperDynamic::<PoseidonGoldilocksConfig, 2>::new(
            common_data,
            fingerprint,
            verifier_data.constants_sigmas_cap.height(),
        );
        //let pub_bits = inner_proof.public_inputs.iter().map(|x: &GoldilocksField|(*x).to_canonical_u64()).collect::<Vec<_>>();

        //tracing::info!("innerproof_public_input_bits: {:?}",pub_bits);

        let wrapper_proof = wrapper.prove_base(&inner_proof, &verifier_data)?;
        if GROTH16_DISABLED_DEV_MODE {
            println!("\x1B[0m\x1B[38;5;227m\x1B[48;5;9m[SECURITY WARNING]\x1B[0m GROTH16_DISABLED_DEV_MODE is set to true, so the rollup will not verify the groth16 proofs on doge (OP_CHECKGROTH16VERIFY is replaced with OP_NOP). GROTH16_DISABLED_DEV_MODE should \x1B[1m\x1B[38;5;9mNEVER\x1B[0m be set to true in production!\x1B[0m");
            Ok(CityGroth16ProofData {
                pi_a: Serialized2DFeltBLS12381([0u8; 48]),
                pi_b_a0: Serialized2DFeltBLS12381([0u8; 48]),
                pi_b_a1: Serialized2DFeltBLS12381([0u8; 48]),
                pi_c: Serialized2DFeltBLS12381([0u8; 48]),
            })
        } else {
            let (proof_string, vk_string) = gnark_plonky2_wrapper::wrap_plonky2_proof(
                wrapper.circuit_data,
                &wrapper_proof,
                Some(&format!("/tmp/plonky2_proof/{}", job_id.data_index)),
                &format!(
                    "{}/.city-rollup/keystore/",
                    home::home_dir().unwrap().display()
                ),
            )?;
            println!("proof: {}",proof_string);
            println!("vk: {}",vk_string);
            /*
            let proof_string = serde_json::to_string(&CityGroth16ProofData {
                pi_a: Serialized2DFeltBLS12381([0u8; 48]),
                pi_b_a0: Serialized2DFeltBLS12381([0u8; 48]),
                pi_b_a1: Serialized2DFeltBLS12381([0u8; 48]),
                pi_c: Serialized2DFeltBLS12381([0u8; 48]),
            })?;
            */
            let proof_data = serde_json::from_str::<CityGroth16ProofData>(&proof_string)?;
            Ok(proof_data)
        }
    }
}
