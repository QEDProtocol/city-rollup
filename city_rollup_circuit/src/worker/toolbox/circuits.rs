use city_common::logging::trace_timer::TraceTimer;
use city_common_circuit::circuits::l1_secp256k1_signature::L1Secp256K1SignatureCircuit;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuitWithDefaultMinified;
use city_common_circuit::circuits::zk_signature_wrapper::ZKSignatureWrapperCircuit;
use city_common_circuit::treeprover::aggregation::state_transition::AggStateTransitionCircuit;
use city_common_circuit::treeprover::aggregation::state_transition_dummy::AggStateTransitionDummyCircuit;
use city_common_circuit::treeprover::aggregation::state_transition_track_events::AggStateTransitionWithEventsCircuit;
use city_common_circuit::treeprover::aggregation::state_transition_track_events_dummy::AggStateTransitionWithEventsDummyCircuit;
use city_common_circuit::treeprover::traits::TreeProverAggCircuit;
use city_crypto::hash::merkle::treeprover::TPCircuitFingerprintConfig;
use city_crypto::hash::qhashout::QHashOut;
use city_crypto::hash::traits::hasher::MerkleZeroHasher;
use city_rollup_common::qworker::fingerprints::CRWorkerToolboxCoreCircuitFingerprints;
use city_rollup_common::qworker::job_id::ProvingJobCircuitType;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use city_rollup_common::qworker::verifier::QWorkerVerifyHelper;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::{
    block_circuits::ops::{
        add_l1_deposit::WCRAddL1DepositCircuit, add_l1_withdrawal::CRAddL1WithdrawalCircuit,
        claim_l1_deposit::CRClaimL1DepositCircuit, l2_transfer::circuit::CRL2TransferCircuit,
        process_l1_withdrawal::WCRProcessL1WithdrawalCircuit,
        register_user::WCRUserRegistrationCircuit,
    },
    worker::traits::{
        QWorkerCircuitAggWithDataSync, QWorkerCircuitSimpleWithDataSync, QWorkerGenericProver,
    },
};

pub struct CRWorkerToolboxCoreCircuits<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub network_magic: u64,

    // user circuits
    pub zk_signature_wrapper: ZKSignatureWrapperCircuit<C, D>,
    pub l1_secp256k1_signature: L1Secp256K1SignatureCircuit<C, D>,

    // state transition operations
    pub op_register_user: WCRUserRegistrationCircuit<C, D>,
    pub op_claim_l1_deposit: CRClaimL1DepositCircuit<C, D>, // signed
    pub op_l2_transfer: CRL2TransferCircuit<C, D>,          // signed
    pub op_add_l1_withdrawal: CRAddL1WithdrawalCircuit<C, D>, // signed

    // state transition with events operations
    pub op_add_l1_deposit: WCRAddL1DepositCircuit<C, D>,
    pub op_process_l1_withdrawal: WCRProcessL1WithdrawalCircuit<C, D>,

    // operation aggregators
    pub agg_state_transition: AggStateTransitionCircuit<C, D>,
    pub agg_state_transition_with_events: AggStateTransitionWithEventsCircuit<C, D>,
    pub agg_state_transition_dummy: AggStateTransitionDummyCircuit<C, D>,
    pub agg_state_transition_with_events_dummy: AggStateTransitionWithEventsDummyCircuit<C, D>,
    pub fingerprints: CRWorkerToolboxCoreCircuitFingerprints<C::F>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> CRWorkerToolboxCoreCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(network_magic: u64) -> Self {
        let mut trace_timer = TraceTimer::new("CRWorkerToolboxCoreCircuits");
        trace_timer.lap("start => build core toolbox circuits");
        // user circuits
        let zk_signature_wrapper = ZKSignatureWrapperCircuit::new();
        trace_timer.lap("built zk_signature_wrapper");

        let l1_secp256k1_signature = L1Secp256K1SignatureCircuit::new();
        trace_timer.lap("built l1_secp256k1_signature");

        // state transition operations
        let op_register_user =
            WCRUserRegistrationCircuit::new_default_with_minifiers(network_magic, 1);
        trace_timer.lap("built op_register_user");

        let op_claim_l1_deposit = CRClaimL1DepositCircuit::new_with_signature_circuit_data_ref(
            network_magic,
            l1_secp256k1_signature.minifier_chain.get_common_data(),
            l1_secp256k1_signature.get_verifier_config_ref(),
        );
        trace_timer.lap("built op_claim_l1_deposit");

        let op_l2_transfer = CRL2TransferCircuit::new(network_magic);
        trace_timer.lap("built op_l2_transfer");

        let op_add_l1_withdrawal = CRAddL1WithdrawalCircuit::new(network_magic);
        trace_timer.lap("built op_add_l1_withdrawal");

        // state transition with events operations
        let op_add_l1_deposit =
            WCRAddL1DepositCircuit::new_default_with_minifiers(network_magic, 1);
        trace_timer.lap("built op_add_l1_deposit");

        let op_process_l1_withdrawal =
            WCRProcessL1WithdrawalCircuit::new_default_with_minifiers(network_magic, 1);
        trace_timer.lap("built op_process_l1_withdrawal");

        // operation aggregators
        let agg_state_transition = AggStateTransitionCircuit::new(
            op_register_user.get_common_circuit_data_ref(),
            op_register_user
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
        );
        trace_timer.lap("built agg_state_transition");
        let agg_state_transition_dummy = AggStateTransitionDummyCircuit::new();
        trace_timer.lap("built agg_state_transition_dummy");

        // operation aggregators
        let agg_state_transition_with_events = AggStateTransitionWithEventsCircuit::new(
            op_process_l1_withdrawal.get_common_circuit_data_ref(),
            op_process_l1_withdrawal
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
        );
        trace_timer.lap("built agg_state_transition_with_events");
        let agg_state_transition_with_events_dummy =
            AggStateTransitionWithEventsDummyCircuit::new();
        trace_timer.lap("built agg_state_transition_with_events_dummy");

        let mut result = Self {
            network_magic,
            zk_signature_wrapper,
            l1_secp256k1_signature,
            op_register_user,
            op_claim_l1_deposit,
            op_l2_transfer,
            op_add_l1_withdrawal,
            op_add_l1_deposit,
            op_process_l1_withdrawal,
            agg_state_transition,
            agg_state_transition_dummy,
            agg_state_transition_with_events,
            agg_state_transition_with_events_dummy,
            fingerprints: Default::default(),
        };
        let fc = result.get_fingerprint_config();
        result.fingerprints = fc;
        result
    }
    pub fn get_fingerprint_config(&self) -> CRWorkerToolboxCoreCircuitFingerprints<C::F> {
        let agg_state_transition_fingerprint = self.agg_state_transition.get_fingerprint();

        let agg_state_transition_with_events_fingerprint =
            self.agg_state_transition_with_events.get_fingerprint();

        let agg_state_transition_dummy_fingerprint =
            self.agg_state_transition_dummy.get_fingerprint();
        let agg_state_transition_with_events_dummy_fingerprint = self
            .agg_state_transition_with_events_dummy
            .get_fingerprint();

        CRWorkerToolboxCoreCircuitFingerprints {
            network_magic: self.network_magic,
            zk_signature_wrapper: self.zk_signature_wrapper.get_fingerprint(),
            l1_secp256k1_signature: self.l1_secp256k1_signature.get_fingerprint(),

            op_register_user: TPCircuitFingerprintConfig::from_leaf_and_agg_fingerprints_with_type::<
                C::Hasher,
            >(
                self.op_register_user.get_fingerprint(),
                agg_state_transition_fingerprint,
                agg_state_transition_dummy_fingerprint,
                ProvingJobCircuitType::RegisterUser.to_u8(),
                ProvingJobCircuitType::RegisterUserAggregate.to_u8(),
            ),
            op_claim_l1_deposit:
                TPCircuitFingerprintConfig::from_leaf_and_agg_fingerprints_with_type::<C::Hasher>(
                    self.op_claim_l1_deposit.get_fingerprint(),
                    agg_state_transition_fingerprint,
                    agg_state_transition_dummy_fingerprint,
                    ProvingJobCircuitType::ClaimL1Deposit.to_u8(),
                    ProvingJobCircuitType::ClaimL1DepositAggregate.to_u8(),
                ),
            op_l2_transfer: TPCircuitFingerprintConfig::from_leaf_and_agg_fingerprints_with_type::<
                C::Hasher,
            >(
                self.op_l2_transfer.get_fingerprint(),
                agg_state_transition_fingerprint,
                agg_state_transition_dummy_fingerprint,
                ProvingJobCircuitType::TransferTokensL2.to_u8(),
                ProvingJobCircuitType::TransferTokensL2Aggregate.to_u8(),
            ),
            op_add_l1_withdrawal:
                TPCircuitFingerprintConfig::from_leaf_and_agg_fingerprints_with_type::<C::Hasher>(
                    self.op_add_l1_withdrawal.get_fingerprint(),
                    agg_state_transition_fingerprint,
                    agg_state_transition_dummy_fingerprint,
                    ProvingJobCircuitType::AddL1Withdrawal.to_u8(),
                    ProvingJobCircuitType::AddL1WithdrawalAggregate.to_u8(),
                ),
            op_add_l1_deposit: TPCircuitFingerprintConfig::from_leaf_and_agg_fingerprints_with_type::<
                C::Hasher,
            >(
                self.op_add_l1_deposit.get_fingerprint(),
                agg_state_transition_with_events_fingerprint,
                agg_state_transition_with_events_dummy_fingerprint,
                ProvingJobCircuitType::AddL1Deposit.to_u8(),
                ProvingJobCircuitType::AddL1DepositAggregate.to_u8(),
            ),
            op_process_l1_withdrawal:
                TPCircuitFingerprintConfig::from_leaf_and_agg_fingerprints_with_type::<C::Hasher>(
                    self.op_process_l1_withdrawal.get_fingerprint(),
                    agg_state_transition_with_events_fingerprint,
                    agg_state_transition_with_events_dummy_fingerprint,
                    ProvingJobCircuitType::ProcessL1Withdrawal.to_u8(),
                    ProvingJobCircuitType::ProcessL1WithdrawalAggregate.to_u8(),
                ),
            agg_state_transition: agg_state_transition_fingerprint,
            agg_state_transition_with_events: agg_state_transition_with_events_fingerprint,
            agg_state_transition_dummy: agg_state_transition_dummy_fingerprint,
            agg_state_transition_with_events_dummy:
                agg_state_transition_with_events_dummy_fingerprint,
        }
    }
    pub fn print_op_common_data(&self) {
        self.op_register_user
            .print_config_with_name("op_register_user");

        self.op_claim_l1_deposit
            .print_config_with_name("op_claim_l1_deposit");

        self.op_l2_transfer.print_config_with_name("op_l2_transfer");

        self.op_add_l1_withdrawal
            .print_config_with_name("op_add_l1_withdrawal");

        self.op_add_l1_deposit
            .print_config_with_name("op_add_l1_deposit");

        self.op_process_l1_withdrawal
            .print_config_with_name("op_process_l1_withdrawal");

        self.agg_state_transition
            .print_config_with_name("agg_state_transition");

        self.agg_state_transition_dummy
            .print_config_with_name("agg_state_transition_dummy");

        self.agg_state_transition_with_events
            .print_config_with_name("agg_state_transition_with_events");

        self.agg_state_transition_with_events_dummy
            .print_config_with_name("agg_state_transition_with_events_dummy");
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QWorkerVerifyHelper<C, D>
    for CRWorkerToolboxCoreCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
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
            ProvingJobCircuitType::RegisterUser => self.op_register_user.get_verifier_triplet(),
            ProvingJobCircuitType::RegisterUserAggregate => {
                self.agg_state_transition.get_verifier_triplet()
            }
            ProvingJobCircuitType::AddL1Deposit => self.op_add_l1_deposit.get_verifier_triplet(),
            ProvingJobCircuitType::AddL1DepositAggregate => {
                self.agg_state_transition_with_events.get_verifier_triplet()
            }
            ProvingJobCircuitType::ClaimL1Deposit => {
                self.op_claim_l1_deposit.get_verifier_triplet()
            }
            ProvingJobCircuitType::ClaimL1DepositAggregate => {
                self.agg_state_transition.get_verifier_triplet()
            }
            ProvingJobCircuitType::TransferTokensL2 => self.op_l2_transfer.get_verifier_triplet(),
            ProvingJobCircuitType::TransferTokensL2Aggregate => {
                self.agg_state_transition.get_verifier_triplet()
            }
            ProvingJobCircuitType::AddL1Withdrawal => {
                self.op_add_l1_withdrawal.get_verifier_triplet()
            }
            ProvingJobCircuitType::AddL1WithdrawalAggregate => {
                self.agg_state_transition.get_verifier_triplet()
            }
            ProvingJobCircuitType::ProcessL1Withdrawal => {
                self.op_process_l1_withdrawal.get_verifier_triplet()
            }
            ProvingJobCircuitType::ProcessL1WithdrawalAggregate => {
                self.agg_state_transition_with_events.get_verifier_triplet()
            }
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => todo!(),
            ProvingJobCircuitType::GenerateSigHashIntrospectionProof => todo!(),
            ProvingJobCircuitType::GenerateFinalSigHashProof => todo!(),
            ProvingJobCircuitType::GenerateFinalSigHashProofGroth16 => todo!(),
            ProvingJobCircuitType::DummyRegisterUserAggregate => {
                self.agg_state_transition_dummy.get_verifier_triplet()
            }
            ProvingJobCircuitType::DummyAddL1DepositAggregate => self
                .agg_state_transition_with_events_dummy
                .get_verifier_triplet(),
            ProvingJobCircuitType::DummyClaimL1DepositAggregate => {
                self.agg_state_transition_dummy.get_verifier_triplet()
            }
            ProvingJobCircuitType::DummyTransferTokensL2Aggregate => {
                self.agg_state_transition_dummy.get_verifier_triplet()
            }
            ProvingJobCircuitType::DummyAddL1WithdrawalAggregate => {
                self.agg_state_transition_dummy.get_verifier_triplet()
            }
            ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate => self
                .agg_state_transition_with_events_dummy
                .get_verifier_triplet(),
            ProvingJobCircuitType::WrappedSignatureProof => {
                self.zk_signature_wrapper.get_verifier_triplet()
            }
            ProvingJobCircuitType::Secp256K1SignatureProof => {
                self.l1_secp256k1_signature.get_verifier_triplet()
            }
            ProvingJobCircuitType::Unknown => panic!("cannot get circuit data for Unknown"),
            ProvingJobCircuitType::AggUserRegisterClaimDepositL2Transfer => {
                panic!("cannot get circuit data for AggUserRegisterClaimDepositL2Transfer")
            }
            ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit => {
                panic!("cannot get circuit data for AggAddProcessL1WithdrawalAddL1Deposit")
            }
            ProvingJobCircuitType::WrapFinalSigHashProofBLS12381 => {
                panic!("WrapFinalSigHashProofBLS12381 is not a standard circuit")
            }
        }
    }

    fn get_tree_prover_fingerprint_config(
        &self,
        circuit_type: ProvingJobCircuitType,
    ) -> anyhow::Result<TPCircuitFingerprintConfig<C::F>> {
        match circuit_type {
            ProvingJobCircuitType::RegisterUserAggregate => Ok(self.fingerprints.op_register_user),
            ProvingJobCircuitType::AddL1DepositAggregate => Ok(self.fingerprints.op_add_l1_deposit),
            ProvingJobCircuitType::ClaimL1DepositAggregate => {
                Ok(self.fingerprints.op_claim_l1_deposit)
            }
            ProvingJobCircuitType::TransferTokensL2Aggregate => {
                Ok(self.fingerprints.op_l2_transfer)
            }
            ProvingJobCircuitType::AddL1WithdrawalAggregate => {
                Ok(self.fingerprints.op_add_l1_withdrawal)
            }
            ProvingJobCircuitType::ProcessL1WithdrawalAggregate => {
                Ok(self.fingerprints.op_process_l1_withdrawal)
            }
            _ => Err(anyhow::anyhow!(
                "circuit of type {:?} does not have a leaf fingerprint",
                circuit_type
            )),
        }
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QWorkerGenericProver<S, C, D> for CRWorkerToolboxCoreCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn worker_prove(
        &self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let circuit_type = job_id.circuit_type;
        match circuit_type {
            ProvingJobCircuitType::RegisterUser => self
                .op_register_user
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::RegisterUserAggregate => self
                .agg_state_transition
                .prove_q_worker_agg(self, store, job_id),
            ProvingJobCircuitType::AddL1Deposit => self
                .op_add_l1_deposit
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::AddL1DepositAggregate => self
                .agg_state_transition_with_events
                .prove_q_worker_agg(self, store, job_id),
            ProvingJobCircuitType::ClaimL1Deposit => self
                .op_claim_l1_deposit
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::ClaimL1DepositAggregate => self
                .agg_state_transition
                .prove_q_worker_agg(self, store, job_id),
            ProvingJobCircuitType::TransferTokensL2 => self
                .op_l2_transfer
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::TransferTokensL2Aggregate => self
                .agg_state_transition
                .prove_q_worker_agg(self, store, job_id),
            ProvingJobCircuitType::AddL1Withdrawal => self
                .op_add_l1_withdrawal
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::AddL1WithdrawalAggregate => self
                .agg_state_transition
                .prove_q_worker_agg(self, store, job_id),
            ProvingJobCircuitType::ProcessL1Withdrawal => self
                .op_process_l1_withdrawal
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::ProcessL1WithdrawalAggregate => self
                .agg_state_transition_with_events
                .prove_q_worker_agg(self, store, job_id),
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => todo!(),
            ProvingJobCircuitType::GenerateSigHashIntrospectionProof => todo!(),
            ProvingJobCircuitType::GenerateFinalSigHashProof => todo!(),
            ProvingJobCircuitType::GenerateFinalSigHashProofGroth16 => todo!(),
            ProvingJobCircuitType::DummyRegisterUserAggregate => self
                .agg_state_transition_dummy
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::DummyAddL1DepositAggregate => self
                .agg_state_transition_with_events_dummy
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::DummyClaimL1DepositAggregate => self
                .agg_state_transition_dummy
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::DummyTransferTokensL2Aggregate => self
                .agg_state_transition_dummy
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::DummyAddL1WithdrawalAggregate => self
                .agg_state_transition_dummy
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate => self
                .agg_state_transition_with_events_dummy
                .prove_q_worker_simple(self, store, job_id),
            ProvingJobCircuitType::WrappedSignatureProof => todo!(),
            ProvingJobCircuitType::Secp256K1SignatureProof => todo!(),
            ProvingJobCircuitType::Unknown => todo!(),
            ProvingJobCircuitType::AggUserRegisterClaimDepositL2Transfer => todo!(),
            ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit => todo!(),
            ProvingJobCircuitType::WrapFinalSigHashProofBLS12381 => todo!(),
        }
    }
}
