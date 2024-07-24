use city_common::data::u8bytes::U8Bytes;
use city_crypto::hash::merkle::treeprover::{AggStateTransitionInput, AggStateTransitionWithEventsInput, DummyAggStateTransition, DummyAggStateTransitionWithEvents};
use plonky2::{hash::hash_types::RichField, plonk::{config::GenericConfig, proof::ProofWithPublicInputs}};
use serde::{Deserialize, Serialize};

use crate::qworker::{job_id::{ProvingJobCircuitType, QProvingJobDataID}, job_witnesses::sighash::CRSigHashRootCircuitInput};

use super::{agg::{CRAggAddProcessL1WithdrawalAddL1DepositCircuitInput, CRAggUserRegisterClaimDepositL2TransferCircuitInput, CRBlockStateTransitionCircuitInput}, op::{CRAddL1DepositCircuitInput, CRAddL1WithdrawalCircuitInput, CRClaimL1DepositCircuitInput, CRL2TransferCircuitInput, CRProcessL1WithdrawalCircuitInput, CRUserRegistrationCircuitInput}, sighash::{CRSigHashFinalGLCircuitInput, CRSigHashWrapperCircuitInput}};

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct QJobProofPublicInputs<F: RichField> {
    pub job_id: QProvingJobDataID,
    pub public_inputs: Vec<F>,
}
impl<F: RichField> QJobProofPublicInputs<F> {
    pub fn new(job_id: QProvingJobDataID, public_inputs: Vec<F>) -> Self {
        Self { job_id, public_inputs }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct QJobProofProofOutput<C: GenericConfig<D>, const D: usize> {
    pub job_id: QProvingJobDataID,
    pub proof: ProofWithPublicInputs<C::F, C, D>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct QJobWitnessWithId<F: RichField> {
    pub job_id: QProvingJobDataID,
    pub witness: QJobWitness<F>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
#[serde(tag = "q_witness_type")]
pub enum QJobWitness<F: RichField> {
    RegisterUser(CRUserRegistrationCircuitInput<F>),
    RegisterUserAggregate(AggStateTransitionInput<F>),
    AddL1Deposit(CRAddL1DepositCircuitInput<F>),
    AddL1DepositAggregate(AggStateTransitionWithEventsInput<F>),
    ClaimL1Deposit(CRClaimL1DepositCircuitInput<F>),
    ClaimL1DepositAggregate(AggStateTransitionInput<F>),
    TransferTokensL2(CRL2TransferCircuitInput<F>),
    TransferTokensL2Aggregate(AggStateTransitionInput<F>),
    AddL1Withdrawal(CRAddL1WithdrawalCircuitInput<F>),
    AddL1WithdrawalAggregate(AggStateTransitionInput<F>),
    ProcessL1Withdrawal(CRProcessL1WithdrawalCircuitInput<F>),
    ProcessL1WithdrawalAggregate(AggStateTransitionWithEventsInput<F>),
    GenerateRollupStateTransitionProof(CRBlockStateTransitionCircuitInput<F>),
    GenerateSigHashIntrospectionProof(CRSigHashWrapperCircuitInput<F>),
    GenerateFinalSigHashProof(CRSigHashFinalGLCircuitInput<F>),
    WrapFinalSigHashProofBLS12381(QProvingJobDataID),
    AggUserRegisterClaimDepositL2Transfer(CRAggUserRegisterClaimDepositL2TransferCircuitInput<F>),
    AggAddProcessL1WithdrawalAddL1Deposit(CRAggAddProcessL1WithdrawalAddL1DepositCircuitInput<F>),
    DummyRegisterUserAggregate(DummyAggStateTransition<F>),
    DummyAddL1DepositAggregate(DummyAggStateTransitionWithEvents<F>),
    DummyClaimL1DepositAggregate(DummyAggStateTransition<F>),
    DummyTransferTokensL2Aggregate(DummyAggStateTransition<F>),
    DummyAddL1WithdrawalAggregate(DummyAggStateTransition<F>),
    DummyProcessL1WithdrawalAggregate(DummyAggStateTransitionWithEvents<F>),
    RawBytes(U8Bytes),
}

impl<F: RichField> QJobWitness<F> {
    pub fn can_deserialize_witness(job_id: QProvingJobDataID) -> bool {
        match job_id.circuit_type {
            ProvingJobCircuitType::RegisterUser => true,
            ProvingJobCircuitType::RegisterUserAggregate => true,
            ProvingJobCircuitType::AddL1Deposit => true,
            ProvingJobCircuitType::AddL1DepositAggregate => true,
            ProvingJobCircuitType::ClaimL1Deposit => true,
            ProvingJobCircuitType::ClaimL1DepositAggregate => true,
            ProvingJobCircuitType::TransferTokensL2 => true,
            ProvingJobCircuitType::TransferTokensL2Aggregate => true,
            ProvingJobCircuitType::AddL1Withdrawal => true,
            ProvingJobCircuitType::AddL1WithdrawalAggregate => true,
            ProvingJobCircuitType::ProcessL1Withdrawal => true,
            ProvingJobCircuitType::ProcessL1WithdrawalAggregate => true,
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => true,
            ProvingJobCircuitType::GenerateSigHashIntrospectionProof => true,
            ProvingJobCircuitType::GenerateFinalSigHashProof => true,
            ProvingJobCircuitType::WrapFinalSigHashProofBLS12381 => true,
            ProvingJobCircuitType::AggUserRegisterClaimDepositL2Transfer => true,
            ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit => true,
            ProvingJobCircuitType::DummyRegisterUserAggregate => true,
            ProvingJobCircuitType::DummyAddL1DepositAggregate => true,
            ProvingJobCircuitType::DummyClaimL1DepositAggregate => true,
            ProvingJobCircuitType::DummyTransferTokensL2Aggregate => true,
            ProvingJobCircuitType::DummyAddL1WithdrawalAggregate => true,
            ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate => true,
            _ => false,
        }
    }
    pub fn try_deserialize_witness(job_id: QProvingJobDataID, data: &[u8]) -> anyhow::Result<Self> {
        match job_id.circuit_type {
            ProvingJobCircuitType::RegisterUser => Ok(Self::RegisterUser(bincode::deserialize(data)?)),
            ProvingJobCircuitType::RegisterUserAggregate => Ok(Self::RegisterUserAggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::AddL1Deposit => Ok(Self::AddL1Deposit(bincode::deserialize(data)?)),
            ProvingJobCircuitType::AddL1DepositAggregate => Ok(Self::AddL1DepositAggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::ClaimL1Deposit => Ok(Self::ClaimL1Deposit(bincode::deserialize(data)?)),
            ProvingJobCircuitType::ClaimL1DepositAggregate => Ok(Self::ClaimL1DepositAggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::TransferTokensL2 => Ok(Self::TransferTokensL2(bincode::deserialize(data)?)),
            ProvingJobCircuitType::TransferTokensL2Aggregate => Ok(Self::TransferTokensL2Aggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::AddL1Withdrawal => Ok(Self::AddL1Withdrawal(bincode::deserialize(data)?)),
            ProvingJobCircuitType::AddL1WithdrawalAggregate => Ok(Self::AddL1WithdrawalAggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::ProcessL1Withdrawal => Ok(Self::ProcessL1Withdrawal(bincode::deserialize(data)?)),
            ProvingJobCircuitType::ProcessL1WithdrawalAggregate => Ok(Self::ProcessL1WithdrawalAggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => Ok(Self::GenerateRollupStateTransitionProof(bincode::deserialize(data)?)),
            ProvingJobCircuitType::GenerateSigHashIntrospectionProof => Ok(Self::GenerateSigHashIntrospectionProof(bincode::deserialize(data)?)),
            ProvingJobCircuitType::GenerateFinalSigHashProof => Ok(Self::GenerateFinalSigHashProof(bincode::deserialize(data)?)),
            ProvingJobCircuitType::WrapFinalSigHashProofBLS12381 => Ok(Self::WrapFinalSigHashProofBLS12381(bincode::deserialize(data)?)),
            ProvingJobCircuitType::AggUserRegisterClaimDepositL2Transfer => Ok(Self::AggUserRegisterClaimDepositL2Transfer(bincode::deserialize(data)?)),
            ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit => Ok(Self::AggAddProcessL1WithdrawalAddL1Deposit(bincode::deserialize(data)?)),
            ProvingJobCircuitType::DummyRegisterUserAggregate => Ok(Self::DummyRegisterUserAggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::DummyAddL1DepositAggregate => Ok(Self::DummyAddL1DepositAggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::DummyClaimL1DepositAggregate => Ok(Self::DummyClaimL1DepositAggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::DummyTransferTokensL2Aggregate => Ok(Self::DummyTransferTokensL2Aggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::DummyAddL1WithdrawalAggregate => Ok(Self::DummyAddL1WithdrawalAggregate(bincode::deserialize(data)?)),
            ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate => Ok(Self::DummyProcessL1WithdrawalAggregate(bincode::deserialize(data)?)),
            _ => Ok(Self::RawBytes(U8Bytes::from(data.to_vec()))),
        }
    }
}

impl<F: RichField> QJobWitnessWithId<F> {
    pub fn try_deserialize_witness(job_id: QProvingJobDataID, data: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            job_id,
            witness: QJobWitness::try_deserialize_witness(job_id, data)?,
        })
    }
    pub fn can_deserialize_witness(job_id: QProvingJobDataID) -> bool {
        QJobWitness::<F>::can_deserialize_witness(job_id)
    }
}
