use city_crypto::hash::{
    merkle::{
        core::DeltaMerkleProofCore,
        treeprover::{
            AggStateTrackableInput, AggStateTrackableWithEventsInput, AggStateTransition,
            AggStateTransitionWithEvents,
        },
    },
    qhashout::QHashOut,
};
use kvq::traits::KVQSerializable;
use plonky2::{
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    plonk::config::Hasher,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;

use crate::{
    introspection::rollup::introspection_result::BTCRollupIntrospectionResultDeposit,
    qworker::job_id::QProvingJobDataID,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CircuitInputWithJobId<I: Debug + Clone + Serialize + DeserializeOwned + PartialEq> {
    pub input: I,
    pub job_id: QProvingJobDataID,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CircuitInputWithDependencies<I: Debug + Clone + Serialize + DeserializeOwned + PartialEq>
{
    pub input: I,
    pub dependencies: Vec<QProvingJobDataID>,
}
impl<I: Debug + Clone + Serialize + DeserializeOwned + PartialEq> CircuitInputWithJobId<I> {
    pub fn new(input: I, job_id: QProvingJobDataID) -> Self {
        Self { input, job_id }
    }
}
impl<
        I: Debug + Clone + Serialize + DeserializeOwned + PartialEq + AggStateTrackableInput<F>,
        F: RichField,
    > AggStateTrackableInput<F> for CircuitInputWithJobId<I>
{
    fn get_state_transition(&self) -> AggStateTransition<F> {
        self.input.get_state_transition()
    }
}

impl<
        I: Debug
            + Clone
            + Serialize
            + DeserializeOwned
            + PartialEq
            + AggStateTrackableWithEventsInput<F>,
        F: RichField,
    > AggStateTrackableWithEventsInput<F> for CircuitInputWithJobId<I>
{
    fn get_state_transition_with_events(&self) -> AggStateTransitionWithEvents<F> {
        self.input.get_state_transition_with_events()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRAddL1DepositCircuitInput<F: RichField> {
    pub deposit_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes_root: QHashOut<F>,
}

impl<F: RichField> AggStateTrackableWithEventsInput<F> for CRAddL1DepositCircuitInput<F> {
    fn get_state_transition_with_events(&self) -> AggStateTransitionWithEvents<F> {
        AggStateTransitionWithEvents {
            state_transition_start: self.deposit_tree_delta_merkle_proof.old_root,
            state_transition_end: self.deposit_tree_delta_merkle_proof.new_root,
            event_hash: self.deposit_tree_delta_merkle_proof.new_value,
        }
    }
}
impl<F: RichField> KVQSerializable for CRAddL1DepositCircuitInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRAddL1WithdrawalCircuitInput<F: RichField> {
    pub user_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub withdrawal_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes_root: QHashOut<F>,
    pub signature_proof_id: QProvingJobDataID,
}
impl<F: RichField> AggStateTrackableInput<F> for CRAddL1WithdrawalCircuitInput<F> {
    fn get_state_transition(&self) -> AggStateTransition<F> {
        AggStateTransition {
            state_transition_start: QHashOut(PoseidonHash::two_to_one(
                self.user_tree_delta_merkle_proof.old_root.0,
                self.withdrawal_tree_delta_merkle_proof.old_root.0,
            )),
            state_transition_end: QHashOut(PoseidonHash::two_to_one(
                self.user_tree_delta_merkle_proof.new_root.0,
                self.withdrawal_tree_delta_merkle_proof.new_root.0,
            )),
        }
    }
}

impl<F: RichField> KVQSerializable for CRAddL1WithdrawalCircuitInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRClaimL1DepositCircuitInput<F: RichField> {
    pub deposit: BTCRollupIntrospectionResultDeposit<F>,
    pub user_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub deposit_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes_root: QHashOut<F>,
    pub signature_proof_id: QProvingJobDataID,
}
impl<F: RichField> AggStateTrackableInput<F> for CRClaimL1DepositCircuitInput<F> {
    fn get_state_transition(&self) -> AggStateTransition<F> {
        AggStateTransition {
            state_transition_start: QHashOut(PoseidonHash::two_to_one(
                self.user_tree_delta_merkle_proof.old_root.0,
                self.deposit_tree_delta_merkle_proof.old_root.0,
            )),
            state_transition_end: QHashOut(PoseidonHash::two_to_one(
                self.user_tree_delta_merkle_proof.new_root.0,
                self.deposit_tree_delta_merkle_proof.new_root.0,
            )),
        }
    }
}
impl<F: RichField> KVQSerializable for CRClaimL1DepositCircuitInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRL2TransferCircuitInput<F: RichField> {
    pub sender_user_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub receiver_user_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes_root: QHashOut<F>,
    pub signature_proof_id: QProvingJobDataID,
}
impl<F: RichField> AggStateTrackableInput<F> for CRL2TransferCircuitInput<F> {
    fn get_state_transition(&self) -> AggStateTransition<F> {
        AggStateTransition {
            state_transition_start: self.sender_user_tree_delta_merkle_proof.old_root,
            state_transition_end: self.receiver_user_tree_delta_merkle_proof.new_root,
        }
    }
}
impl<F: RichField> KVQSerializable for CRL2TransferCircuitInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRProcessL1WithdrawalCircuitInput<F: RichField> {
    pub withdrawal_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes_root: QHashOut<F>,
}

impl<F: RichField> AggStateTrackableWithEventsInput<F> for CRProcessL1WithdrawalCircuitInput<F> {
    fn get_state_transition_with_events(&self) -> AggStateTransitionWithEvents<F> {
        AggStateTransitionWithEvents {
            state_transition_start: self.withdrawal_tree_delta_merkle_proof.old_root,
            state_transition_end: self.withdrawal_tree_delta_merkle_proof.new_root,
            event_hash: self.withdrawal_tree_delta_merkle_proof.new_value,
        }
    }
}

impl<F: RichField> KVQSerializable for CRProcessL1WithdrawalCircuitInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRUserRegistrationCircuitInput<F: RichField> {
    pub user_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes_root: QHashOut<F>,
}
impl<F: RichField> AggStateTrackableInput<F> for CRUserRegistrationCircuitInput<F> {
    fn get_state_transition(&self) -> AggStateTransition<F> {
        AggStateTransition {
            state_transition_start: self.user_tree_delta_merkle_proof.old_root,
            state_transition_end: self.user_tree_delta_merkle_proof.new_root,
        }
    }
}

impl<F: RichField> KVQSerializable for CRUserRegistrationCircuitInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
}
