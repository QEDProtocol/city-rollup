use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(
    Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord,
)]
#[repr(u8)]
pub enum QJobTopic {
    GenerateStandardProof = 0,
    GenerateGroth16Proof = 1,
    BlockUserSignatureProof = 2,
}
impl QJobTopic {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<QJobTopic> for u8 {
    fn from(value: QJobTopic) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for QJobTopic {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QJobTopic::GenerateStandardProof),
            1 => Ok(QJobTopic::GenerateGroth16Proof),
            2 => Ok(QJobTopic::BlockUserSignatureProof),
            _ => Err(anyhow::format_err!("Invalid QJobTopic value: {}", value)),
        }
    }
}

#[derive(
    Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord,
)]
#[repr(u8)]
pub enum ProvingJobDataType {
    InputWitness = 0,
    BaseInputProof = 1,
    OutputProof = 8,
    Counter = 16,
}
impl ProvingJobDataType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl TryFrom<u8> for ProvingJobDataType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProvingJobDataType::InputWitness),
            1 => Ok(ProvingJobDataType::BaseInputProof),
            8 => Ok(ProvingJobDataType::OutputProof),
            16 => Ok(ProvingJobDataType::Counter),
            _ => Err(anyhow::format_err!(
                "Invalid ProvingJobDataType value: {}",
                value
            )),
        }
    }
}
impl From<ProvingJobDataType> for u8 {
    fn from(value: ProvingJobDataType) -> u8 {
        value as u8
    }
}

#[derive(
    Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord,
)]
#[repr(u8)]
pub enum ProvingJobCircuitType {
    RegisterUser = 0,
    RegisterUserAggregate = 1,

    AddL1Deposit = 2,
    AddL1DepositAggregate = 3,

    ClaimL1Deposit = 4,
    ClaimL1DepositAggregate = 5,

    TransferTokensL2 = 6,
    TransferTokensL2Aggregate = 7,

    AddL1Withdrawal = 8,
    AddL1WithdrawalAggregate = 9,

    ProcessL1Withdrawal = 10,
    ProcessL1WithdrawalAggregate = 11,

    GenerateRollupStateTransitionProof = 32,
    GenerateSigHashIntrospectionProof = 33,
    GenerateFinalSigHashProof = 34,
    GenerateFinalSigHashProofGroth16 = 35,

    DummyRegisterUserAggregate = 48,
    DummyAddL1DepositAggregate = 49,
    DummyClaimL1DepositAggregate = 50,
    DummyTransferTokensL2Aggregate = 51,
    DummyAddL1WithdrawalAggregate = 52,
    DummyProcessL1WithdrawalAggregate = 53,

    WrappedSignatureProof = 64,
    Secp256K1SignatureProof = 65,
    Unknown = 255,
}

impl ProvingJobCircuitType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
    pub fn to_circuit_group_id(&self) -> u32 {
        (self.to_u8() as u32) + 0xCF00u32
    }
}

impl TryFrom<u8> for ProvingJobCircuitType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProvingJobCircuitType::RegisterUser),
            1 => Ok(ProvingJobCircuitType::RegisterUserAggregate),
            2 => Ok(ProvingJobCircuitType::AddL1Deposit),
            3 => Ok(ProvingJobCircuitType::AddL1DepositAggregate),
            4 => Ok(ProvingJobCircuitType::ClaimL1Deposit),
            5 => Ok(ProvingJobCircuitType::ClaimL1DepositAggregate),
            6 => Ok(ProvingJobCircuitType::TransferTokensL2),
            7 => Ok(ProvingJobCircuitType::TransferTokensL2Aggregate),
            8 => Ok(ProvingJobCircuitType::AddL1Withdrawal),
            9 => Ok(ProvingJobCircuitType::AddL1WithdrawalAggregate),
            10 => Ok(ProvingJobCircuitType::ProcessL1Withdrawal),
            11 => Ok(ProvingJobCircuitType::ProcessL1WithdrawalAggregate),
            32 => Ok(ProvingJobCircuitType::GenerateRollupStateTransitionProof),
            33 => Ok(ProvingJobCircuitType::GenerateSigHashIntrospectionProof),
            34 => Ok(ProvingJobCircuitType::GenerateFinalSigHashProof),
            35 => Ok(ProvingJobCircuitType::GenerateFinalSigHashProofGroth16),
            48 => Ok(ProvingJobCircuitType::DummyRegisterUserAggregate),
            49 => Ok(ProvingJobCircuitType::DummyAddL1DepositAggregate),
            50 => Ok(ProvingJobCircuitType::DummyClaimL1DepositAggregate),
            51 => Ok(ProvingJobCircuitType::DummyTransferTokensL2Aggregate),
            52 => Ok(ProvingJobCircuitType::DummyAddL1WithdrawalAggregate),
            53 => Ok(ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate),
            64 => Ok(ProvingJobCircuitType::WrappedSignatureProof),
            65 => Ok(ProvingJobCircuitType::Secp256K1SignatureProof),
            255 => Ok(ProvingJobCircuitType::Unknown),
            _ => Err(anyhow::format_err!(
                "Invalid ProvingJobCircuitType value: {}",
                value
            )),
        }
    }
}

impl From<ProvingJobCircuitType> for u8 {
    fn from(value: ProvingJobCircuitType) -> Self {
        value as u8
    }
}

pub type QProvingJobDataIDSerialized = [u8; 24];

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct QProvingJobDataID {
    pub topic: QJobTopic,
    pub goal_id: u64,
    pub circuit_type: ProvingJobCircuitType,
    pub group_id: u32,
    pub sub_group_id: u32,
    pub task_index: u32,
    pub data_type: ProvingJobDataType,
    pub data_index: u8,
}
impl From<&QProvingJobDataID> for [u8; 24] {
    fn from(value: &QProvingJobDataID) -> Self {
        let mut result = [0u8; 24];
        result[0] = value.topic.to_u8();
        result[1..9].copy_from_slice(&value.goal_id.to_le_bytes());
        result[9] = value.circuit_type.to_u8();
        result[10..14].copy_from_slice(&value.group_id.to_le_bytes());
        result[14..18].copy_from_slice(&value.sub_group_id.to_le_bytes());
        result[18..22].copy_from_slice(&value.task_index.to_le_bytes());
        result[22] = value.data_type.to_u8();
        result[23] = value.data_index;
        result
    }
}
impl TryFrom<[u8; 24]> for QProvingJobDataID {
    type Error = anyhow::Error;
    fn try_from(value: [u8; 24]) -> Result<Self, Self::Error> {
        let topic: QJobTopic = value[0].try_into()?;
        let goal_id = u64::from_le_bytes(value[1..9].try_into()?);
        let circuit_type = ProvingJobCircuitType::try_from(value[9])?;
        let group_id = u32::from_le_bytes(value[10..14].try_into()?);
        let sub_group_id = u32::from_le_bytes(value[14..18].try_into()?);
        let task_index = u32::from_le_bytes(value[18..22].try_into()?);
        let data_type = ProvingJobDataType::try_from(value[22])?;
        let data_index = value[23];
        Ok(QProvingJobDataID {
            topic,
            goal_id,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type,
            data_index,
        })
    }
}

impl QProvingJobDataID {
    pub fn new(
        topic: QJobTopic,
        goal_id: u64,
        group_id: u32,
        sub_group_id: u32,
        task_index: u32,
        circuit_type: ProvingJobCircuitType,
        data_type: ProvingJobDataType,
        data_index: u8,
    ) -> Self {
        Self {
            topic,
            goal_id,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type,
            data_index,
        }
    }
    pub fn transfer_signature_proof(rpc_node_id: u32, block_id: u64, transfer_id: u32) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: block_id,
            group_id: 1,
            circuit_type: ProvingJobCircuitType::WrappedSignatureProof,
            sub_group_id: rpc_node_id,
            task_index: transfer_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn withdrawal_signature_proof(rpc_node_id: u32, block_id: u64, withdrawal_id: u32) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: block_id,
            group_id: 2,
            circuit_type: ProvingJobCircuitType::WrappedSignatureProof,
            sub_group_id: rpc_node_id,
            task_index: withdrawal_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn claim_deposit_l1_signature_proof(
        rpc_node_id: u32,
        block_id: u64,
        deposit_id: u32,
    ) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: block_id,
            group_id: 2,
            circuit_type: ProvingJobCircuitType::Secp256K1SignatureProof,
            sub_group_id: rpc_node_id,
            task_index: deposit_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn new_proof_job_id(
        goal_id: u64,
        circuit_type: ProvingJobCircuitType,
        group_id: u32,
        sub_group_id: u32,
        task_index: u32,
    ) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn new_groth16_proof_job_id(
        goal_id: u64,
        circuit_type: ProvingJobCircuitType,
        group_id: u32,
        sub_group_id: u32,
        task_index: u32,
    ) -> Self {
        Self {
            topic: QJobTopic::GenerateGroth16Proof,
            goal_id,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn get_input_proof_id(&self, data_index: u8) -> Self {
        Self {
            data_type: ProvingJobDataType::BaseInputProof,
            data_index,
            ..*self
        }
    }
    pub fn get_tree_parent_proof_input_id(&self) -> Self {
        Self {
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
            sub_group_id: self.sub_group_id + 1,
            task_index: self.sub_group_id >> 1u32,
            ..*self
        }
    }
    pub fn get_output_id(&self) -> Self {
        Self {
            data_type: ProvingJobDataType::OutputProof,
            data_index: 0,
            ..*self
        }
    }
    pub fn get_sub_group_counter_id(&self) -> Self {
        Self {
            data_type: ProvingJobDataType::Counter,
            data_index: 0,
            ..*self
        }
    }
    pub fn to_fixed_bytes(&self) -> QProvingJobDataIDSerialized {
        self.into()
    }
}
#[cfg(test)]
mod tests {
    use super::{ProvingJobCircuitType, QProvingJobDataID};

    #[test]
    fn test_decode() {
        let job =
            QProvingJobDataID::new_proof_job_id(1, ProvingJobCircuitType::AddL1Deposit, 0, 0, 0);

        let result = bincode::serialize(&job).unwrap();

        let result2 = job.to_fixed_bytes();
        assert_eq!(result, result2.to_vec());

        let decoded_job: QProvingJobDataID = bincode::deserialize(&result).unwrap();

        assert_eq!(job, decoded_job);
        let decoded_job2: QProvingJobDataID = bincode::deserialize(&result2).unwrap();

        assert_eq!(job, decoded_job2);
    }
}
