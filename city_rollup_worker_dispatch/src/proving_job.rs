use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_with::serde_as;

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash)]
#[repr(u8)]
pub enum ProvingJobType {
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
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash)]
#[repr(u8)]
pub enum ProvingJobDataType {
    InputWitness = 0,
    BaseInputProofA = 1,
    BaseInputProofB = 2,
    BaseInputProofC = 3,
    BaseInputProofD = 4,
    BaseInputProofE = 5,
    BaseInputProofF = 6,
    BaseInputProofG = 7,
    OutputProof = 8,
    Counter = 16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ProvingJobDataID {
    pub parent_group: u32,
    pub task_group: u32,
    pub task_sub_group: u32,
    pub task_index: u32,
    pub job_type: ProvingJobType,
    pub job_data_type: ProvingJobDataType,
}
impl ProvingJobDataID {
    pub fn new(
        parent_group: u32,
        task_group: u32,
        task_sub_group: u32,
        task_index: u32,
        job_type: ProvingJobType,
        job_data_type: ProvingJobDataType,
    ) -> Self {
        Self {
            parent_group,
            task_group,
            task_sub_group,
            task_index,
            job_type,
            job_data_type,
        }
    }
    pub fn get_output_proof_id(&self) -> Self {
        Self {
            parent_group: self.parent_group,
            task_group: self.task_group,
            task_sub_group: self.task_sub_group,
            task_index: self.task_index,
            job_type: self.job_type,
            job_data_type: ProvingJobDataType::OutputProof,
        }
    }
    pub fn get_counter_id(&self) -> Self {
        Self {
            parent_group: self.parent_group,
            task_group: self.task_group,
            task_sub_group: self.task_sub_group,
            task_index: 0,
            job_type: self.job_type,
            job_data_type: ProvingJobDataType::Counter,
        }
    }
}
impl ToString for ProvingJobDataID {
    fn to_string(&self) -> String {
        hex::encode(postcard::to_allocvec(self).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::{ProvingJobDataID, ProvingJobDataType, ProvingJobType};

    #[test]
    fn test_decode() {
        let job = ProvingJobDataID::new(
            1,
            0,
            0,
            0,
            ProvingJobType::AddL1Deposit,
            ProvingJobDataType::InputWitness,
        );
        println!("job: {:?}", job);

        let result = postcard::to_allocvec(&job).unwrap();
        let hex_value = hex::encode(&result);
        println!("got result: {}", hex_value);

        let decoded_job: ProvingJobDataID = postcard::from_bytes(&result).unwrap();

        assert_eq!(job, decoded_job);
    }
}
