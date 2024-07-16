use clap::ValueEnum;
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(
    Serialize_repr,
    Deserialize_repr,
    PartialEq,
    Debug,
    Clone,
    Copy,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ValueEnum,
)]
#[repr(u32)]
pub enum QWorkerMode {
    All = 0,
    NoGroth16 = 1,
    OnlyGroth16 = 2,
}
impl QWorkerMode {
    pub fn to_u32(&self) -> u32 {
        *self as u32
    }
    pub fn is_groth16_enabled(&self) -> bool {
        match self {
            QWorkerMode::All => true,
            QWorkerMode::NoGroth16 => false,
            QWorkerMode::OnlyGroth16 => true,
        }
    }
}
impl From<QWorkerMode> for u32 {
    fn from(value: QWorkerMode) -> u32 {
        value as u32
    }
}
impl TryFrom<u32> for QWorkerMode {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QWorkerMode::All),
            1 => Ok(QWorkerMode::NoGroth16),
            2 => Ok(QWorkerMode::OnlyGroth16),
            _ => Err(anyhow::format_err!("Invalid QWorkerMode value: {}", value)),
        }
    }
}

impl ToString for QWorkerMode {
    fn to_string(&self) -> String {
        match *self {
            QWorkerMode::All => "all".to_string(),
            QWorkerMode::NoGroth16 => "no-groth16".to_string(),
            QWorkerMode::OnlyGroth16 => "only-groth16".to_string(),
        }
    }
}

#[derive(
    Serialize_repr,
    Deserialize_repr,
    PartialEq,
    Debug,
    Clone,
    Copy,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ValueEnum,
)]
#[repr(u32)]
pub enum QDumpInspectionData {
    DependencyMap = 0,
    JobConfig = 1,
    SignatureProofIds = 2,
    ProofWitnesses = 3,
    ProofPublicInputs = 4,
    Proofs = 5,
}
impl QDumpInspectionData {
    pub fn to_u32(&self) -> u32 {
        *self as u32
    }
}
impl From<QDumpInspectionData> for u32 {
    fn from(value: QDumpInspectionData) -> u32 {
        value as u32
    }
}
impl TryFrom<u32> for QDumpInspectionData {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QDumpInspectionData::DependencyMap),
            1 => Ok(QDumpInspectionData::JobConfig),
            2 => Ok(QDumpInspectionData::SignatureProofIds),
            3 => Ok(QDumpInspectionData::ProofWitnesses),
            4 => Ok(QDumpInspectionData::ProofPublicInputs),
            5 => Ok(QDumpInspectionData::Proofs),
            _ => Err(anyhow::format_err!(
                "Invalid QDumpInspectionData value: {}",
                value
            )),
        }
    }
}

impl ToString for QDumpInspectionData {
    fn to_string(&self) -> String {
        match *self {
            QDumpInspectionData::DependencyMap => "dependency-map".to_string(),
            QDumpInspectionData::JobConfig => "job-config".to_string(),
            QDumpInspectionData::SignatureProofIds => "signature-proof-ids".to_string(),
            QDumpInspectionData::ProofWitnesses => "proof-witnesses".to_string(),
            QDumpInspectionData::ProofPublicInputs => "proof-public-inputs".to_string(),
            QDumpInspectionData::Proofs => "proofs".to_string(),
        }
    }
}
