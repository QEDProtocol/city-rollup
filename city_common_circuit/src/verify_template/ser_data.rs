use plonky2::fri::{reduction_strategies::FriReductionStrategy, FriConfig, FriParams};
use serde::{Deserialize, Serialize};

/// A method for deciding what arity to use at each reduction layer.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum VTFriReductionStrategy {
    Fixed(Vec<usize>),
    ConstantArityBits(usize, usize),
    MinSize(Option<usize>),
}
impl VTFriReductionStrategy {
    pub fn to_code(&self) -> String {
        match self {
            VTFriReductionStrategy::Fixed(v) => format!(
                "VTFriReductionStrategy::Fixed(vec!{})",
                serde_json::to_string(v).unwrap()
            ),
            VTFriReductionStrategy::ConstantArityBits(a, b) => {
                format!("VTFriReductionStrategy::ConstantArityBits({}, {})", *a, *b)
            }
            VTFriReductionStrategy::MinSize(op) => {
                if op.is_none() {
                    "VTFriReductionStrategy::MinSize(None)".to_string()
                } else {
                    format!("VTFriReductionStrategy::MinSize(Some({}))", op.unwrap())
                }
            }
        }
    }
}
impl From<FriReductionStrategy> for VTFriReductionStrategy {
    fn from(value: FriReductionStrategy) -> Self {
        match value {
            FriReductionStrategy::Fixed(v) => VTFriReductionStrategy::Fixed(v),
            FriReductionStrategy::ConstantArityBits(a, b) => {
                VTFriReductionStrategy::ConstantArityBits(a, b)
            }
            FriReductionStrategy::MinSize(v) => VTFriReductionStrategy::MinSize(v),
        }
    }
}

impl Into<FriReductionStrategy> for VTFriReductionStrategy {
    fn into(self) -> FriReductionStrategy {
        match self {
            VTFriReductionStrategy::Fixed(v) => FriReductionStrategy::Fixed(v),
            VTFriReductionStrategy::ConstantArityBits(a, b) => {
                FriReductionStrategy::ConstantArityBits(a, b)
            }
            VTFriReductionStrategy::MinSize(v) => FriReductionStrategy::MinSize(v),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VTFriConfig {
    /// `rate = 2^{-rate_bits}`.
    pub rate_bits: usize,

    /// Height of Merkle tree caps.
    pub cap_height: usize,

    /// Number of bits used for grinding.
    pub proof_of_work_bits: u32,

    /// The reduction strategy to be applied at each layer during the commit phase.
    pub reduction_strategy: VTFriReductionStrategy,

    /// Number of query rounds to perform.
    pub num_query_rounds: usize,
}
impl VTFriConfig {
    pub fn to_code(&self) -> String {
        format!(
            "VTFriConfig {{ rate_bits: {}, cap_height: {}, proof_of_work_bits: {}, reduction_strategy: {}, num_query_rounds: {} }}",
            self.rate_bits,
            self.cap_height,
            self.proof_of_work_bits,
            self.reduction_strategy.to_code(),
            self.num_query_rounds
        )
    }
}

impl From<FriConfig> for VTFriConfig {
    fn from(value: FriConfig) -> Self {
        Self {
            rate_bits: value.rate_bits,
            cap_height: value.cap_height,
            proof_of_work_bits: value.proof_of_work_bits,
            reduction_strategy: value.reduction_strategy.into(),
            num_query_rounds: value.num_query_rounds,
        }
    }
}
impl Into<FriConfig> for VTFriConfig {
    fn into(self) -> FriConfig {
        FriConfig {
            rate_bits: self.rate_bits,
            cap_height: self.cap_height,
            proof_of_work_bits: self.proof_of_work_bits,
            reduction_strategy: self.reduction_strategy.into(),
            num_query_rounds: self.num_query_rounds,
        }
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VTFriParams {
    /// User-specified FRI configuration.
    pub config: VTFriConfig,

    /// Whether to use a hiding variant of Merkle trees (where random salts are added to leaves).
    pub hiding: bool,

    /// The degree of the purported codeword, measured in bits.
    pub degree_bits: usize,

    /// The arity of each FRI reduction step, expressed as the log2 of the actual arity.
    /// For example, `[3, 2, 1]` would describe a FRI reduction tree with 8-to-1 reduction, then
    /// a 4-to-1 reduction, then a 2-to-1 reduction. After these reductions, the reduced polynomial
    /// is sent directly.
    pub reduction_arity_bits: Vec<usize>,
}
impl VTFriParams {
    pub fn to_code(&self) -> String {
        format!(
            "VTFriParams {{ config: {}, hiding: {}, degree_bits: {}, reduction_arity_bits: vec!{} }}",
            self.config.to_code(),
            self.hiding,
            self.degree_bits,
            serde_json::to_string(&self.reduction_arity_bits).unwrap()
        )
    }
}
impl From<FriParams> for VTFriParams {
    fn from(value: FriParams) -> Self {
        Self {
            config: value.config.into(),
            hiding: value.hiding,
            degree_bits: value.degree_bits,
            reduction_arity_bits: value.reduction_arity_bits,
        }
    }
}
impl Into<FriParams> for VTFriParams {
    fn into(self) -> FriParams {
        FriParams {
            config: self.config.into(),
            hiding: self.hiding,
            degree_bits: self.degree_bits,
            reduction_arity_bits: self.reduction_arity_bits,
        }
    }
}
