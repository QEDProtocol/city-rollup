use city_crypto::hash::{
    merkle::core::{DeltaMerkleProof, DeltaMerkleProofCore},
    qhashout::QHashOut,
};
use plonky2::{
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::introspection::rollup::introspection_result::BTCRollupIntrospectionResultDeposit;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CityTokenTransferPlanned<C: GenericConfig<D>, const D: usize> {
    pub sender_user_tree_delta_merkle_proof: DeltaMerkleProof<C::F>,
    pub receiver_user_tree_delta_merkle_proof: DeltaMerkleProof<C::F>,
    pub signature_proof: ProofWithPublicInputs<C::F, C, D>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]

pub struct CityClaimDepositPlanned<C: GenericConfig<D>, const D: usize> {
    pub user_tree_delta_merkle_proof: DeltaMerkleProof<C::F>,
    pub deposit_tree_delta_merkle_proof: DeltaMerkleProof<C::F>,
    pub deposit_result: BTCRollupIntrospectionResultDeposit<C::F>,
    pub signature_proof: ProofWithPublicInputs<C::F, C, D>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CityAddDepositPlanned<F: RichField> {
    pub deposit_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CityAddWithdrawalPlanned<C: GenericConfig<D>, const D: usize> {
    pub user_tree_delta_merkle_proof: DeltaMerkleProof<C::F>,
    pub withdrawal_tree_delta_merkle_proof: DeltaMerkleProof<C::F>,
    pub signature_proof: ProofWithPublicInputs<C::F, C, D>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CityProcessWithdrawalPlanned<F: RichField> {
    pub withdrawal_tree_delta_merkle_proof: DeltaMerkleProof<F>,
}
