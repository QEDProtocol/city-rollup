use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::AlgebraicHasher,
};
use serde::{Deserialize, Serialize};

use crate::common::{
    hash::traits::hasher::{MerkleHasher, MerkleHasherWithMarkedLeaf, QHasher},
    QHashOut,
};

pub fn compute_partial_merkle_root_from_leaves_algebraic<F: RichField, H: AlgebraicHasher<F>>(
    leaves: &[HashOut<F>],
) -> HashOut<F> {
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = vec![];
        for i in 0..current.len() / 2 {
            next.push(H::two_to_one(current[2 * i], current[2 * i + 1]));
        }
        if current.len() % 2 == 1 {
            next.push(current[current.len() - 1]);
        }
        current = next;
    }
    current[0]
}
pub fn compute_partial_merkle_root_from_leaves<
    Hash: PartialEq + Copy,
    Hasher: MerkleHasher<Hash>,
>(
    leaves: &[Hash],
) -> Hash {
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = vec![];
        for i in 0..current.len() / 2 {
            next.push(Hasher::two_to_one(&current[2 * i], &current[2 * i + 1]));
        }
        if current.len() % 2 == 1 {
            next.push(current[current.len() - 1]);
        }
        current = next;
    }
    current[0]
}
pub fn compute_root_merkle_proof<H: QHasher<F>, F: RichField>(
    value: QHashOut<F>,
    index: F,
    siblings: &[QHashOut<F>],
) -> QHashOut<F> {
    let mut current = value;
    let index = index.to_canonical_u64();
    for (i, sibling) in siblings.iter().enumerate() {
        if index & (1 << i) == 0 {
            current = H::q_two_to_one(current, *sibling);
        } else {
            current = H::q_two_to_one(*sibling, current);
        }
    }
    current
}
pub fn verify_merkle_proof<H: QHasher<F>, F: RichField>(proof: &MerkleProof<F>) -> bool {
    compute_root_merkle_proof::<H, F>(proof.value, proof.index, &proof.siblings) == proof.root
}
pub fn verify_delta_merkle_proof<H: QHasher<F>, F: RichField>(proof: &DeltaMerkleProof<F>) -> bool {
    compute_root_merkle_proof::<H, F>(proof.old_value, proof.index, &proof.siblings)
        == proof.old_root
        && compute_root_merkle_proof::<H, F>(proof.new_value, proof.index, &proof.siblings)
            == proof.new_root
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MerkleProofBase<F: RichField> {
    pub value: QHashOut<F>,
    pub index: F,
    pub siblings: Vec<QHashOut<F>>,
}
impl<F: RichField> MerkleProofBase<F> {
    pub fn compute_root<H: QHasher<F>>(&self) -> QHashOut<F> {
        compute_root_merkle_proof::<H, F>(self.value, self.index, &self.siblings)
    }
    pub fn to_merkle_proof<H: QHasher<F>>(&self) -> MerkleProof<F> {
        MerkleProof {
            root: self.compute_root::<H>(),
            value: self.value,
            index: self.index,
            siblings: self.siblings.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MerkleProof<F: RichField> {
    pub root: QHashOut<F>,
    pub value: QHashOut<F>,
    pub index: F,
    pub siblings: Vec<QHashOut<F>>,
}

impl<F: RichField> MerkleProof<F> {
    pub fn verify<H: QHasher<F>>(&self) -> bool {
        verify_merkle_proof::<H, F>(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DeltaMerkleProofBase<F: RichField> {
    pub old_value: QHashOut<F>,
    pub new_value: QHashOut<F>,
    pub index: F,
    pub siblings: Vec<QHashOut<F>>,
}
impl<F: RichField> DeltaMerkleProofBase<F> {
    pub fn compute_old_root<H: QHasher<F>>(&self) -> QHashOut<F> {
        compute_root_merkle_proof::<H, F>(self.old_value, self.index, &self.siblings)
    }
    pub fn compute_new_root<H: QHasher<F>>(&self) -> QHashOut<F> {
        compute_root_merkle_proof::<H, F>(self.new_value, self.index, &self.siblings)
    }
    pub fn to_delta_merkle_proof<H: QHasher<F>>(&self) -> DeltaMerkleProof<F> {
        DeltaMerkleProof {
            old_root: self.compute_old_root::<H>(),
            old_value: self.old_value,
            new_root: self.compute_new_root::<H>(),
            new_value: self.new_value,
            index: self.index,
            siblings: self.siblings.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DeltaMerkleProof<F: RichField> {
    pub old_root: QHashOut<F>,
    pub old_value: QHashOut<F>,
    pub new_root: QHashOut<F>,
    pub new_value: QHashOut<F>,
    pub index: F,
    pub siblings: Vec<QHashOut<F>>,
}

impl<F: RichField> DeltaMerkleProof<F> {
    pub fn verify<H: QHasher<F>>(&self) -> bool {
        verify_delta_merkle_proof::<H, F>(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleProofCore<Hash: PartialEq + Copy> {
    pub root: Hash,
    pub value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

impl<Hash: PartialEq + Copy> MerkleProofCore<Hash> {
    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool {
        verify_merkle_proof_core::<Hash, Hasher>(self)
    }
    pub fn verify_marked<Hasher: MerkleHasherWithMarkedLeaf<Hash>>(&self) -> bool {
        verify_merkle_proof_marked_leaves_core::<Hash, Hasher>(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeltaMerkleProofCorePartial<Hash: PartialEq + Copy> {
    pub old_value: Hash,
    pub new_value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeltaMerkleProofCore<Hash: PartialEq + Copy> {
    pub old_root: Hash,
    pub old_value: Hash,

    pub new_root: Hash,
    pub new_value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}
impl<Hash: PartialEq + Copy> DeltaMerkleProofCore<Hash> {
    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool {
        verify_delta_merkle_proof_core::<Hash, Hasher>(self)
    }
    pub fn verify_marked<Hasher: MerkleHasherWithMarkedLeaf<Hash>>(&self) -> bool {
        verify_delta_merkle_proof_marked_leaves_core::<Hash, Hasher>(self)
    }
}
pub fn verify_merkle_proof_core<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(
    proof: &MerkleProofCore<Hash>,
) -> bool {
    let mut current = proof.value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    current == proof.root
}
pub fn verify_delta_merkle_proof_core<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(
    proof: &DeltaMerkleProofCore<Hash>,
) -> bool {
    let mut current = proof.old_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    if current != proof.old_root {
        return false;
    }
    current = proof.new_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    current == proof.new_root
}

pub fn verify_merkle_proof_marked_leaves_core<
    Hash: PartialEq + Copy,
    Hasher: MerkleHasher<Hash>,
>(
    proof: &MerkleProofCore<Hash>,
) -> bool {
    let mut current = proof.value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    current == proof.root
}
pub fn verify_delta_merkle_proof_marked_leaves_core<
    Hash: PartialEq + Copy,
    Hasher: MerkleHasherWithMarkedLeaf<Hash>,
>(
    proof: &DeltaMerkleProofCore<Hash>,
) -> bool {
    let mut current = proof.old_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if i == 0 {
            if proof.index & (1 << i) == 0 {
                current = Hasher::two_to_one_marked_leaf(&current, sibling);
            } else {
                current = Hasher::two_to_one_marked_leaf(sibling, &current);
            }
        } else {
            // for non leaves, we hash like normal
            if proof.index & (1 << i) == 0 {
                current = Hasher::two_to_one(&current, sibling);
            } else {
                current = Hasher::two_to_one(sibling, &current);
            }
        }
    }
    if current != proof.old_root {
        return false;
    }
    current = proof.new_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    current == proof.new_root
}

pub fn calc_merkle_root_from_leaves<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(
    leaves: Vec<Hash>,
) -> Hash {
    let mut current_leaves: Vec<Hash> = leaves
        .chunks_exact(2)
        .map(|chunk| Hasher::two_to_one(&chunk[0], &chunk[1]))
        .collect();
    let height = (current_leaves.len() as f64).log2().ceil() as usize;
    for _ in 1..height {
        let next_leaves = current_leaves
            .chunks_exact(2)
            .map(|chunk| Hasher::two_to_one(&chunk[0], &chunk[1]))
            .collect();
        current_leaves = next_leaves;
    }
    current_leaves[0]
}
