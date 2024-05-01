use core::fmt::Debug;
use plonky2::field::types::PrimeField64;

use crate::common::builder::core::{TargetResolverCore, WitnessHelpersCore};
use crate::common::builder::hash::hash256bytes::WitnessHash256;
use plonky2::field::types::Field;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use serde::{Deserialize, Serialize};
use starkyx::{
    chip::{uint::operations::instruction::UintInstructions, AirParameters, Chip},
    machine::{bytes::builder::BytesBuilder, hash::sha::algorithm::SHAir},
    math::extension::CubicParameters,
    plonky2::Plonky2Air,
};

use crate::common::{
    builder::hash::{
        hash160bytes::Hash160BytesTarget,
        hash256bytes::{CircuitBuilderHash256Bytes, Hash256BytesTarget},
        ripemd160::CircuitBuilderHashRipemd160,
    },
    hash::core::sha256::CoreSha256Hasher,
};

use super::smartgadget::{PlannedHash256BytesTarget, SmartSha256AcceleratorGadget};

pub type Sha256AcceleratorDomainID = usize;

pub trait Sha256AcceleratorDomainResolver {
    fn set_witness_for_domain(
        &mut self,
        domain_id: Sha256AcceleratorDomainID,
        preimages: &[Vec<u8>],
    );
    fn set_witness_for_domain_refs(
        &mut self,
        domain_id: Sha256AcceleratorDomainID,
        preimages: &[&[u8]],
    );
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sha256AcceleratorDomain {
    pub planned_hashes: Vec<PlannedHash256BytesTarget>,
    pub derived_hash_ids: Vec<usize>,
    pub witnessed_hash_ids: Vec<usize>,
}
impl Sha256AcceleratorDomain {
    pub fn new() -> Self {
        Self {
            planned_hashes: Vec::new(),
            derived_hash_ids: Vec::new(),
            witnessed_hash_ids: Vec::new(),
        }
    }
    pub fn add_sha256_input<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage_length: usize,
    ) -> (Vec<Target>, Hash256BytesTarget) {
        let preimage = builder.add_virtual_targets(preimage_length);
        let digest = builder.add_virtual_hash256_bytes_target();

        self.witnessed_hash_ids.push(self.planned_hashes.len());
        self.planned_hashes
            .push(PlannedHash256BytesTarget { preimage, digest });

        (self.planned_hashes.last().unwrap().preimage.clone(), digest)
    }

    pub fn add_sha256_input_ref<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage_length: usize,
    ) -> (&[Target], Hash256BytesTarget) {
        let preimage = builder.add_virtual_targets(preimage_length);
        let digest = builder.add_virtual_hash256_bytes_target();

        self.witnessed_hash_ids.push(self.planned_hashes.len());
        self.planned_hashes
            .push(PlannedHash256BytesTarget { preimage, digest });

        (&self.planned_hashes.last().unwrap().preimage, digest)
    }
    pub fn sha256<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage: &[Target],
    ) -> Hash256BytesTarget {
        self.derived_hash_ids.push(self.planned_hashes.len());
        let digest = builder.add_virtual_hash256_bytes_target();
        self.planned_hashes.push(PlannedHash256BytesTarget {
            preimage: preimage.to_vec(),
            digest,
        });
        digest
    }

    pub fn add_btc_hash256_input_ref<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage_length: usize,
    ) -> (&[Target], Hash256BytesTarget) {
        let combo = self.add_sha256_input_ref(builder, preimage_length).1;

        let final_digest = self.sha256(builder, &combo);
        (
            &self.planned_hashes[self.planned_hashes.len() - 2].preimage,
            final_digest,
        )
    }
    pub fn add_btc_hash256_input<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage_length: usize,
    ) -> (Vec<Target>, Hash256BytesTarget) {
        let first_digest_index = self.planned_hashes.len();
        let first_digest = self.add_sha256_input_ref(builder, preimage_length).1;
        let final_digest = self.sha256(builder, &first_digest);
        (
            self.planned_hashes[first_digest_index].preimage.clone(),
            final_digest,
        )
    }
    pub fn btc_hash256<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage: &[Target],
    ) -> Hash256BytesTarget {
        let first = self.sha256(builder, preimage);
        self.sha256(builder, &first)
    }

    pub fn add_btc_hash160_input_ref<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage_length: usize,
    ) -> (&[Target], Hash160BytesTarget) {
        let (preimage, first_digest) = self.add_sha256_input_ref(builder, preimage_length);
        let final_digest = builder.hash_ripemd160_hash256_bytes(first_digest);
        (preimage, final_digest)
    }
    pub fn add_btc_hash160_input<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage_length: usize,
    ) -> (Vec<Target>, Hash160BytesTarget) {
        let (preimage, first_digest) = self.add_sha256_input_ref(builder, preimage_length);
        let final_digest = builder.hash_ripemd160_hash256_bytes(first_digest);
        (preimage.to_vec(), final_digest)
    }
    pub fn btc_hash160<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage: &[Target],
    ) -> Hash160BytesTarget {
        let first_digest = self.sha256(builder, preimage);
        builder.hash_ripemd160_hash256_bytes(first_digest)
    }
    pub fn set_witness_iter<
        'a,
        W: Witness<F>,
        F: RichField + Extendable<D>,
        const D: usize,
        Iter: Iterator<Item = &'a [u8]>,
    >(
        &self,
        witness: &mut W,
        preimages: Iter,
    ) {
        self.witnessed_hash_ids
            .iter()
            .zip(preimages)
            .for_each(|(hash_id, p)| {
                let digest = CoreSha256Hasher::hash_bytes(p);
                witness.set_hash256_bytes_target(&self.planned_hashes[*hash_id].digest, &digest.0);
                witness.set_target_arr(
                    &self.planned_hashes[*hash_id].preimage,
                    &p.iter()
                        .map(|x| F::from_canonical_u8(*x))
                        .collect::<Vec<F>>(),
                )
            });
    }
    pub fn set_witness_vec<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        witness: &mut W,
        preimages: &[Vec<u8>],
    ) {
        self.witnessed_hash_ids
            .iter()
            .zip(preimages)
            .for_each(|(hash_id, p)| {
                let digest = CoreSha256Hasher::hash_bytes(p);
                witness.set_hash256_bytes_target(&self.planned_hashes[*hash_id].digest, &digest.0);
                witness.set_target_arr(
                    &self.planned_hashes[*hash_id].preimage,
                    &p.iter()
                        .map(|x| F::from_canonical_u8(*x))
                        .collect::<Vec<F>>(),
                )
            });
    }

    pub fn set_witness_refs<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        witness: &mut W,
        preimages: &[&[u8]],
    ) {
        self.witnessed_hash_ids
            .iter()
            .zip(preimages)
            .for_each(|(hash_id, p)| {
                let digest = CoreSha256Hasher::hash_bytes(p);
                witness.set_hash256_bytes_target(&self.planned_hashes[*hash_id].digest, &digest.0);
                witness.set_target_arr(
                    &self.planned_hashes[*hash_id].preimage,
                    &p.iter()
                        .map(|x| F::from_canonical_u8(*x))
                        .collect::<Vec<F>>(),
                )
            });
    }
    pub fn process_derived_pass<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        witness: &mut W,
    ) {
        self.derived_hash_ids.iter().for_each(|hash_id| {
            let bytes = self.planned_hashes[*hash_id]
                .preimage
                .iter()
                .map(|t| witness.try_get_target(*t).unwrap().to_canonical_u64() as u8)
                .collect::<Vec<u8>>();
            let digest = CoreSha256Hasher::hash_bytes(&bytes);
            witness.set_hash256_bytes_target(&self.planned_hashes[*hash_id].digest, &digest.0);
        });
    }
}
impl Default for Sha256AcceleratorDomain {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Debug)]
pub struct Sha256AcceleratorDomainPlanner {
    pub domains: Vec<Sha256AcceleratorDomain>,
    pub next_domain_id: Sha256AcceleratorDomainID,
}

impl Sha256AcceleratorDomainPlanner {
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            next_domain_id: 0,
        }
    }
    pub fn register_domain(
        &mut self,
        domain: &Sha256AcceleratorDomain,
    ) -> Sha256AcceleratorDomainID {
        let id = self.next_domain_id;
        self.next_domain_id += 1;
        self.domains.push(domain.clone());
        id
    }
    pub fn get_seq_full(
        mut self,
    ) -> (
        Vec<PlannedHash256BytesTarget>,
        Vec<PlannedHash256BytesTarget>,
        Vec<Vec<usize>>,
    ) {
        let mut witness_hashes: Vec<PlannedHash256BytesTarget> = Vec::new();
        let mut derived_hashes: Vec<PlannedHash256BytesTarget> = Vec::new();
        let mut domain_witness_ids: Vec<Vec<usize>> = Vec::new();
        self.domains.iter_mut().enumerate().for_each(|(_, domain)| {
            let start_index = witness_hashes.len();
            let w_ids = domain.witnessed_hash_ids.clone();
            domain_witness_ids.push(
                domain
                    .witnessed_hash_ids
                    .iter()
                    .map(|id| id + start_index)
                    .collect::<Vec<_>>(),
            );
            domain
                .planned_hashes
                .drain(0..domain.planned_hashes.len())
                .into_iter()
                .enumerate()
                .for_each(|(i, p_hash)| {
                    // let global_id = i + start_index;
                    if w_ids.contains(&i) {
                        witness_hashes.push(p_hash);
                    } else {
                        derived_hashes.push(p_hash);
                    }
                });
        });
        (witness_hashes, derived_hashes, domain_witness_ids)
    }
}

#[derive(Clone, Debug)]
pub struct Sha256AcceleratorDomainPlannerOld {
    pub witness_hashes: Vec<PlannedHash256BytesTarget>,
    pub derived_hashes: Vec<PlannedHash256BytesTarget>,
    pub domain_witness_hashes: Vec<Vec<usize>>,
    pub next_domain_id: Sha256AcceleratorDomainID,
    pub prepared_preimages: Vec<Vec<u8>>,
}

impl Sha256AcceleratorDomainPlannerOld {
    pub fn new() -> Self {
        Self {
            witness_hashes: Vec::new(),
            derived_hashes: Vec::new(),
            domain_witness_hashes: Vec::new(),
            next_domain_id: 0,
            prepared_preimages: Vec::new(),
        }
    }
    pub fn register_domain(
        &mut self,
        domain: &mut Sha256AcceleratorDomain,
    ) -> Sha256AcceleratorDomainID {
        let start_index = self.witness_hashes.len();
        let w_ids = domain.witnessed_hash_ids.clone();
        // let d_ids = domain.derived_hash_ids.clone();
        let global_witness_ids = domain
            .witnessed_hash_ids
            .iter()
            .map(|id| id + start_index)
            .collect::<Vec<_>>();
        domain
            .planned_hashes
            .drain(0..domain.planned_hashes.len())
            .into_iter()
            .enumerate()
            .for_each(|(i, p_hash)| {
                // let global_id = i + start_index;
                if w_ids.contains(&i) {
                    self.witness_hashes.push(p_hash);
                } else {
                    self.derived_hashes.push(p_hash);
                }
            });

        let id = self.next_domain_id;
        self.next_domain_id += 1;
        self.domain_witness_hashes.push(global_witness_ids);
        id
    }
}

#[derive(Clone, Debug)]
pub struct SmartSha256AcceleratorGadgetWithDomain<
    S: SHAir<BytesBuilder<L>, CYCLE_LENGTH>,
    L: AirParameters<Field = C::F>,
    C: 'static + GenericConfig<D>,
    const D: usize,
    const CYCLE_LENGTH: usize,
> where
    L::Instruction: UintInstructions,
    L::CubicParams: CubicParameters<C::F>,
    Chip<L>: Plonky2Air<C::F, D>,
    S::Integer: PartialEq + Eq + Debug,
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub combo_hashes: Vec<PlannedHash256BytesTarget>,
    pub split_point: usize,
    pub witness_domain_map: Vec<Vec<usize>>,
    pub finalized_order: Vec<Sha256AcceleratorDomainID>,
    pub witness_preimages: Vec<Vec<u8>>,
    pub accelerator: SmartSha256AcceleratorGadget<S, L, C, D, CYCLE_LENGTH>,
}

impl<
        S: SHAir<BytesBuilder<L>, CYCLE_LENGTH>,
        L: AirParameters<Field = C::F>,
        C: 'static + GenericConfig<D>,
        const D: usize,
        const CYCLE_LENGTH: usize,
    > SmartSha256AcceleratorGadgetWithDomain<S, L, C, D, CYCLE_LENGTH>
where
    L::Instruction: UintInstructions,
    L::CubicParams: CubicParameters<C::F>,
    Chip<L>: Plonky2Air<C::F, D>,
    S::Integer: PartialEq + Eq + Debug,
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        builder: &mut CircuitBuilder<C::F, D>,
        planner: Sha256AcceleratorDomainPlanner,
    ) -> Self {
        let (witness_hashes, derived_hashes, witness_domain_map) = planner.get_seq_full();
        let w_len = witness_hashes.len();
        let combo_hashes = vec![witness_hashes, derived_hashes].concat();
        let accelerator = SmartSha256AcceleratorGadget::finalize_planner(builder, &combo_hashes);

        Self {
            witness_domain_map,
            split_point: w_len,
            finalized_order: Vec::new(),
            witness_preimages: Vec::new(),
            combo_hashes,
            accelerator,
        }
    }
    pub fn finalize_witness<W: Witness<C::F>, R: TargetResolverCore<C::F>>(
        &mut self,
        witness: &mut W,
        alt_resolver: &R,
    ) {
        let mut preimage_order_finalized: Vec<Vec<u8>> = Vec::new();
        let mut preimages_index = 0usize;
        self.finalized_order.iter().for_each(|domain_id| {
            self.witness_domain_map[*domain_id]
                .iter()
                .for_each(|hash_id| {
                    let digest =
                        CoreSha256Hasher::hash_bytes(&self.witness_preimages[preimages_index]);
                    witness
                        .set_hash256_bytes_target(&self.combo_hashes[*hash_id].digest, &digest.0);
                    println!(
                        "finwit: {}, {}",
                        self.combo_hashes[*hash_id].preimage.len(),
                        self.witness_preimages[preimages_index].len()
                    );
                    assert_eq!(
                        self.combo_hashes[*hash_id].preimage.len(),
                        self.witness_preimages[preimages_index].len(),
                        "Preimage length mismatch"
                    );
                    witness.set_target_arr(
                        &self.combo_hashes[*hash_id].preimage,
                        &self.witness_preimages[preimages_index]
                            .iter()
                            .map(|x| C::F::from_canonical_u8(*x))
                            .collect::<Vec<C::F>>(),
                    );

                    preimage_order_finalized.push(self.witness_preimages[preimages_index].clone());
                    preimages_index += 1;
                });
        });
        self.witness_preimages = vec![];
        self.finalized_order = vec![];
        self.combo_hashes[self.split_point..].iter().for_each(|ch| {
            let preimage_r = witness
                .resolve_targets_or_constants(alt_resolver, &ch.preimage)
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect::<Vec<u8>>();
            let digest = CoreSha256Hasher::hash_bytes(&preimage_r);
            preimage_order_finalized.push(preimage_r);
            witness.set_hash256_bytes_target(&ch.digest, &digest.0);
        });
        self.accelerator
            .set_witness(witness, &preimage_order_finalized);
    }
}
impl<
        S: SHAir<BytesBuilder<L>, CYCLE_LENGTH>,
        L: AirParameters<Field = C::F>,
        C: 'static + GenericConfig<D>,
        const D: usize,
        const CYCLE_LENGTH: usize,
    > Sha256AcceleratorDomainResolver
    for SmartSha256AcceleratorGadgetWithDomain<S, L, C, D, CYCLE_LENGTH>
where
    L::Instruction: UintInstructions,
    L::CubicParams: CubicParameters<C::F>,
    Chip<L>: Plonky2Air<C::F, D>,
    S::Integer: PartialEq + Eq + Debug,
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn set_witness_for_domain(
        &mut self,
        domain_id: Sha256AcceleratorDomainID,
        preimages: &[Vec<u8>],
    ) {
        self.finalized_order.push(domain_id);
        self.witness_preimages.extend_from_slice(preimages);
    }

    fn set_witness_for_domain_refs(
        &mut self,
        domain_id: Sha256AcceleratorDomainID,
        preimages: &[&[u8]],
    ) {
        self.finalized_order.push(domain_id);
        let mut base = preimages.iter().map(|x| x.to_vec()).collect::<Vec<_>>();
        self.witness_preimages.append(&mut base);
    }
}
