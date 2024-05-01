use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{PartialWitness, Witness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::{
    btc::data::rollup::signature::QEDSigAction, common::builder::core::CircuitBuilderHelpersCore,
};

pub struct SimpleQEDSigAction {
    pub network_magic: Target,
    pub user: Target,
    pub sig_action: Target,
    pub nonce: Target,
    pub action_arguments: Vec<Target>,
    pub sig_action_hash: HashOutTarget,
}

pub fn compute_sig_action_hash_circuit<
    H: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    network_magic: Target,
    user: Target,
    sig_action: Target,
    nonce: Target,
    action_arguments: &[Target],
) -> HashOutTarget {
    let arguments_hash = builder.hash_n_to_hash_no_pad::<H>(action_arguments.to_vec());
    builder.hash_n_to_hash_no_pad::<H>(vec![
        network_magic,
        user,
        sig_action,
        nonce,
        arguments_hash.elements[0],
        arguments_hash.elements[1],
        arguments_hash.elements[2],
        arguments_hash.elements[3],
    ])
}

impl SimpleQEDSigAction {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        action_arguments_length: usize,
        network_magic: Option<u64>,
    ) -> Self {
        let network_magic = if network_magic.is_some() {
            builder.constant_u64(network_magic.unwrap())
        } else {
            builder.add_virtual_target()
        };
        let user = builder.add_virtual_target();
        let sig_action = builder.add_virtual_target();
        let nonce = builder.add_virtual_target();
        let action_arguments = builder.add_virtual_targets(action_arguments_length);
        let sig_action_hash = compute_sig_action_hash_circuit::<H, F, D>(
            builder,
            network_magic,
            user,
            sig_action,
            nonce,
            &action_arguments,
        );
        Self {
            network_magic,
            user,
            sig_action,
            nonce,
            action_arguments,
            sig_action_hash,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut PartialWitness<F>,
        sig_action_hint: &QEDSigAction<F>,
    ) {
        witness.set_target(self.network_magic, sig_action_hint.network_magic);
        witness.set_target(self.user, sig_action_hint.user);
        witness.set_target(self.sig_action, sig_action_hint.sig_action);
        witness.set_target(self.nonce, sig_action_hint.nonce);
        witness.set_target_arr(&self.action_arguments, &sig_action_hint.action_arguments);
    }
}
