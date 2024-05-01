use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::witness::{PartialWitness, Witness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            self, CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use city_mono::{
    cityrollup::agg_circuits::state_transition_track_events::{
        AggStateTrackableWithEventsInput, AggStateTransitionWithEventsCircuit,
        AggWTTELeafAggregator, StateTransitionWithEvents,
    },
    common::{
        builder::{hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers},
        hash::{
            merkle::{
                gadgets::delta_merkle_proof::DeltaMerkleProofGadget,
                helpers::merkle_proof::{DeltaMerkleProof, DeltaMerkleProofCore},
            },
            traits::hasher::{MerkleHasher, PoseidonHasher},
        },
        proof_minifier::{
            pm_chain::OASProofMinifierChain,
            pm_core::{get_circuit_fingerprint_generic, OASProofMinifier},
        },
        QHashOut,
    },
    store::kvq::{
        adapters::base::KVQStandardAdapter,
        models::merkle_tree::{merkle_tree::KVQMerkleTreeModel, types::tree::KVQMerkleNodeKey},
        store::simplemem::smstore::KVQSimpleMemoryBackingStore,
    },
    treeprover::{
        prover::prove_tree_serial,
        traits::{
            QStandardCircuit, QStandardCircuitProvable, QStandardCircuitProvableWrapped,
            TPLeafAggregator, TreeProverAggCircuit, TreeProverAggCircuitWrapper,
            TreeProverLeafCircuit, VerifierConfig,
        },
    },
};
use serde::{Deserialize, Serialize};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type H = PoseidonHash;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct DemoLeafCircuitInput<F: RichField> {
    pub delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes: QHashOut<F>,
}
impl AggStateTrackableWithEventsInput<F> for DemoLeafCircuitInput<F> {
    fn get_state_transition_with_events(&self) -> StateTransitionWithEvents<F> {
        StateTransitionWithEvents {
            state_transition_start: self.delta_merkle_proof.old_root,
            state_transition_end: self.delta_merkle_proof.new_root,
            event_hash: QHashOut(PoseidonHash::two_to_one(
                self.delta_merkle_proof.old_value.0,
                self.delta_merkle_proof.new_value.0,
            )),
        }
    }
}
/*
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct DemoAggCircuitInput<F: RichField> {
    pub left_state_transition_start: QHashOut<F>,
    pub left_state_transition_end: QHashOut<F>,
    pub right_state_transition_start: QHashOut<F>,
    pub right_state_transition_end: QHashOut<F>,
    pub left_event_hash: QHashOut<F>,
    pub right_event_hash: QHashOut<F>,
    pub left_proof_is_leaf: bool,
    pub right_proof_is_leaf: bool,
}*/

#[derive(Debug)]
pub struct DemoLeafCircuit {
    pub delta_merkle_proof_gadget: DeltaMerkleProofGadget,
    pub allowed_circuit_hashes_target: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: QHashOut<F>,
}
impl Clone for DemoLeafCircuit {
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl DemoLeafCircuit {
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let delta_merkle_proof_gadget: DeltaMerkleProofGadget =
            DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(&mut builder, 32);

        let state_transition_hash = builder.hash_two_to_one::<H>(
            delta_merkle_proof_gadget.old_root,
            delta_merkle_proof_gadget.new_root,
        );

        let event_transition_hash = builder.hash_two_to_one::<H>(
            delta_merkle_proof_gadget.old_value,
            delta_merkle_proof_gadget.new_value,
        );
        let allowed_circuit_hashes_target = builder.add_virtual_hash();

        builder.register_public_inputs(&allowed_circuit_hashes_target.elements);
        builder.register_public_inputs(&state_transition_hash.elements);
        builder.register_public_inputs(&event_transition_hash.elements);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            delta_merkle_proof_gadget,
            allowed_circuit_hashes_target,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        allowed_circuit_hashes: QHashOut<F>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(self.allowed_circuit_hashes_target, allowed_circuit_hashes.0);
        self.delta_merkle_proof_gadget
            .set_witness_core_proof_q(&mut pw, &delta_merkle_proof);
        self.circuit_data.prove(pw).unwrap()
    }
}
impl QStandardCircuit<C, D> for DemoLeafCircuit {
    fn get_fingerprint(&self) -> QHashOut<F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> {
        &self.circuit_data.common
    }
}
impl QStandardCircuitProvable<DemoLeafCircuitInput<F>, C, D> for DemoLeafCircuit {
    fn prove_standard(
        &self,
        input: &DemoLeafCircuitInput<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        Ok(self.prove_base(&input.delta_merkle_proof, input.allowed_circuit_hashes))
    }
}
/*
#[derive(Debug)]
pub struct WrappedDemoLeafCircuit {
    pub demo_leaf_circuit: DemoLeafCircuit,
    pub proof_minifier_chain: OASProofMinifierChain<D, F, C>,
}
impl Clone for WrappedDemoLeafCircuit {
    fn clone(&self) -> Self {
        Self::new_base()
    }
}
impl WrappedDemoLeafCircuit {
    pub fn new_base() -> Self {
        let demo_leaf_circuit = DemoLeafCircuit::new();
        let proof_minifier_chain = OASProofMinifierChain::new(
            &demo_leaf_circuit.circuit_data.verifier_only,
            &demo_leaf_circuit.circuit_data.common,
            1,
        );

        Self {
            demo_leaf_circuit,
            proof_minifier_chain,
        }
    }

    pub fn print_config(&self) {
        println!(
            "constants_sigmas_cap_height: {}",
            self.proof_minifier_chain
                .get_verifier_data()
                .constants_sigmas_cap
                .height()
        );
        println!(
            "common_data: {:?}",
            self.proof_minifier_chain.get_common_data()
        );
    }
    pub fn prove_base(
        &self,
        delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        allowed_circuit_hashes: QHashOut<F>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let proof1 = self
            .demo_leaf_circuit
            .prove_base(delta_merkle_proof, allowed_circuit_hashes);
        let proof2 = self.proof_minifier_chain.prove(&proof1);
        proof2.unwrap()
    }
}*/

/*
#[derive(Debug, Clone)]
pub struct AggCircuitHeaderGadget {
    pub left_state_transition_start: HashOutTarget,
    pub left_state_transition_end: HashOutTarget,
    pub right_state_transition_start: HashOutTarget,
    pub right_state_transition_end: HashOutTarget,
    pub left_event_hash: HashOutTarget,
    pub right_event_hash: HashOutTarget,

    pub leaf_fingerprint: HashOutTarget,
    pub agg_fingerprint: HashOutTarget,

    // end inputs
    // start outputs
    pub allowed_circuit_hashes_root: HashOutTarget,
    pub state_transition_hash: HashOutTarget,
    pub event_transition_hash: HashOutTarget,
}
impl AggCircuitHeaderGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let left_state_transition_start = builder.add_virtual_hash();
        let left_state_transition_end = builder.add_virtual_hash();
        let right_state_transition_start = builder.add_virtual_hash();
        let right_state_transition_end = builder.add_virtual_hash();
        let left_event_hash = builder.add_virtual_hash();
        let right_event_hash = builder.add_virtual_hash();

        let leaf_fingerprint = builder.add_virtual_hash();
        let agg_fingerprint = builder.add_virtual_hash();

        let allowed_circuit_hashes_root =
            builder.hash_two_to_one::<H>(leaf_fingerprint, agg_fingerprint);
        let state_transition_hash =
            builder.hash_two_to_one::<H>(left_state_transition_start, right_state_transition_end);
        let event_transition_hash = builder.hash_two_to_one::<H>(left_event_hash, right_event_hash);

        // start constraints
        builder.connect_hashes(left_state_transition_end, right_state_transition_start);
        // end constraints

        Self {
            left_state_transition_start,
            left_state_transition_end,
            right_state_transition_start,
            right_state_transition_end,
            left_event_hash,
            right_event_hash,
            leaf_fingerprint,
            agg_fingerprint,

            allowed_circuit_hashes_root,
            state_transition_hash,
            event_transition_hash,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &DemoAggCircuitInput<F>,
        agg_fingerprint: QHashOut<F>,
        leaf_fingerprint: QHashOut<F>,
    ) {
        witness.set_hash_target(self.agg_fingerprint, agg_fingerprint.0);
        witness.set_hash_target(self.leaf_fingerprint, leaf_fingerprint.0);

        witness.set_hash_target(
            self.left_state_transition_start,
            input.left_state_transition_start.0,
        );
        witness.set_hash_target(
            self.left_state_transition_end,
            input.left_state_transition_end.0,
        );
        witness.set_hash_target(
            self.right_state_transition_start,
            input.right_state_transition_start.0,
        );
        witness.set_hash_target(
            self.right_state_transition_end,
            input.right_state_transition_end.0,
        );
        witness.set_hash_target(self.left_event_hash, input.left_event_hash.0);
        witness.set_hash_target(self.right_event_hash, input.right_event_hash.0);
    }
}

#[derive(Debug)]
pub struct DemoAggCircuit {
    pub header_gadget: AggCircuitHeaderGadget,

    pub left_proof: ProofWithPublicInputsTarget<D>,
    pub left_verifier_data: VerifierCircuitTarget,

    pub right_proof: ProofWithPublicInputsTarget<D>,
    pub right_verifier_data: VerifierCircuitTarget,

    // end circuit targets
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: QHashOut<F>,
}
impl Clone for DemoAggCircuit {
    fn clone(&self) -> Self {
        Self::new(
            &self.circuit_data.common,
            self.circuit_data
                .verifier_only
                .constants_sigmas_cap
                .height(),
        )
    }
}
impl DemoAggCircuit {
    pub fn new_base(
        child_common_data: &CommonCircuitData<F, D>,
        verifier_cap_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let header_gadget = AggCircuitHeaderGadget::add_virtual_to::<F, D>(&mut builder);

        let left_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let left_verifier_data = builder.add_virtual_verifier_data(verifier_cap_height);

        let right_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let right_verifier_data = builder.add_virtual_verifier_data(verifier_cap_height);

        builder.verify_proof_with_fingerprint_enum::<C>(
            &left_proof,
            &left_verifier_data,
            child_common_data,
            &[
                header_gadget.agg_fingerprint,
                header_gadget.leaf_fingerprint,
            ],
        );
        builder.verify_proof_with_fingerprint_enum::<C>(
            &right_proof,
            &right_verifier_data,
            child_common_data,
            &[
                header_gadget.agg_fingerprint,
                header_gadget.leaf_fingerprint,
            ],
        );
        builder.register_public_inputs(&header_gadget.allowed_circuit_hashes_root.elements);
        builder.register_public_inputs(&header_gadget.state_transition_hash.elements);
        builder.register_public_inputs(&header_gadget.event_transition_hash.elements);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            header_gadget,
            left_proof,
            left_verifier_data,
            right_proof,
            right_verifier_data,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        agg_fingerprint: QHashOut<F>,
        agg_verifier_data: &VerifierOnlyCircuitData<C, D>,
        leaf_fingerprint: QHashOut<F>,
        leaf_verifier_data: &VerifierOnlyCircuitData<C, D>,
        left_proof: &ProofWithPublicInputs<F, C, D>,
        right_proof: &ProofWithPublicInputs<F, C, D>,
        input: &DemoAggCircuitInput<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        println!("agg_prove_base: {:?}", input);
        let mut pw = PartialWitness::<F>::new();
        self.header_gadget
            .set_witness(&mut pw, input, agg_fingerprint, leaf_fingerprint);

        pw.set_proof_with_pis_target(&self.left_proof, left_proof);
        pw.set_verifier_data_target(
            &self.left_verifier_data,
            if input.left_proof_is_leaf {
                leaf_verifier_data
            } else {
                agg_verifier_data
            },
        );
        pw.set_proof_with_pis_target(&self.right_proof, right_proof);
        pw.set_verifier_data_target(
            &self.right_verifier_data,
            if input.right_proof_is_leaf {
                leaf_verifier_data
            } else {
                agg_verifier_data
            },
        );
        let result = self.circuit_data.prove(pw);

        if result.is_err() {
            println!("error: {}", serde_json::to_string(&input).unwrap());
        }
        result
    }
}
impl QStandardCircuit<C, D> for DemoAggCircuit {
    fn get_fingerprint(&self) -> QHashOut<F> {
        self.fingerprint
    }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> {
        &self.circuit_data.common
    }
}
pub struct DemoAggCircuitLeafAggregator;
impl TPLeafAggregator<DemoLeafCircuitInput<F>, DemoAggCircuitInput<F>>
    for DemoAggCircuitLeafAggregator
{
    fn get_output_from_inputs(
        left: &DemoAggCircuitInput<F>,
        right: &DemoAggCircuitInput<F>,
    ) -> DemoAggCircuitInput<F> {
        DemoAggCircuitInput {
            left_state_transition_start: left.left_state_transition_start,
            left_state_transition_end: left.right_state_transition_end,
            right_state_transition_start: right.left_state_transition_start,
            right_state_transition_end: right.right_state_transition_end,
            left_event_hash: QHashOut(H::two_to_one(
                left.left_event_hash.0,
                left.right_event_hash.0,
            )),
            right_event_hash: QHashOut(H::two_to_one(
                right.left_event_hash.0,
                right.right_event_hash.0,
            )),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }

    fn get_output_from_left_leaf(
        left: &DemoLeafCircuitInput<F>,
        right: &DemoAggCircuitInput<F>,
    ) -> DemoAggCircuitInput<F> {
        DemoAggCircuitInput {
            left_state_transition_start: left.delta_merkle_proof.old_root,
            left_state_transition_end: left.delta_merkle_proof.new_root,
            right_state_transition_start: right.left_state_transition_start,
            right_state_transition_end: right.right_state_transition_end,
            left_event_hash: QHashOut(H::two_to_one(
                left.delta_merkle_proof.old_value.0,
                left.delta_merkle_proof.new_value.0,
            )),
            right_event_hash: QHashOut(H::two_to_one(
                right.left_event_hash.0,
                right.right_event_hash.0,
            )),
            left_proof_is_leaf: true,
            right_proof_is_leaf: false,
        }
    }

    fn get_output_from_right_leaf(
        left: &DemoAggCircuitInput<F>,
        right: &DemoLeafCircuitInput<F>,
    ) -> DemoAggCircuitInput<F> {
        DemoAggCircuitInput {
            left_state_transition_start: left.left_state_transition_start,
            left_state_transition_end: left.right_state_transition_end,
            right_state_transition_start: right.delta_merkle_proof.old_root,
            right_state_transition_end: right.delta_merkle_proof.new_root,
            left_event_hash: QHashOut(H::two_to_one(
                left.left_event_hash.0,
                left.right_event_hash.0,
            )),
            right_event_hash: QHashOut(H::two_to_one(
                right.delta_merkle_proof.old_value.0,
                right.delta_merkle_proof.new_value.0,
            )),
            left_proof_is_leaf: false,
            right_proof_is_leaf: true,
        }
    }

    fn get_output_from_leaves(
        left: &DemoLeafCircuitInput<F>,
        right: &DemoLeafCircuitInput<F>,
    ) -> DemoAggCircuitInput<F> {
        DemoAggCircuitInput {
            left_state_transition_start: left.delta_merkle_proof.old_root,
            left_state_transition_end: left.delta_merkle_proof.new_root,
            right_state_transition_start: right.delta_merkle_proof.old_root,
            right_state_transition_end: right.delta_merkle_proof.new_root,
            left_event_hash: QHashOut(H::two_to_one(
                left.delta_merkle_proof.old_value.0,
                left.delta_merkle_proof.new_value.0,
            )),
            right_event_hash: QHashOut(H::two_to_one(
                right.delta_merkle_proof.old_value.0,
                right.delta_merkle_proof.new_value.0,
            )),
            left_proof_is_leaf: true,
            right_proof_is_leaf: true,
        }
    }
}
impl TreeProverAggCircuit<DemoLeafCircuitInput<F>, DemoAggCircuitInput<F>, C, D>
    for DemoAggCircuit
{
    fn new(child_common_data: &CommonCircuitData<F, D>, verifier_cap_height: usize) -> Self {
        Self::new_base(child_common_data, verifier_cap_height)
    }

    fn prove_full(
        &self,
        agg_fingerprint: QHashOut<F>,
        agg_verifier_data: &VerifierOnlyCircuitData<C, D>,
        leaf_fingerprint: QHashOut<F>,
        leaf_verifier_data: &VerifierOnlyCircuitData<C, D>,
        left_proof: &ProofWithPublicInputs<F, C, D>,
        right_proof: &ProofWithPublicInputs<F, C, D>,
        input: &DemoAggCircuitInput<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.prove_base(
            agg_fingerprint,
            agg_verifier_data,
            leaf_fingerprint,
            leaf_verifier_data,
            left_proof,
            right_proof,
            input,
        )
    }
}
*/
fn generate_merkle_updates(
    height: usize,
    count: usize,
) -> anyhow::Result<Vec<DeltaMerkleProofCore<QHashOut<F>>>> {
    type S = KVQSimpleMemoryBackingStore;
    type TH = PoseidonHasher;
    type Hash = QHashOut<F>;

    const TREE_A_ID: u8 = 1;
    const TREE_TABLE_TYPE: u16 = 1;
    type KVA = KVQStandardAdapter<S, KVQMerkleNodeKey<TREE_TABLE_TYPE>, Hash>;
    type TreeModel = KVQMerkleTreeModel<TREE_TABLE_TYPE, false, S, KVA, Hash, TH>;

    let mut store = S::new();

    let mut proofs = Vec::new();
    for i in 0..count {
        let l0 = KVQMerkleNodeKey::<TREE_TABLE_TYPE> {
            tree_id: TREE_A_ID,
            primary_id: 0,
            secondary_id: 0,
            level: height as u8,
            index: i as u64,
            checkpoint_id: 0,
        };
        let v0 = QHashOut::from_values(1, 2, 3, 4);
        let d0 = TreeModel::set_leaf(&mut store, &l0, v0)?;
        proofs.push(d0);
    }
    Ok(proofs)
}
fn main() {
    let height: usize = 32;
    let dmps = generate_merkle_updates(height, 15).unwrap();
    let start_root = dmps[0].old_root;
    let end_root = dmps[dmps.len() - 1].new_root;
    let leaf_circuit =
        QStandardCircuitProvableWrapped::<1, _, _, C, D>::new_wrapped(DemoLeafCircuit::new());

    let agg_circuit =
        TreeProverAggCircuitWrapper::<AggStateTransitionWithEventsCircuit<C, D>, C, D>::new(
            leaf_circuit.get_common_circuit_data_ref(),
            leaf_circuit
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
        );
    let allowed_circuit_hashes = QHashOut(H::two_to_one(
        leaf_circuit.get_fingerprint().0,
        agg_circuit.get_fingerprint().0,
    ));

    let leaf_inputs = dmps
        .into_iter()
        .map(|dmp| DemoLeafCircuitInput {
            delta_merkle_proof: dmp,
            allowed_circuit_hashes: allowed_circuit_hashes,
        })
        .collect::<Vec<_>>();
    let final_proof: ProofWithPublicInputs<F, C, D> =
        prove_tree_serial::<AggWTTELeafAggregator, _, _, _, _, _, D>(
            leaf_circuit,
            agg_circuit,
            leaf_inputs,
        )
        .unwrap();
    println!("final_proof_public_inputs: {:?}", final_proof.public_inputs);

    //leaf_circuit.print_config();
    //agg_circuit.print_config();
}
