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
    logging::debug_timer::DebugTimer,
    store::kvq_merkle::{key::KVQMerkleNodeKey, model::KVQMerkleTreeModel},
    treeprover::{
        prover::prove_tree_serial,
        traits::{
            QStandardCircuit, QStandardCircuitProvable, QStandardCircuitProvableWrapped,
            TPLeafAggregator, TreeProverAggCircuit, TreeProverAggCircuitWrapper,
            TreeProverLeafCircuit, VerifierConfig,
        },
    },
};
use kvq::{adapters::standard::KVQStandardAdapter, memory::simple::KVQSimpleMemoryBackingStore};
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
    type TreeModel = KVQMerkleTreeModel<TREE_TABLE_TYPE, 32, S, KVA, Hash, TH>;

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
    let mut debug_timer = DebugTimer::new("merkle_demo");
    debug_timer.lap("1");
    let dmps = generate_merkle_updates(height, 5000).unwrap();
    debug_timer.lap("1");
    /*
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
    */
}
