use city_common::tree_planner::{BinaryTreeJob, BinaryTreePlanner};
use plonky2::{
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    plonk::config::{AlgebraicHasher, Hasher},
};
use serde::{Deserialize, Serialize};

use crate::hash::qhashout::QHashOut;
pub trait WithDummyStateTransition<F: RichField> {
    fn get_dummy_value(state_root: QHashOut<F>) -> Self;
}
pub trait AggStateTrackableInput<F: RichField> {
    fn get_state_transition(&self) -> AggStateTransition<F>;
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct AggStateTransition<F: RichField> {
    pub state_transition_start: QHashOut<F>,
    pub state_transition_end: QHashOut<F>,
}
impl<F: RichField> WithDummyStateTransition<F> for AggStateTransition<F> {
    fn get_dummy_value(state_root: QHashOut<F>) -> Self {
        Self {
            state_transition_start: state_root,
            state_transition_end: state_root,
        }
    }
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct AggStateTransitionInput<F: RichField> {
    pub left_input: AggStateTransition<F>,
    pub right_input: AggStateTransition<F>,
    pub left_proof_is_leaf: bool,
    pub right_proof_is_leaf: bool,
}
impl<F: RichField> WithDummyStateTransition<F> for AggStateTransitionInput<F> {
    fn get_dummy_value(state_root: QHashOut<F>) -> Self {
        Self {
            left_input: AggStateTransition::<F>::get_dummy_value(state_root),
            right_input: AggStateTransition::<F>::get_dummy_value(state_root),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }
}
impl<F: RichField> AggStateTransitionInput<F> {
    pub fn condense(&self) -> AggStateTransition<F> {
        AggStateTransition {
            state_transition_start: self.left_input.state_transition_start,
            state_transition_end: self.right_input.state_transition_end,
        }
    }
    pub fn combine_with_right_leaf<T: AggStateTrackableInput<F>>(&self, right: &T) -> Self {
        Self {
            left_input: self.condense(),
            right_input: right.get_state_transition(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: true,
        }
    }
    pub fn combine_with_left_leaf<T: AggStateTrackableInput<F>>(&self, left: &T) -> Self {
        Self {
            left_input: left.get_state_transition(),
            right_input: self.condense(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: false,
        }
    }
}

pub trait AggStateTrackableWithEventsInput<F: RichField> {
    fn get_state_transition_with_events(&self) -> StateTransitionWithEvents<F>;
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct StateTransitionWithEvents<F: RichField> {
    pub state_transition_start: QHashOut<F>,
    pub state_transition_end: QHashOut<F>,
    pub event_hash: QHashOut<F>,
}
impl<F: RichField> WithDummyStateTransition<F> for StateTransitionWithEvents<F> {
    fn get_dummy_value(state_root: QHashOut<F>) -> Self {
        Self {
            state_transition_start: state_root,
            state_transition_end: state_root,
            event_hash: QHashOut::ZERO,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct AggStateTransitionWithEventsInput<F: RichField> {
    pub left_input: StateTransitionWithEvents<F>,
    pub right_input: StateTransitionWithEvents<F>,
    pub left_proof_is_leaf: bool,
    pub right_proof_is_leaf: bool,
}
impl<F: RichField> WithDummyStateTransition<F> for AggStateTransitionWithEventsInput<F> {
    fn get_dummy_value(state_root: QHashOut<F>) -> Self {
        Self {
            left_input: StateTransitionWithEvents::<F>::get_dummy_value(state_root),
            right_input: StateTransitionWithEvents::<F>::get_dummy_value(state_root),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }
}
impl<F: RichField> AggStateTransitionWithEventsInput<F> {
    pub fn condense(&self) -> StateTransitionWithEvents<F> {
        StateTransitionWithEvents {
            state_transition_start: self.left_input.state_transition_start,
            state_transition_end: self.right_input.state_transition_end,
            event_hash: QHashOut(PoseidonHash::two_to_one(
                self.left_input.event_hash.0,
                self.right_input.event_hash.0,
            )),
        }
    }
    pub fn combine_with_right_leaf<T: AggStateTrackableWithEventsInput<F>>(
        &self,
        right: &T,
    ) -> Self {
        Self {
            left_input: self.condense(),
            right_input: right.get_state_transition_with_events(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: true,
        }
    }
    pub fn combine_with_left_leaf<T: AggStateTrackableWithEventsInput<F>>(&self, left: &T) -> Self {
        Self {
            left_input: left.get_state_transition_with_events(),
            right_input: self.condense(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: false,
        }
    }
}

pub trait TPLeafAggregator<IL, IO> {
    fn get_output_from_inputs(left: &IO, right: &IO) -> IO;
    fn get_output_from_left_leaf(left: &IL, right: &IO) -> IO;
    fn get_output_from_right_leaf(left: &IO, right: &IL) -> IO;
    fn get_output_from_leaves(left: &IL, right: &IL) -> IO;
}
pub struct AggWTLeafAggregator;

impl<IL: AggStateTrackableInput<F>, F: RichField> TPLeafAggregator<IL, AggStateTransitionInput<F>>
    for AggWTLeafAggregator
{
    fn get_output_from_inputs(
        left: &AggStateTransitionInput<F>,
        right: &AggStateTransitionInput<F>,
    ) -> AggStateTransitionInput<F> {
        AggStateTransitionInput {
            left_input: left.condense(),
            right_input: right.condense(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }

    fn get_output_from_left_leaf(
        left: &IL,
        right: &AggStateTransitionInput<F>,
    ) -> AggStateTransitionInput<F> {
        right.combine_with_left_leaf(left)
    }

    fn get_output_from_right_leaf(
        left: &AggStateTransitionInput<F>,
        right: &IL,
    ) -> AggStateTransitionInput<F> {
        left.combine_with_right_leaf(right)
    }

    fn get_output_from_leaves(left: &IL, right: &IL) -> AggStateTransitionInput<F> {
        AggStateTransitionInput {
            left_input: left.get_state_transition(),
            right_input: right.get_state_transition(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: true,
        }
    }
}

pub struct AggWTTELeafAggregator;

impl<IL: AggStateTrackableWithEventsInput<F>, F: RichField>
    TPLeafAggregator<IL, AggStateTransitionWithEventsInput<F>> for AggWTTELeafAggregator
{
    fn get_output_from_inputs(
        left: &AggStateTransitionWithEventsInput<F>,
        right: &AggStateTransitionWithEventsInput<F>,
    ) -> AggStateTransitionWithEventsInput<F> {
        AggStateTransitionWithEventsInput {
            left_input: left.condense(),
            right_input: right.condense(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }

    fn get_output_from_left_leaf(
        left: &IL,
        right: &AggStateTransitionWithEventsInput<F>,
    ) -> AggStateTransitionWithEventsInput<F> {
        right.combine_with_left_leaf(left)
    }

    fn get_output_from_right_leaf(
        left: &AggStateTransitionWithEventsInput<F>,
        right: &IL,
    ) -> AggStateTransitionWithEventsInput<F> {
        left.combine_with_right_leaf(right)
    }

    fn get_output_from_leaves(left: &IL, right: &IL) -> AggStateTransitionWithEventsInput<F> {
        AggStateTransitionWithEventsInput {
            left_input: left.get_state_transition_with_events(),
            right_input: right.get_state_transition_with_events(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TPCircuitFingerprintConfig<F: RichField> {
    pub leaf_fingerprint: QHashOut<F>,
    pub aggregator_fingerprint: QHashOut<F>,
    pub allowed_circuit_hashes_root: QHashOut<F>,
}

impl<F: RichField> TPCircuitFingerprintConfig<F> {
    pub fn from_leaf_and_agg_fingerprints<H: AlgebraicHasher<F>>(
        leaf_fingerprint: QHashOut<F>,
        aggregator_fingerprint: QHashOut<F>,
    ) -> Self {
        let allowed_circuit_hashes_root =
            QHashOut(H::two_to_one(leaf_fingerprint.0, aggregator_fingerprint.0));
        Self {
            leaf_fingerprint,
            aggregator_fingerprint,
            allowed_circuit_hashes_root,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TreeAggJob<IO: Clone> {
    pub input: IO,
    pub tree_position: BinaryTreeJob,
}
impl<IO: Clone> TreeAggJob<IO> {
    pub fn new(input: IO, tree_position: BinaryTreeJob) -> Self {
        Self {
            input,
            tree_position,
        }
    }
}

pub fn generate_tree_inputs_with_position<LA: TPLeafAggregator<IL, IO>, IL: Clone, IO: Clone>(
    leaf_inputs: &[IL],
) -> Vec<Vec<TreeAggJob<IO>>> {
    let tree_positions = BinaryTreePlanner::new(leaf_inputs.len()).levels;

    let mut output: Vec<Vec<TreeAggJob<IO>>> = Vec::with_capacity(tree_positions.len());
    for level in tree_positions {
        let mut level_output: Vec<TreeAggJob<IO>> = Vec::with_capacity(level.len());
        for job in level {
            let input = if job.left_job.is_leaf() {
                if job.right_job.is_leaf() {
                    LA::get_output_from_leaves(
                        &leaf_inputs[job.left_job.index as usize],
                        &leaf_inputs[job.right_job.index as usize],
                    )
                } else {
                    LA::get_output_from_left_leaf(
                        &leaf_inputs[job.left_job.index as usize],
                        &output[job.right_job.level as usize - 1][job.right_job.index as usize]
                            .input,
                    )
                }
            } else {
                if job.right_job.is_leaf() {
                    LA::get_output_from_right_leaf(
                        &output[job.left_job.level as usize - 1][job.left_job.index as usize].input,
                        &leaf_inputs[job.right_job.index as usize],
                    )
                } else {
                    LA::get_output_from_inputs(
                        &output[job.left_job.level as usize - 1][job.left_job.index as usize].input,
                        &output[job.right_job.level as usize - 1][job.right_job.index as usize]
                            .input,
                    )
                }
            };
            level_output.push(TreeAggJob {
                input,
                tree_position: job,
            });
        }
        output.push(level_output);
    }

    output
}

pub fn generate_tree_inputs_from_leaves<LA: TPLeafAggregator<IL, IO>, IL: Clone, IO: Clone>(
    leaf_inputs: &[IL],
) -> Vec<Vec<IO>> {
    let tree_positions = BinaryTreePlanner::new(leaf_inputs.len()).levels;
    let mut output: Vec<Vec<IO>> = Vec::with_capacity(tree_positions.len());
    for level in tree_positions {
        let mut level_output: Vec<IO> = Vec::with_capacity(level.len());
        for job in level {
            let input = if job.left_job.is_leaf() {
                if job.right_job.is_leaf() {
                    LA::get_output_from_leaves(
                        &leaf_inputs[job.left_job.index as usize],
                        &leaf_inputs[job.right_job.index as usize],
                    )
                } else {
                    LA::get_output_from_left_leaf(
                        &leaf_inputs[job.left_job.index as usize],
                        &output[job.right_job.level as usize - 1][job.right_job.index as usize],
                    )
                }
            } else {
                if job.right_job.is_leaf() {
                    LA::get_output_from_right_leaf(
                        &output[job.left_job.level as usize - 1][job.left_job.index as usize],
                        &leaf_inputs[job.right_job.index as usize],
                    )
                } else {
                    LA::get_output_from_inputs(
                        &output[job.left_job.level as usize - 1][job.left_job.index as usize],
                        &output[job.right_job.level as usize - 1][job.right_job.index as usize],
                    )
                }
            };
            level_output.push(input);
        }
        output.push(level_output);
    }

    output
}
