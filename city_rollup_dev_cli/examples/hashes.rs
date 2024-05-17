use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::job_witnesses::agg::CRAggUserRegisterClaimDepositL2TransferCircuitInput;
use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash, plonk::config::Hasher,
};

fn main() {
    let transition_str = "{\"op_register_user_transition_user_state_tree\":{\"state_transition_start\":\"d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43\",\"state_transition_end\":\"7f0c3ea541b21b3c2676d289afc67a83301beb7cebc82b291d3113054669813d\"},\"op_register_user_proof_id\":{\"topic\":0,\"goal_id\":1,\"circuit_type\":1,\"group_id\":52992,\"sub_group_id\":2,\"task_index\":0,\"data_type\":8,\"data_index\":0},\"op_claim_l1_deposit_transition_deposit_tree\":{\"state_transition_start\":\"d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43\",\"state_transition_end\":\"d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43\"},\"op_claim_l1_deposit_transition_user_state_tree\":{\"state_transition_start\":\"7f0c3ea541b21b3c2676d289afc67a83301beb7cebc82b291d3113054669813d\",\"state_transition_end\":\"7f0c3ea541b21b3c2676d289afc67a83301beb7cebc82b291d3113054669813d\"},\"op_claim_l1_deposit_proof_id\":{\"topic\":0,\"goal_id\":1,\"circuit_type\":50,\"group_id\":221,\"sub_group_id\":0,\"task_index\":0,\"data_type\":8,\"data_index\":0},\"op_l2_transfer_transition_user_state_tree\":{\"state_transition_start\":\"7f0c3ea541b21b3c2676d289afc67a83301beb7cebc82b291d3113054669813d\",\"state_transition_end\":\"7f0c3ea541b21b3c2676d289afc67a83301beb7cebc82b291d3113054669813d\"},\"op_l2_transfer_proof_id\":{\"topic\":0,\"goal_id\":1,\"circuit_type\":51,\"group_id\":221,\"sub_group_id\":0,\"task_index\":0,\"data_type\":8,\"data_index\":0}}";
    let input: CRAggUserRegisterClaimDepositL2TransferCircuitInput<GoldilocksField> =
        serde_json::from_str(&transition_str).unwrap();
    println!("{:?}", input);

    let dat = input
        .op_register_user_transition_user_state_tree
        .get_combined_hash::<PoseidonHash>();

    let combo_test = vec![
        input
            .op_register_user_transition_user_state_tree
            .state_transition_start
            .0
            .elements,
        input
            .op_register_user_transition_user_state_tree
            .state_transition_end
            .0
            .elements,
    ]
    .concat()
    .to_vec();
    println!("combo_test: {:?}", combo_test);
    let tst = PoseidonHash::hash_no_pad(&combo_test);
    println!("dat: {}, ({:?})", dat.to_string(), dat);
    println!("tst: {} ({:?})", QHashOut(tst).to_string(), tst);
}
//15396066879629794493n, 10121255962030968466n, 524285228213264487n, 2983318696435310179n
