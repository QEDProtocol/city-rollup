use city_macros::const_concat_arrays;

use super::{
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA, BLOCK_GROTH16_ENCODED_VERIFIER_DATA_0_SHA_256_HASH,
};

// DATA INSTRUCTIONS
const OP_PUSHBYTES_32: u8 = 0x20;
const OP_PUSHDATA1: u8 = 0x4c;

// Utility Instructions
const OP_SWAP: u8 = 0x7c;
const OP_DUP: u8 = 0x76;
const OP_SHA256: u8 = 0xa8;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_1: u8 = 0x51;
const OP_2DROP: u8 = 0x6d;

// Action Instructions
const OP_0NOTEQUAL: u8 = 0x92;

// note: OP_CHECKGROTH16VERIFY is 0xb3, but 0x61 is OP_NOP and can be used for testing without verifying proofs
const OP_CHECKGROTH16VERIFY: u8 = 0xb3; //0x61;

//  size = 3 + 1 + 32 + 1 + 5*(2+80) + 9 = 456
const STANDARD_BLOCK_SCRIPT_BODY: [u8; 456] = city_macros::const_concat_arrays!(
    [OP_SWAP, OP_DUP, OP_SHA256],
    [OP_PUSHBYTES_32],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA_0_SHA_256_HASH,
    [OP_EQUALVERIFY],
    [OP_PUSHDATA1, 80],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA[1],
    [OP_PUSHDATA1, 80],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA[2],
    [OP_PUSHDATA1, 80],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA[3],
    [OP_PUSHDATA1, 80],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA[4],
    [OP_PUSHDATA1, 80],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA[5],
    [
        OP_1,
        OP_CHECKGROTH16VERIFY, // OP_ACTION
        OP_2DROP,
        OP_2DROP,
        OP_2DROP,
        OP_2DROP,
        OP_2DROP,
        OP_2DROP,
        OP_1
    ]
);

// size = 3 + 1 + 32 + 1 + 5*(2+80) + 9 = 456
const GENESIS_BLOCK_SCRIPT_BODY: [u8; 456] = city_macros::const_concat_arrays!(
    [OP_SWAP, OP_DUP, OP_SHA256],
    [OP_PUSHBYTES_32],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA_0_SHA_256_HASH,
    [OP_EQUALVERIFY],
    [OP_PUSHDATA1, 80],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA[1],
    [OP_PUSHDATA1, 80],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA[2],
    [OP_PUSHDATA1, 80],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA[3],
    [OP_PUSHDATA1, 80],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA[4],
    [OP_PUSHDATA1, 80],
    BLOCK_GROTH16_ENCODED_VERIFIER_DATA[5],
    [
        OP_1,
        OP_0NOTEQUAL, // OP_ACTION
        OP_2DROP,
        OP_2DROP,
        OP_2DROP,
        OP_2DROP,
        OP_2DROP,
        OP_2DROP,
        OP_1
    ]
);

pub const GENESIS_BLOCK_SCRIPT_TEMPLATE: [u8; 489] =
    const_concat_arrays!([OP_PUSHBYTES_32], [0u8; 32], GENESIS_BLOCK_SCRIPT_BODY);

pub const STANDARD_BLOCK_SCRIPT_TEMPLATE: [u8; 489] =
    const_concat_arrays!([OP_PUSHBYTES_32], [0u8; 32], STANDARD_BLOCK_SCRIPT_BODY);
