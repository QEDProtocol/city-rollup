use city_macros::const_concat_arrays;

const BLOCK_GROTH16_ENCODED_VERIFIER_DATA: [[u8; 80]; 6] = [
  hex_literal::hex!("f9fcba207a86c6db12b42897517ce94afef5f75fc079a12c76987c96cd9a21a2c703edd90ebd78ce1db88ad703939c533d82e1726e6f7cf9181295afa7a0b2f38517c8a8dbbfa9f1d90c8abc9615dde4"),
  hex_literal::hex!("f71007206f1177e3a21cc9cc7d71e1962a54c3e996a019f2ab03522832fcbc4653c63ae833ed10a29c46cb0b53ac0b11fdcbb74abb7397fce69b1b02a20524597d5ef967f7a4bb61e361435e68093ba0"),
  hex_literal::hex!("f4d21e0dfd30268c995d87c4e9b4f6b66ab0b112f29fce17528af62af6c8c2a07f97fbf2f63368777e1b5ae416e74ce96461592a4f32c137e20a9d084d5e7a35db133f92f24b6a9e26f955f11c107eac"),
  hex_literal::hex!("315da2d0baaafabda118d5d270cc2b83194387a45be51697d702d98c36bbdf6f7bd734907da6fb50732699d32811ac6b706914c709669a944c3a515a599ef212dceda5b4cfa611a0373051ed84dbf0f2"),
  hex_literal::hex!("aea325ee3b32a4b3b4b42535cb935b025f1b182c88a90055c8747ad06ceb40421f2f6135f12685799a021dbfd0a28cb940e842342cf5c11bea9947d8180c8981aea561f364b9e7979e8065a24cef64b4"),
  hex_literal::hex!("26602c18df26a22fb829ce63f0ee4c75ab615a4fa2f29916f9a436a46263bdc3f1baac49ff3891a83612a5ad3fa80010d5d9f9ff71a24936e8021af4eaf9683f977ff4a6d12894fcbc1455a0d14f9fcc"),
];

// note: BLOCK_VERIFIER_DATA_0_SHA_256_HASH = sha256(BLOCK_VERIFIER_DATA[0])
const BLOCK_GROTH16_ENCODED_VERIFIER_DATA_0_SHA_256_HASH: [u8; 32] =
    hex_literal::hex!("86a678dd3c502984b1dcd3113bd0a109fd4ca99bf06dae158b9459cc825e4ac3");

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
const OP_CHECKGROTH16VERIFY: u8 = 0xb3;

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