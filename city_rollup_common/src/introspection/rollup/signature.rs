use city_crypto::{
    hash::{base_types::hash256::Hash256, qhashout::QHashOut},
    signature::secp256k1::curve::{
        curve_types::AffinePoint,
        ecdsa::{ECDSAPublicKey, ECDSASignature},
        secp256k1::Secp256K1,
    },
};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::point::DecompressPoint;
use plonky2::{
    field::{secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar},
    hash::hash_types::{HashOut, RichField},
    plonk::config::AlgebraicHasher,
};
use serde::{Deserialize, Serialize};

use serde_with::serde_as;

use super::constants::{SIG_ACTION_CLAIM_DEPOSIT_MAGIC, SIG_ACTION_TRANSFER_MAGIC};

pub fn secp256k1_scalar_from_bytes(bytes: &[u8], offset: usize) -> Secp256K1Scalar {
    let mut arr = [0u64; 4];
    for i in 0..4 {
        arr[i] = u64::from_le_bytes(
            bytes[i * 8 + offset..(i + 1) * 8 + offset]
                .try_into()
                .unwrap(),
        );
    }
    Secp256K1Scalar(arr)
}

pub fn secp256k1_base_from_bytes(bytes: &[u8], offset: usize) -> Secp256K1Base {
    let mut arr = [0u64; 4];
    for i in 0..4 {
        arr[i] = u64::from_le_bytes(
            bytes[i * 8 + offset..(i + 1) * 8 + offset]
                .try_into()
                .unwrap(),
        );
    }
    Secp256K1Base(arr)
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
pub struct QEDCompressedSecp256K1Signature {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub public_key: [u8; 33],

    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature: [u8; 64],

    // HashOut<F> in little-endian byte form
    pub message: Hash256,
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
#[serde(bound = "")]
pub struct QEDPreparedSecp256K1Signature<F: RichField> {
    pub message: HashOut<F>,
    pub public_key: ECDSAPublicKey<Secp256K1>,
    pub signature: ECDSASignature<Secp256K1>,
}

impl<F: RichField> TryFrom<&QEDCompressedSecp256K1Signature> for QEDPreparedSecp256K1Signature<F> {
    type Error = ();

    fn try_from(value: &QEDCompressedSecp256K1Signature) -> Result<Self, Self::Error> {
        let mut message = [F::ZERO; 4];
        for i in 0..4 {
            message[i] = F::from_canonical_u64(u64::from_le_bytes(
                value.message.0[i * 8..(i + 1) * 8].try_into().unwrap(),
            ));
        }
        let message_hash = HashOut { elements: message };
        let r = secp256k1_scalar_from_bytes(&value.signature, 0);
        let s = secp256k1_scalar_from_bytes(&value.signature, 0);
        let public_key_x = secp256k1_base_from_bytes(&value.public_key, 1);

        let public_key_point = k256::AffinePoint::decompress(
            value.public_key[1..33].into(),
            (value.public_key[0] & 0x1u8).into(),
        );
        if public_key_point.is_none().into() {
            return Err(());
        }
        let public_key_bytes = public_key_point.unwrap().to_bytes().to_vec();
        let public_key_y = secp256k1_base_from_bytes(&public_key_bytes, 33);

        Ok(Self {
            message: message_hash,
            signature: ECDSASignature { r, s },
            public_key: ECDSAPublicKey(AffinePoint {
                x: public_key_x,
                y: public_key_y,
                zero: false,
            }),
        })
    }
}
pub fn hash256_to_hashout_u224<F: RichField>(hash: Hash256) -> HashOut<F> {
    HashOut {
        elements: core::array::from_fn(|i| {
            F::from_canonical_u64(
                u64::from_le_bytes(hash.0[i * 8..(i + 1) * 8].try_into().unwrap())
                    & 0x00FFFFFFFFFFFFFF,
            )
        }),
    }
}
fn public_key_enc_to_felts<F: RichField>(hash: &[u8; 33]) -> [F; 9] {
    let mut arr = [F::ZERO; 9];
    arr[0] = F::from_canonical_u8(hash[0]);
    arr[1] = F::from_canonical_u32(u32::from_le_bytes(hash[1..5].try_into().unwrap()));
    arr[2] = F::from_canonical_u32(u32::from_le_bytes(hash[5..9].try_into().unwrap()));
    arr[3] = F::from_canonical_u32(u32::from_le_bytes(hash[9..13].try_into().unwrap()));
    arr[4] = F::from_canonical_u32(u32::from_le_bytes(hash[13..17].try_into().unwrap()));
    arr[5] = F::from_canonical_u32(u32::from_le_bytes(hash[17..21].try_into().unwrap()));
    arr[6] = F::from_canonical_u32(u32::from_le_bytes(hash[21..25].try_into().unwrap()));
    arr[7] = F::from_canonical_u32(u32::from_le_bytes(hash[25..29].try_into().unwrap()));
    arr[8] = F::from_canonical_u32(u32::from_le_bytes(hash[29..33].try_into().unwrap()));

    arr
}
#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(bound = "")]
pub struct QEDClaimDepositAction<F: RichField> {
    transaction_id: Hash256,
    transaction_hash_224: HashOut<F>,
    amount: F,
    network_magic: F,
    user: F,
    nonce: F,
}
impl<F: RichField> QEDClaimDepositAction<F> {
    pub fn new(
        network_magic: u64,
        user: u64,
        nonce: u64,
        transaction_id: Hash256,
        amount: u64,
    ) -> Self {
        let network_magic = F::from_canonical_u64(network_magic);
        let nonce = F::from_canonical_u64(nonce);
        let transaction_hash_224 = hash256_to_hashout_u224(transaction_id);
        Self {
            network_magic,
            nonce,
            transaction_id,
            transaction_hash_224,
            amount: F::from_noncanonical_u64(amount),
            user: F::from_noncanonical_u64(user),
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(bound = "")]
pub struct QEDSigAction<F: RichField> {
    pub network_magic: F,
    pub user: F,
    pub sig_action: F,
    pub nonce: F,
    pub action_arguments: Vec<F>,
}
impl<F: RichField> QEDSigAction<F> {
    pub fn new_claim_deposit_action(
        network_magic: u64,
        user: u64,
        nonce: u64,
        transaction_id: Hash256,
        amount: u64,
    ) -> Self {
        let network_magic = F::from_canonical_u64(network_magic);
        let nonce = F::from_canonical_u64(nonce);
        let tx_hash_224 = hash256_to_hashout_u224(transaction_id);
        Self {
            network_magic,
            sig_action: F::from_canonical_u64(SIG_ACTION_CLAIM_DEPOSIT_MAGIC),
            nonce,
            action_arguments: vec![
                tx_hash_224.elements[0],
                tx_hash_224.elements[1],
                tx_hash_224.elements[2],
                tx_hash_224.elements[3],
                F::from_noncanonical_u64(amount),
            ],
            user: F::from_noncanonical_u64(user),
        }
    }
    pub fn new_transfer_action(
        network_magic: u64,
        user: u64,
        nonce: u64,
        recipient: u64,
        amount: u64,
    ) -> Self {
        let network_magic = F::from_canonical_u64(network_magic);
        let nonce = F::from_canonical_u64(nonce);
        let recipient = F::from_canonical_u64(recipient);
        Self {
            network_magic,
            sig_action: F::from_canonical_u64(SIG_ACTION_TRANSFER_MAGIC),
            nonce,
            action_arguments: vec![recipient, F::from_noncanonical_u64(amount)],
            user: F::from_noncanonical_u64(user),
        }
    }
    pub fn get_hash<H: AlgebraicHasher<F>>(&self) -> HashOut<F> {
        let arguments_hash = H::hash_no_pad(&self.action_arguments);
        let final_hash = H::hash_no_pad(&[
            self.network_magic,
            self.user,
            self.sig_action,
            self.nonce,
            arguments_hash.elements[0],
            arguments_hash.elements[1],
            arguments_hash.elements[2],
            arguments_hash.elements[3],
        ]);
        final_hash
    }
}
pub static PRIVATE_KEY_CONSTANTS: [u64; 20] = [
    0x778e50b9dd8594bbu64,
    0xed002cebe1ee4f45u64,
    0x892f65737845d0e7u64,
    0x943cd37231de09f1u64,
    0xaf006f1eab88773eu64,
    0x5d42870ae2270fb3u64,
    0xe7694b0d45f52b0du64,
    0x51133e2ed8491c34u64,
    0x56e76757187dede1u64,
    0x79d0eed9ddf5670bu64,
    0x3e642be8e3b3e541u64,
    0x492c60967aaa688fu64,
    0xa7460ab3f6fee8ffu64,
    0x29dfc928bf4e29acu64,
    0x37d15e6391bb8841u64,
    0xeace73452965c4e8u64,
    0x75841f6eea927c6fu64,
    0x8823d0f893734f95u64,
    0x83c02d4b34e8a6d4u64,
    0x5b22e8cfb5b1a0abu64,
];
#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
#[serde(bound = "")]
pub struct SimpleL2PrivateKey<F: RichField> {
    pub private_key: QHashOut<F>,
}

impl<F: RichField> SimpleL2PrivateKey<F> {
    pub fn new(private_key: QHashOut<F>) -> Self {
        Self { private_key }
    }
    pub fn get_public_key<H: AlgebraicHasher<F>>(&self) -> QHashOut<F> {
        QHashOut(H::hash_no_pad(&[
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[0]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[1]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[2]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[19]),
            self.private_key.0.elements[1],
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[1]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[2]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[3]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[4]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[5]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[6]),
            self.private_key.0.elements[0],
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[7]),
            self.private_key.0.elements[2],
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[8]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[9]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[10]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[11]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[12]),
            self.private_key.0.elements[3],
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[13]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[14]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[15]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[16]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[17]),
            F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[18]),
        ]))
    }
}
