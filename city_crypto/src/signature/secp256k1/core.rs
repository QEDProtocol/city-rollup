use crate::{
    hash::{base_types::hash256::Hash256, qhashout::QHashOut},
    signature::secp256k1::curve::{
        curve_types::AffinePoint,
        ecdsa::{ECDSAPublicKey, ECDSASignature},
        secp256k1::Secp256K1,
    },
};
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use plonky2::{
    field::{secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar},
    hash::hash_types::{HashOut, RichField},
};
use serde::{Deserialize, Serialize};

use serde_with::serde_as;

pub fn secp256k1_scalar_from_bytes(bytes: &[u8], offset: usize) -> Secp256K1Scalar {
    /*
    let mut arr = [0u64; 4];
    for i in 0..4 {
        arr[i] = u64::from_le_bytes(
            bytes[i * 8 + offset..(i + 1) * 8 + offset]
                .try_into()
                .unwrap(),
        );
    }
    */

    let arr: [u64; 4] = core::array::from_fn(|i| {
        u64::from_be_bytes(
            bytes[(3 - i) * 8 + offset..(3 - i + 1) * 8 + offset]
                .try_into()
                .unwrap(),
        )
    });
    Secp256K1Scalar(arr)
}

pub fn secp256k1_base_from_bytes(bytes: &[u8], offset: usize) -> Secp256K1Base {
    let arr: [u64; 4] = core::array::from_fn(|i| {
        u64::from_be_bytes(
            bytes[(3 - i) * 8 + offset..(3 - i + 1) * 8 + offset]
                .try_into()
                .unwrap(),
        )
    });
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

pub fn u256_to_der(u256: &[u8]) -> Vec<u8> {
    assert_eq!(u256.len(), 32);
    let mut result = vec![];
    result.push(0x02u8);
    if (u256[0] & 0x80) != 0 {
        result.push((u256.len() + 1) as u8);
        result.push(0);
        result.extend_from_slice(u256);
    } else {
        result.push(u256.len() as u8);
        result.extend_from_slice(u256);
    }
    result
}

impl QEDCompressedSecp256K1Signature {
    pub fn to_btc_script(&self) -> Vec<u8> {
        let r = u256_to_der(&self.signature[0..32]);
        let s = u256_to_der(&self.signature[32..64]);
        let combined_rs_length = (r.len() + s.len()) as u8;
        let sig_stack_raw = [
            vec![combined_rs_length + 3, 0x30u8, combined_rs_length],
            r,
            s,
            vec![0x01],
        ]
        .concat();
        [sig_stack_raw, vec![0x21], self.public_key.to_vec()].concat()
    }
}
#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
#[serde(bound = "")]
pub struct QEDPreparedSecp256K1Signature<F: RichField> {
    pub message: QHashOut<F>,
    pub public_key: ECDSAPublicKey<Secp256K1>,
    pub signature: ECDSASignature<Secp256K1>,
}

impl<F: RichField> TryFrom<&QEDCompressedSecp256K1Signature> for QEDPreparedSecp256K1Signature<F> {
    type Error = anyhow::Error;

    fn try_from(value: &QEDCompressedSecp256K1Signature) -> Result<Self, Self::Error> {
        let mut message = [F::ZERO; 4];
        for i in 0..4 {
            message[i] = F::from_noncanonical_u64(u64::from_le_bytes(
                value.message.0[i * 8..(i + 1) * 8].try_into().unwrap(),
            ));
        }
        let message_hash = QHashOut(HashOut { elements: message });
        let r = secp256k1_scalar_from_bytes(&value.signature, 0);
        let s = secp256k1_scalar_from_bytes(&value.signature, 32);

        let public_key_x = secp256k1_base_from_bytes(&value.public_key, 1);
        let public_key_point = k256::AffinePoint::decompress(
            value.public_key[1..33].into(),
            (value.public_key[0] & 0x1u8).into(),
        );
        if public_key_point.is_none().into() {
            return Err(anyhow::format_err!("Invalid public key"));
        }
        let public_key_point = public_key_point.unwrap();

        let public_key_bytes = public_key_point.to_encoded_point(false).as_bytes().to_vec();

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
