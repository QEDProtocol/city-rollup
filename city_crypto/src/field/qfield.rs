use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};

pub trait QRichField: RichField {}
impl QRichField for GoldilocksField {}
