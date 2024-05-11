use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::RichField;

pub trait QRichField: RichField {}
impl QRichField for GoldilocksField {}
