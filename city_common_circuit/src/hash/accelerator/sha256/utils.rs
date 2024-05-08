use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/*pub fn get_pad_length_sha256_bytes(msg_length: usize) -> usize {
    let mut pad_length = msg_length + 1; // +1 for 0x80

    // Find number of zeros
    let mdi = msg_length % 64;
    assert!(mdi < 120);
    let padlen = if mdi < 56 { 55 - mdi } else { 119 - mdi };
    // Pad with zeros
    pad_length += padlen;

    // add length as 64 bit number
    pad_length += 8;
    pad_length
}*/
pub fn get_pad_length_sha256_bytes(msg_length: usize) -> usize {
    let mdi = msg_length % 64;
    let pad_amount = if mdi < 56 { 55 - mdi } else { 119 - mdi };
    msg_length + 1 + pad_amount + 8
}
pub fn get_pad_length_sha256_u32(msg_length: usize) -> usize {
    get_pad_length_sha256_bytes(msg_length) / 4
}

/*

function reconstructInputsData(data, inputByteLengths) {

  const inputs = [];
  let pos = 0;
  for (let i = 0; i < inputByteLengths.length; i++) {
    let localExcess = inputByteLengths[i] % 4;
    let trimmedLength = inputByteLengths[i]-localExcess;
    const input = [];
    for(let j = 0;j<trimmedLength;j+=4){
      input[j] = data[pos+j+3];
      input[j+1] = data[pos+j+2];
      input[j+2] = data[pos+j+1];
      input[j+3] = data[pos+j];
    }
    for(let k=0;k<localExcess;k++){
      input[k+trimmedLength] = data[pos+trimmedLength+3-k];
    }
    inputs[i] = input;
    pos += getPaddedLength(inputByteLengths[i]);
  }
  return inputs;
}
*/
pub fn reconstruct_preimages_sha256<T: Sized + Copy>(
    outputs: &[T],
    preimage_lengths: &[usize],
) -> Vec<Vec<T>> {
    let mut pos: usize = 0;
    //let mut results: Vec<Vec<T>> = Vec::new();
    preimage_lengths
        .iter()
        .map(|len_ptr| {
            let len = *len_ptr;
            let local_excess = len % 4;
            let trimmed_length = len - local_excess;
            let mut input: Vec<T> = Vec::with_capacity(len);
            (0..trimmed_length).step_by(4).for_each(|j| {
                input.push(outputs[pos + j + 3]);
                input.push(outputs[pos + j + 2]);
                input.push(outputs[pos + j + 1]);
                input.push(outputs[pos + j]);
            });
            (0..local_excess).for_each(|k| {
                input.push(outputs[pos + trimmed_length + 3 - k]);
            });
            pos += get_pad_length_sha256_bytes(len);
            input
        })
        .collect()
}

pub fn reconstruct_preimages_sha256_constrain_padding_length<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    outputs: &[Target],
    preimage_lengths: &[usize],
) -> (Vec<Vec<Target>>, usize) {
    let mut pos: usize = 0;
    let zero = builder.zero();
    //let mut results: Vec<Vec<T>> = Vec::new();
    let results = preimage_lengths
        .iter()
        .map(|len_ptr| {
            let len = *len_ptr;
            let local_excess = len % 4;
            let trimmed_length = len - local_excess;
            let mut input: Vec<Target> = Vec::with_capacity(len);
            (0..trimmed_length).step_by(4).for_each(|j| {
                input.push(outputs[pos + j + 3]);
                input.push(outputs[pos + j + 2]);
                input.push(outputs[pos + j + 1]);
                input.push(outputs[pos + j]);
            });
            (0..local_excess).for_each(|k| {
                input.push(outputs[pos + trimmed_length + 3 - k]);
            });
            let end_sep = builder.constant(F::from_canonical_u8(0x80));
            if local_excess == 3 {
                builder.connect(outputs[pos + trimmed_length], end_sep);
            } else if local_excess == 2 {
                builder.connect(outputs[pos + trimmed_length], zero);
                builder.connect(outputs[pos + trimmed_length + 1], end_sep);
            } else if local_excess == 1 {
                builder.connect(outputs[pos + trimmed_length], zero);
                builder.connect(outputs[pos + trimmed_length + 1], zero);
                builder.connect(outputs[pos + trimmed_length + 2], end_sep);
            } else {
                builder.connect(outputs[pos + trimmed_length], zero);
                builder.connect(outputs[pos + trimmed_length + 1], zero);
                builder.connect(outputs[pos + trimmed_length + 2], zero);
                builder.connect(outputs[pos + trimmed_length + 3], end_sep);
            }
            let end_pos = pos + trimmed_length + 4;

            let total_pad_length = get_pad_length_sha256_bytes(len);

            // we won't be hashing anything larger than 512mb, so we can safely assume that
            // the length will fit in 4 bytes (instead of 8)
            let final_pos = pos + total_pad_length - 4;

            (end_pos..final_pos).for_each(|i| {
                builder.connect(outputs[i], zero);
            });

            let bit_length: u32 = len as u32 * 8;
            let bit_length_bytes = bit_length.to_le_bytes();
            bit_length_bytes.iter().enumerate().for_each(|(i, &byte)| {
                let byte_target = builder.constant(F::from_canonical_u8(byte));
                builder.connect(outputs[final_pos + i], byte_target);
            });

            pos += total_pad_length;
            input
        })
        .collect();
    (results, pos)
}

pub fn pad_preimage_virtual_targets_sha256<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    preimage_bytes_target: &[Target],
) -> Vec<Target> {
    let mut padded = preimage_bytes_target.to_vec();
    let total_len = get_pad_length_sha256_bytes(preimage_bytes_target.len());
    (preimage_bytes_target.len()..total_len).for_each(|_| {
        padded.push(builder.add_virtual_target());
    });
    padded
}
