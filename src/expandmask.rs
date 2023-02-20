use digest::{ExtendableOutput, Update, XofReader};

use crate::{keccak, params::*};

pub(crate) fn polyvecl_uniform_gamma1(
    p: &DilithiumParams,
    y: &mut [crate::poly::Poly],
    seed: &[u8],
    nonce: u16,
    keccak: &mut keccak::KeccakState,
) {
    debug_assert_eq!(y.len(), p.l);
    debug_assert_eq!(seed.len(), CRHBYTES);
    for (idx, y_elem) in Iterator::zip(0.., y.iter_mut()) {
        poly_uniform_gamma1(p, y_elem, seed, p.l as u16 * nonce + idx, keccak)
    }
}

pub(crate) fn poly_uniform_gamma1(
    p: &DilithiumParams,
    y_elem: &mut crate::poly::Poly,
    seed: &[u8],
    nonce: u16,
    keccak: &mut keccak::KeccakState,
) {
    debug_assert_eq!(seed.len(), CRHBYTES);
    // FIXME: This buf allocation is ugly, and also we should implement this in
    // a streaming fashion.
    // Buffer is largest for GAMMA1 == 2^19, where it is 20 bits per
    // coefficient.
    const BUF_CAP: usize = 20 * 256 / 8;
    let mut buf = [0; BUF_CAP];
    let buf_len = p.polyz_packedbytes;

    let mut xof = crate::keccak::SHAKE256::new(keccak);
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());
    let mut xofread = xof.finalize_xof();
    xofread.read(&mut buf[0..buf_len]);
    crate::packing::polyz_unpack(p, y_elem, &buf[0..buf_len]);
}
