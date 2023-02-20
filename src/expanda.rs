use digest::{ExtendableOutput, Update, XofReader};

use crate::{keccak, params::*, poly};

pub(crate) fn polyvec_matrix_expand(
    p: &DilithiumParams,
    keccak: &mut keccak::KeccakState,
    mat: &mut [poly::Poly],
    rho: &[u8],
) {
    let mut idx = 0;
    for i in 0..p.k {
        for j in 0..p.l {
            let nonce = ((i as u16) << 8) | j as u16;
            poly_uniform(&p, keccak, &mut mat[idx], rho, nonce);
            idx += 1;
        }
    }
}

fn poly_uniform(
    _p: &DilithiumParams,
    keccak: &mut keccak::KeccakState,
    poly: &mut poly::Poly,
    seed: &[u8],
    nonce: u16,
) {
    let mut xof = keccak::SHAKE128::new(keccak);
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());
    let mut xofread = xof.finalize_xof();

    'coeff: for coeff in poly.coeffs.iter_mut() {
        loop {
            let mut sample = [0; 4];
            xofread.read(&mut sample[0..3]);
            let mut t = i32::from_le_bytes(sample);
            t &= 0x7FFFFF;
            if t < Q {
                *coeff = t;
                continue 'coeff;
            }
        }
    }
}
