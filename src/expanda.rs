use digest::{ExtendableOutput, Update, XofReader};

use crate::{
    fips202::{KeccakState, SHAKE128},
    params::{DilithiumParams, N, Q},
};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct Poly {
    pub(crate) coeffs: [u32; 256],
}

pub(crate) fn polyvec_matrix_expand(p: &DilithiumParams, keccak: &mut KeccakState, mat: &mut [Poly], rho: &[u8]) {
    let mut idx = 0;
    for i in 0..p.k {
        for j in 0..p.l {
            let nonce = ((i as u16) << 8) | j as u16;
            poly_uniform(&p, keccak, &mut mat[idx], rho, nonce);
            idx += 1;
        }
    }
}

// void poly_uniform(poly *a,
//     const uint8_t seed[SEEDBYTES],
//     uint16_t nonce)
// {
// unsigned int i, ctr, off;
// unsigned int buflen = POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES;
// uint8_t buf[POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES + 2];
// stream128_state state;

// stream128_init(&state, seed, nonce);
// stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);

// ctr = rej_uniform(a->coeffs, N, buf, buflen);

// while(ctr < N) {
// off = buflen % 3;
// for(i = 0; i < off; ++i)
// buf[i] = buf[buflen - off + i];

// stream128_squeezeblocks(buf + off, 1, &state);
// buflen = STREAM128_BLOCKBYTES + off;
// ctr += rej_uniform(a->coeffs + ctr, N - ctr, buf, buflen);
// }
// }

fn poly_uniform(
    _p: &DilithiumParams,
    keccak: &mut KeccakState,
    poly: &mut Poly,
    seed: &[u8],
    nonce: u16,
) {
    let mut xof = SHAKE128::new(keccak);
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());
    let mut xofread = xof.finalize_xof();

    'coeff: for coeff in poly.coeffs.iter_mut() {
        loop {
            let mut sample = [0; 4];
            xofread.read(&mut sample[0..3]);
            let mut t = u32::from_le_bytes(sample);
            t &= 0x7FFFFF;
            if t < Q {
                *coeff = t;
                continue 'coeff;
            }
        }
    }
}
