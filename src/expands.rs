use digest::{ExtendableOutput, Update, XofReader};

use crate::{
    fips202,
    params::{DilithiumParams, CRHBYTES},
    Poly,
};

pub(crate) fn polyvec_uniform_eta(
    p: &DilithiumParams,
    keccak: &mut fips202::KeccakState,
    sx: &mut [Poly],
    rhoprime: &[u8],
    mut nonce: u16,
) -> u16 {
    for poly in sx.iter_mut() {
        poly_uniform_eta(p, keccak, poly, rhoprime, nonce);
        nonce += 1;
    }
    nonce
}

fn poly_uniform_eta(
    p: &DilithiumParams,
    keccak: &mut fips202::KeccakState,
    poly: &mut Poly,
    seed: &[u8],
    nonce: u16,
) {
    // TODO: Buffer in larger chunks than a single byte.

    debug_assert_eq!(seed.len(), CRHBYTES);

    let mut xof = fips202::SHAKE256::new(keccak);
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());
    let mut xofread = xof.finalize_xof();

    let mut coeffs = poly.coeffs.iter_mut();
    let mut coeff = coeffs.next().expect("poly has no coefficients");
    if p.ETA == 2 {
        loop {
            let mut sample = [0; 1];
            xofread.read(&mut sample);
            let mut t0 = u32::from(sample[0] & 0x0F);
            if t0 < 15 {
                t0 = t0.wrapping_sub((205u32.wrapping_mul(t0) >> 10).wrapping_mul(5));
                *coeff = 2u32.wrapping_sub(t0);
                coeff = match coeffs.next() {
                    Some(x) => x,
                    None => break,
                };
            }
            let mut t1 = u32::from(sample[0] >> 4);
            if t1 < 15 {
                t1 = t1.wrapping_sub((205u32.wrapping_mul(t1) >> 10).wrapping_mul(5));
                *coeff = 2u32.wrapping_sub(t1);
                coeff = match coeffs.next() {
                    Some(x) => x,
                    None => break,
                };
            }
        }
    } else if p.ETA == 4 {
        loop {
            let mut sample = [0; 1];
            xofread.read(&mut sample);
            let t0 = u32::from(sample[0] & 0x0F);
            if t0 < 9 {
                *coeff = 4u32.wrapping_sub(t0);
                coeff = match coeffs.next() {
                    Some(x) => x,
                    None => break,
                };
            }
            let t1 = u32::from(sample[0] >> 4);
            if t1 < 9 {
                *coeff = 4u32.wrapping_sub(t1);
                coeff = match coeffs.next() {
                    Some(x) => x,
                    None => break,
                };
            }
        }
    } else {
        unreachable!("invalid value for ETA: {}", p.ETA)
    }
}
