use digest::{ExtendableOutput, Update, XofReader};

use crate::{params::*, poly};

pub(crate) fn sample_in_ball(
    p: &DilithiumParams,
    c: &mut poly::Poly,
    seed: &[u8],
    keccak: &mut crate::keccak::KeccakState,
) {
    debug_assert_eq!(seed.len(), SEEDBYTES);
    let tau = p.tau as usize;

    let mut xof = crate::keccak::SHAKE256::new(keccak);
    xof.update(seed);
    let mut xofread = xof.finalize_xof();

    let mut signs_arr = [0u8; 8];
    xofread.read(&mut signs_arr);
    let mut signs = u64::from_le_bytes(signs_arr);

    *c = poly::Poly::zero();
    for i in N - tau..N {
        let b = loop {
            let mut b_arr = [0u8];
            xofread.read(&mut b_arr);
            let b = usize::from(b_arr[0]);
            if b > i {
                continue;
            }
            break b;
        };

        c.coeffs[i] = c.coeffs[b];
        c.coeffs[b] = if signs & 0x1 != 0 { -1 } else { 1 };
        signs >>= 1;
    }
}
