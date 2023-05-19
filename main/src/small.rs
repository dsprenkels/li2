use crate::{expanda, keccak, ntt, packing, params::*, poly, reduce};

use digest::{ExtendableOutput, Update, XofReader};

struct SignMemoryPool<'a> {
    sigbytes: &'a mut [u8],
    seedbuf: &'a mut [u8],
    s1: &'a mut [poly::Poly],
    y: &'a mut [poly::Poly],
    z: &'a mut [poly::Poly],
    t0: &'a mut [poly::Poly],
    s2: &'a mut [poly::Poly],
    w: &'a mut [poly::CompressedPoly],
    w1: &'a mut [poly::Poly],
    w0: &'a mut [poly::Poly],
    h: &'a mut [poly::Poly],
    cp: &'a mut poly::Poly,
    keccak: &'a mut crate::keccak::KeccakState,
}

pub fn dilithium2_signature(sk: &[u8], msg: &[u8], sig: &mut [u8]) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM2;
    dilithium_signature_mem::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, msg, sig)
}

pub fn dilithium3_signature(sk: &[u8], msg: &[u8], sig: &mut [u8]) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM3;
    dilithium_signature_mem::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, msg, sig)
}

pub fn dilithium5_signature(sk: &[u8], msg: &[u8], sig: &mut [u8]) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM5;
    dilithium_signature_mem::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, msg, sig)
}

fn dilithium_signature_mem<const K: usize, const L: usize, const KL: usize>(
    p: &'static DilithiumParams,
    sk: &[u8],
    msg: &[u8],
    sig: &mut [u8],
) -> Result<(), crate::Error> {
    let mut seedbuf = [0u8; 3 * SEEDBYTES + 2 * CRHBYTES];
    let mut s1 = [poly::Poly::zero(); L];
    let mut y = [poly::Poly::zero(); L];
    let mut z = [poly::Poly::zero(); L];
    let mut t0 = [poly::Poly::zero(); K];
    let mut s2 = [poly::Poly::zero(); K];
    let mut w = [poly::CompressedPoly::zero(); K];
    let mut w1 = [poly::Poly::zero(); K];
    let mut w0 = [poly::Poly::zero(); K];
    let mut h = [poly::Poly::zero(); K];
    let mut cp = poly::Poly::zero();

    let mem = SignMemoryPool {
        sigbytes: &mut sig[..],
        seedbuf: &mut seedbuf[..],
        s1: &mut s1[..],
        y: &mut y[..],
        z: &mut z[..],
        t0: &mut t0[..],
        s2: &mut s2[..],
        w: &mut w[..],
        w1: &mut w1[..],
        w0: &mut w0[..],
        h: &mut h[..],
        cp: &mut cp,
        keccak: &mut crate::keccak::KeccakState::default(),
    };

    dilithium_signature_inner(p, mem, sk, msg)
}

fn dilithium_signature_inner(
    p: &'static DilithiumParams,
    mem: SignMemoryPool<'_>,
    sk: &[u8],
    m: &[u8],
) -> Result<(), crate::Error> {
    use crate::expandmask;

    let mut nonce = 0u16;

    let seedbuf = mem.seedbuf;
    let (rho_old, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
    let (tr_old, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
    let (key_old, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
    let (mu, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
    let (rhoprime, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
    debug_assert_eq!(seedbuf, &[]);

    packing::unpack_sk(p, rho_old, tr_old, key_old, mem.t0, mem.s1, mem.s2, sk);

    let (rho, key, tr, s1bytes, s2bytes, t0bytes) = packing::sk_split(p, sk);

    // Compute mu := CRH(tr || msg)
    let mut xof = keccak::SHAKE256::new(mem.keccak);
    xof.update(tr);
    xof.update(m);
    xof.finalize_xof().read(mu);

    // Compute rhoprime := CRH(K || mu)
    let mut xof = keccak::SHAKE256::new(mem.keccak);
    xof.update(key);
    xof.update(mu);
    xof.finalize_xof().read(rhoprime);

    // Expand matrix and transform vectors
    ntt::polyvec_ntt(mem.s1);
    ntt::polyvec_ntt(mem.s2);
    ntt::polyvec_ntt(mem.t0);

    let mut attempt = 0;
    'rej: loop {
        attempt += 1;
        if attempt >= p.max_attempts {
            panic!("max attempts exceeded");
        }

        // Set w to 0
        for row in 0..p.k {
            for idx in 0..N {
                mem.w[row].set(idx, 0);
            }
        }

        // Matrix-vector multiplication
        for row in 0..p.k {
            mem.w[row] = poly::CompressedPoly::zero();
            mem.w1[row] = poly::Poly::zero();
        }
        for col in 0..p.l {
            // Sample intermediate vector y
            let mut y_elem = poly::Poly::zero();
            let expandmask_nonce = p.l as u16 * nonce + col as u16;
            expandmask::poly_uniform_gamma1(
                p,
                &mut y_elem,
                rhoprime,
                expandmask_nonce,
                mem.keccak,
            );
            ntt::poly_ntt(&mut y_elem);

            for row in 0..p.k {
                let expanda_nonce = ((row as u16) << 8) | col as u16;
                let mut expanda_iter = expanda::poly_uniform_iter(rho, expanda_nonce, mem.keccak);
                for idx in 0..N {
                    let a_coeff = expanda_iter.next().unwrap();
                    let y_coeff = y_elem.coeffs[idx];
                    let t = i64::wrapping_mul(a_coeff as i64, y_coeff as i64);
                    let mut coeff = mem.w[row].get(idx);
                    coeff = i32::wrapping_add(coeff, reduce::montgomery_reduce(t));
                    coeff = reduce::reduce32(coeff);
                    mem.w[row].set(idx, coeff);
                }
            }
        }

        // For now copy the compressed w back to uncompressed w for testing
        for row in 0..p.k {
            for idx in 0..N {
                mem.w1[row].coeffs[idx] = mem.w[row].get(idx);
            }
            ntt::poly_invntt_tomont(&mut mem.w1[row]);
        }

        // Decompose w and call the random oracle
        poly::polyvec_pointwise(mem.w1, crate::reduce::caddq);
        poly::polyveck_decompose(p, mem.w1, mem.w0);
        packing::pack_polyvec_w1(p, &mut mem.sigbytes[0..p.k * p.w1_poly_packed_len], mem.w1);

        // Compute challenge
        let mut xof = keccak::SHAKE256::new(mem.keccak);
        xof.update(mu);
        let w1_packed = &mem.sigbytes[0..p.k * p.w1_poly_packed_len];
        xof.update(w1_packed);
        let ctilde = &mut mem.sigbytes[..SEEDBYTES];
        xof.finalize_xof().read(ctilde);
        crate::challenge::sample_in_ball(p, mem.cp, &mem.sigbytes[0..SEEDBYTES], mem.keccak);
        ntt::poly_ntt(mem.cp);

        // Compute z, reject if it reveals secret
        poly::polyvec_pointwise_montgomery(mem.z, mem.cp, mem.s1);
        ntt::polyvec_invntt_tomont(mem.z);
        expandmask::polyvecl_uniform_gamma1(p, mem.y, rhoprime, nonce, mem.keccak);
        poly::polyvec_add(mem.z, mem.y);
        poly::polyvec_pointwise(mem.z, crate::reduce::reduce32);
        nonce += 1;
        if poly::polyvec_chknorm(mem.z, p.gamma1 - p.beta).is_err() {
            continue 'rej;
        }

        // Check that subtracting cs2 does not change high bits of w and
        // low bits do not reveal secret information
        poly::polyvec_pointwise_montgomery(mem.h, mem.cp, mem.s2);
        ntt::polyvec_invntt_tomont(mem.h);
        poly::polyvec_sub(mem.w0, mem.h);
        poly::polyvec_pointwise(mem.w0, crate::reduce::reduce32);
        if poly::polyvec_chknorm(mem.w0, p.gamma2 - p.beta).is_err() {
            continue 'rej;
        }

        // Compute hints for w1
        poly::polyvec_pointwise_montgomery(mem.h, mem.cp, mem.t0);
        ntt::polyvec_invntt_tomont(mem.h);
        poly::polyvec_pointwise(mem.h, crate::reduce::reduce32);
        if poly::polyvec_chknorm(mem.h, p.gamma2).is_err() {
            continue 'rej;
        }
        poly::polyvec_add(mem.w0, mem.h);
        let hints_popcount = poly::polyvec_make_hint(p, mem.w0, mem.w1);
        if hints_popcount > p.omega {
            continue 'rej;
        }

        // Write signature
        let mut tmp = [0; SEEDBYTES];
        tmp.copy_from_slice(&mem.sigbytes[0..SEEDBYTES]);
        packing::pack_sig(p, mem.sigbytes, &tmp, mem.z, mem.w0);
        break 'rej;
    }
    Ok(())
}

// For now just use stubs from the "fast" code
pub use crate::fast::{
    dilithium2_keygen_from_seed, dilithium2_verify, dilithium3_keygen_from_seed, dilithium3_verify,
    dilithium5_keygen_from_seed, dilithium5_verify,
};
