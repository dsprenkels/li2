use crate::params::*;
use crate::poly::polyvec_matrix_pointwise_montgomery;
use crate::rounding;
use crate::{challenge, expanda, ntt, reduce, DilithiumParams};
use crate::{keccak, packing, poly};
use digest::{ExtendableOutput, Update, XofReader};
use rand::{CryptoRng, Rng, RngCore};
use std::vec;

#[derive(Debug, Clone, Copy)]
struct RingSigCtx<const L: usize, const K: usize, const W1PACKEDLEN: usize> {
    rho: [u8; SEEDBYTES],
    z: [poly::Poly; L],
    hints: [poly::Poly; K],
    ctilde: [u8; SEEDBYTES],
    w1packed: [[u8; W1PACKEDLEN]; K],
}

fn dilithium_ring_signature<const K: usize, const L: usize, const KL: usize, R>(
    mut rng: R,
    p: &DilithiumParams,
    sk_bytes: &[u8],
    pubkeys: &[&[u8]],
    msg: &[u8],
) -> vec::Vec<([poly::Poly; L], [poly::Poly; K], [u8; SEEDBYTES])>
where
    R: RngCore + CryptoRng,
{
    let mut sk_mat = [poly::Poly::zero(); KL];
    let mut sk_s1 = [poly::Poly::zero(); L];
    let mut sk_y = [poly::Poly::zero(); L];
    let mut sk_t0 = [poly::Poly::zero(); K];
    let mut sk_s2 = [poly::Poly::zero(); K];
    let mut sk_w1 = [poly::Poly::zero(); K];
    let mut sk_w0 = [poly::Poly::zero(); K];
    let mut sk_h = [poly::Poly::zero(); K];
    let mut sk_cp = poly::Poly::zero();
    let mut sk_keccak = keccak::KeccakState::default();

    let mut sk_rho = [0; SEEDBYTES];
    let mut sk_tr = [0; SEEDBYTES];
    let mut sk_key = [0; SEEDBYTES];
    let mut sk_mu = [0; CRHBYTES];
    let mut sk_rhoprime = [0; CRHBYTES];
    packing::unpack_sk(
        p,
        &mut sk_rho,
        &mut sk_tr,
        &mut sk_key,
        &mut sk_t0,
        &mut sk_s1,
        &mut sk_s2,
        sk_bytes,
    );

    // Simulate other signatures
    let mut ringsigs = vec::Vec::new();
    for pk_bytes in pubkeys {
        ringsigs.push(dilithium_ring_simulate(rng, p, pk_bytes));
    }
    ringsigs.sort_by_key(|ctx| ctx.rho);

    // Precompute mu
    let mut mu = [0; CRHBYTES];
    let mut keccak = keccak::KeccakState::default();
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    // Mitigate length-extension attacks by binding the amount of
    // participants in the ring signature.
    let participants = u32::try_from(pubkeys.len() + 1).expect("too many ring participants");
    xof.update(&participants.to_le_bytes());
    let mut sk_tr_absorbed = false;
    for ctx in ringsigs {
        if !sk_tr_absorbed && sk_rho < ctx.rho {
            xof.update(&sk_tr);
            sk_tr_absorbed = true;
        }
        xof.update(&ctx.rho);
    }
    xof.update(msg);
    xof.finalize_xof().read(&mut mu);

    // Start making the "real" signature
    let real = dilithium_ring_real(p, sk_bytes, &mu, &ringsigs);
    ringsigs.push(real);
    ringsigs.sort_by_key(|ctx| ctx.rho);

    todo!("serialize and return ring signature")
}

fn dilithium_ring_real<
    const K: usize,
    const L: usize,
    const KL: usize,
    const W1PACKEDLEN: usize,
>(
    p: &DilithiumParams,
    sk_bytes: &[u8],
    mu: &[u8; CRHBYTES],
    simulated: &[RingSigCtx<L, K, W1PACKEDLEN>],
) -> RingSigCtx<L, K, W1PACKEDLEN> {
    let mut w1packed = [[0; W1PACKEDLEN]; K];

    let mut nonce = 0u16;
    let mut mat = [poly::Poly::zero(); KL];
    let mut s1 = [poly::Poly::zero(); L];
    let mut y = [poly::Poly::zero(); L];
    let mut t0 = [poly::Poly::zero(); K];
    let mut s2 = [poly::Poly::zero(); K];
    let mut w1 = [poly::Poly::zero(); K];
    let mut w0 = [poly::Poly::zero(); K];
    let mut h = [poly::Poly::zero(); K];
    let mut cp = poly::Poly::zero();
    let mut keccak = keccak::KeccakState::default();

    let mut rho = [0; SEEDBYTES];
    let mut tr = [0; SEEDBYTES];
    let mut key = [0; SEEDBYTES];
    let mut mu = [0; CRHBYTES];
    let mut rhoprime = [0; CRHBYTES];
    let mut ctilde = [0; SEEDBYTES];
    packing::unpack_sk(
        p, &mut rho, &mut tr, &mut key, &mut t0, &mut s1, &mut s2, sk_bytes,
    );

    // Compute rhoprime := CRH(K || mu)
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(&key);
    xof.update(&mu);
    xof.finalize_xof().read(&mut rhoprime);

    // Expand matrix and transform vectors
    crate::expanda::polyvec_matrix_expand(p, &mut keccak, &mut mat, &rho);
    crate::ntt::polyvec_ntt(&mut s1);
    crate::ntt::polyvec_ntt(&mut s2);
    crate::ntt::polyvec_ntt(&mut t0);

    let mut attempt = 0;
    'rej: loop {
        attempt += 1;
        if attempt >= p.max_attempts {
            panic!("max attempts exceeded");
        }

        // Sample intermediate vector y
        crate::expandmask::polyvecl_uniform_gamma1(p, &mut y, &rhoprime, nonce, &mut keccak);
        nonce += 1;

        // Matrix-vector multiplication
        let mut z = y;
        crate::ntt::polyvec_ntt(&mut z);
        poly::polyvec_matrix_pointwise_montgomery(p, &mut w1, &mat, &z);
        poly::polyvec_pointwise(&mut w1, &mut reduce::reduce32);
        crate::ntt::polyvec_invntt_tomont(&mut w1);

        // Decompose w
        poly::polyvec_pointwise(&mut w1, &mut reduce::caddq);
        poly::polyveck_decompose(p, &mut w1, &mut w0);

        // Call random oracle withh commitments in order of pubkey rho
        let mut xof = keccak::SHAKE256::new(&mut keccak);
        let mut absorbed_real_w1 = false;
        for ctx in simulated {
            if !absorbed_real_w1 && rho < ctx.rho {
                for i in 0..p.k {
                    packing::pack_poly_w1(p, &mut w1packed[i], &w1[i]);
                    xof.update(&w1packed[i]);
                }
                absorbed_real_w1 = true;
            }
            for i in 0..p.k {
                xof.update(&ctx.w1packed[i]);
            }
        }
        xof.finalize_xof().read(&mut ctilde);

        // Compute c1 = c - c2 - c3 - ...
        for ctx in simulated {
            for i in 0..SEEDBYTES {
                ctilde[i] ^= ctx.ctilde[i];
            }
        }
        crate::challenge::sample_in_ball(p, &mut cp, &ctilde, &mut keccak);
        crate::ntt::poly_ntt(&mut cp);

        // Compute z, reject if it reveals secret
        poly::polyvec_pointwise_montgomery(&mut z, &cp, &s1);
        crate::ntt::polyvec_invntt_tomont(&mut z);
        poly::polyvec_add(&mut z, &y);
        poly::polyvec_pointwise(&mut z, &mut crate::reduce::reduce32);
        if poly::polyvec_chknorm(&z, p.gamma1 - p.beta).is_err() {
            continue 'rej;
        }

        // Check that subtracting cs2 does not change high bits of w and
        // low bits do not reveal secret information
        poly::polyvec_pointwise_montgomery(&mut h, &cp, &s2);
        crate::ntt::polyvec_invntt_tomont(&mut h);
        poly::polyvec_sub(&mut w0, &h);
        poly::polyvec_pointwise(&mut w0, &mut crate::reduce::reduce32);
        if poly::polyvec_chknorm(&w0, p.gamma2 - p.beta).is_err() {
            continue 'rej;
        }

        // Compute hints for w1
        poly::polyvec_pointwise_montgomery(&mut h, &cp, &t0);
        crate::ntt::polyvec_invntt_tomont(&mut h);
        poly::polyvec_pointwise(&mut h, &mut crate::reduce::reduce32);
        if poly::polyvec_chknorm(&h, p.gamma2).is_err() {
            continue 'rej;
        }
        poly::polyvec_add(&mut w0, &h);
        let hints_popcount = poly::polyvec_make_hint(p, &mut w0, &w1);
        if hints_popcount > p.omega {
            continue 'rej;
        }

        // Write signature
        return RingSigCtx {
            ctilde,
            hints: w0,
            rho,
            z,
            w1packed,
        };
    }

    // TODO: LEFT HERE
    // I just wrote this function, but nothing has been tested yet.
    // We should now add debug tests to ensure that the ring signatures are
    // correctly generated.
}

fn dilithium_ring_simulate<
    const K: usize,
    const L: usize,
    const KL: usize,
    const W1PACKEDLEN: usize,
    R,
>(
    mut rng: R,
    p: &DilithiumParams,
    pk_bytes: &[u8],
) -> RingSigCtx<L, K, W1PACKEDLEN>
where
    R: RngCore + CryptoRng,
{
    debug_assert_eq!(pk_bytes.len(), p.public_key_len);

    let mut keccak = keccak::KeccakState::default();

    let mut rho = [0; SEEDBYTES];
    let mut t1 = [poly::Poly::zero(); K];
    packing::unpack_pk(p, &mut rho, &mut t1, pk_bytes);

    // Sample random ctile
    let mut ctilde = [0; SEEDBYTES];
    rng.fill_bytes(&mut ctilde);

    // Sample random z below ||gamma1 - beta||
    let mut z = [poly::Poly::zero(); L];
    poly::polyvec_pointwise(&mut z, &mut |_| {
        rng.gen_range(-p.gamma1 + p.beta + 1..=p.gamma1 - p.beta - 1)
    });
    let mut zhat = z;
    ntt::polyvec_ntt(&mut zhat);

    // Compute Az
    let mut mat = [poly::Poly::zero(); KL];
    expanda::polyvec_matrix_expand(p, &mut keccak, &mut mat, &rho);
    let mut what = [poly::Poly::zero(); K];
    polyvec_matrix_pointwise_montgomery(p, &mut what, &mat, &z);

    // Compute ct1
    let mut c = poly::Poly::zero();
    challenge::sample_in_ball(p, &mut c, &ctilde, &mut keccak);
    let mut chat = c;
    ntt::poly_ntt(&mut chat);
    let mut t1hat = t1.clone();
    ntt::polyvec_ntt(&mut t1hat);

    // Compute Az - ct1
    poly::polyvec_sub(&mut what, &t1hat);
    let mut w = what;
    ntt::polyvec_invntt_tomont(&mut w);
    poly::polyvec_pointwise(&mut w, &mut reduce::reduce32);
    poly::polyvec_pointwise(&mut w, &mut reduce::caddq);

    // Compute w1' = UseHint(Az - ct1)
    let hints = sample_hints(&mut rng, p, chat);
    poly::polyvec_use_hint(p, &mut w, &hints);

    // Pack computed w1
    let mut w1packed = [[0; W1PACKEDLEN]; K];
    for i in 0..p.k {
        packing::pack_poly_w1(p, &mut w1packed[i], &w[i]);
    }

    // Return ~c, w1
    RingSigCtx {
        rho,
        z,
        hints,
        ctilde,
        w1packed,
    }
}

fn sample_hints<const K: usize, R>(
    mut rng: R,
    p: &DilithiumParams,
    chat: poly::Poly,
) -> [poly::Poly; K]
where
    R: RngCore + CryptoRng,
{
    // At this point I haven't figured out what the exact probability is of
    // some h coefficient being equal to 1.
    // So for now we just simulate this using some randomly generated t0
    // values.
    // TODO: Figure out that probability and use it here.

    loop {
        let mut popcount = 0;

        let mut ct0 = [poly::Poly::zero(); K];
        poly::polyvec_pointwise(&mut ct0, &mut |_| {
            let t0_range = -2i32.pow(D) / 2..2i32.pow(D) / 2;
            rng.gen_range(t0_range)
        });

        // Multiply to get some dummy ct0
        ntt::polyvec_ntt(&mut ct0);
        poly::polyvec_pointwise_montgomery_inplace(&mut ct0, &chat);
        poly::polyvec_pointwise(&mut ct0, &mut |ct0_coeff| {
            reduce::reduce32(ct0_coeff);
            reduce::caddq(ct0_coeff);

            let w_range = 0..Q;
            let mut w_coeff = rng.gen_range(w_range);
            w_coeff += ct0_coeff;
            reduce::reduce32(w_coeff);
            reduce::caddq(w_coeff);

            let hint = rounding::make_hint(p, -ct0_coeff, w_coeff);
            popcount += usize::from(hint);
            hint.into()
        });

        if popcount <= p.omega {
            return ct0;
        }
    }
}
