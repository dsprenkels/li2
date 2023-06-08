#![allow(clippy::needless_range_loop)]

// TODO: Order the public keys by tr instead of by rho
// TODO: Double-check that all the domain separation is sound

use crate::{challenge, expanda, ntt, reduce, DilithiumParams};
use crate::{keccak, packing, poly};
use crate::{params::*, rounding};
use core::usize;
use digest::{ExtendableOutput, Update, XofReader};
use rand::{self, Rng};
use std::vec;

#[derive(Debug, Clone, Copy)]
pub struct RingSecretKey<const L: usize, const K: usize> {
    key: [u8; SEEDBYTES],
    s1: [poly::Poly; L],
    s2: [poly::Poly; K],
}

#[derive(Debug, Clone, Copy)]
pub struct RingPubKey<const K: usize> {
    rho: [u8; SEEDBYTES],
    t: [poly::Poly; K],
}

#[derive(Debug, Clone, Copy)]
pub struct RingSigPart<const L: usize, const K: usize> {
    ctilde: [u8; SEEDBYTES],
    z: [poly::Poly; L],
}

pub type RingSig<const L: usize, const K: usize> = vec::Vec<RingSigPart<L, K>>;

#[derive(Debug, Clone, Copy)]
struct RingSigCtx<const L: usize, const K: usize, const W1PACKEDLEN: usize> {
    rho: [u8; SEEDBYTES],
    z: [poly::Poly; L],
    ctilde: [u8; SEEDBYTES],
    w1packed: [[u8; W1PACKEDLEN]; K],
}

fn ctx_into_sig<const L: usize, const K: usize, const W1PACKEDLEN: usize>(
    ringsigs: &[RingSigCtx<L, K, W1PACKEDLEN>],
) -> RingSig<L, K> {
    ringsigs
        .iter()
        .map(|cx| RingSigPart {
            ctilde: cx.ctilde,
            z: cx.z,
        })
        .collect()
}

pub fn dilithium2_ring_keypair(
    seed: &[u8; SEEDBYTES],
) -> (
    RingSecretKey<{ DILITHIUM2.l }, { DILITHIUM2.k }>,
    RingPubKey<{ DILITHIUM2.k }>,
) {
    dilithium_ring_keypair::<
        { DILITHIUM2.l },
        { DILITHIUM2.k },
        { DILITHIUM2.k * DILITHIUM2.l },
        { DILITHIUM2.w1_poly_packed_len },
    >(&DILITHIUM2, seed)
}
pub fn dilithium3_ring_keypair(
    seed: &[u8; SEEDBYTES],
) -> (
    RingSecretKey<{ DILITHIUM3.l }, { DILITHIUM3.k }>,
    RingPubKey<{ DILITHIUM3.k }>,
) {
    dilithium_ring_keypair::<
        { DILITHIUM3.l },
        { DILITHIUM3.k },
        { DILITHIUM3.k * DILITHIUM3.l },
        { DILITHIUM3.w1_poly_packed_len },
    >(&DILITHIUM3, seed)
}
pub fn dilithium5_ring_keypair(
    seed: &[u8; SEEDBYTES],
) -> (
    RingSecretKey<{ DILITHIUM5.l }, { DILITHIUM5.k }>,
    RingPubKey<{ DILITHIUM5.k }>,
) {
    dilithium_ring_keypair::<
        { DILITHIUM5.l },
        { DILITHIUM5.k },
        { DILITHIUM5.k * DILITHIUM5.l },
        { DILITHIUM5.w1_poly_packed_len },
    >(&DILITHIUM5, seed)
}

fn dilithium_ring_keypair<
    const L: usize,
    const K: usize,
    const KL: usize,
    const W1PACKEDLEN: usize,
>(
    p: &DilithiumParams,
    seed: &[u8; SEEDBYTES],
) -> (RingSecretKey<L, K>, RingPubKey<K>) {
    debug_assert_eq!(KL, K * L);
    debug_assert_eq!(seed.len(), SEEDBYTES);

    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut mat = [poly::Poly::zero(); KL];
    let mut s1 = [poly::Poly::zero(); L];
    let mut s2 = [poly::Poly::zero(); K];
    let mut t = [poly::Poly::zero(); K];
    let mut keccak = crate::keccak::KeccakState::default();
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(seed);
    xof.finalize_xof().read(&mut seedbuf);

    let (rho, seedbuf) = &mut seedbuf.split_at_mut(SEEDBYTES);
    let (rhoprime, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
    let (key, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
    debug_assert_eq!(seedbuf, &[]);

    // Expand matrix
    crate::expanda::polyvec_matrix_expand(p, &mut keccak, &mut mat, rho);

    // Sample short vectors s1 and s2
    let mut nonce = 0;
    let s1_mut: &mut [poly::Poly] = &mut s1;
    let s2_mut: &mut [poly::Poly] = &mut s2;
    nonce += crate::expands::polyvec_uniform_eta(p, &mut keccak, s1_mut, rhoprime, nonce);
    crate::expands::polyvec_uniform_eta(p, &mut keccak, s2_mut, rhoprime, nonce);

    // Matrix-vector multiplication
    let mut s1hat = s1;
    crate::ntt::polyvec_ntt(&mut s1hat);
    poly::polyvec_matrix_pointwise_montgomery(p, &mut t, &mat, &mut s1hat);
    poly::polyvec_pointwise(&mut t, &mut crate::reduce::reduce32);
    crate::ntt::polyvec_invntt_tomont(&mut t);

    // Add error vector s2
    poly::polyvec_add(&mut t, &s2);

    let mut rhobuf = [0; SEEDBYTES];

    rhobuf.copy_from_slice(rho);
    let mut keybuf = [0; SEEDBYTES];
    keybuf.copy_from_slice(key);
    (
        RingSecretKey {
            key: keybuf,
            s1,
            s2,
        },
        RingPubKey { rho: rhobuf, t },
    )
}

pub fn dilithium2_ring_signature<R>(
    rng: &mut R,
    sk: &RingSecretKey<{ DILITHIUM2.l }, { DILITHIUM2.k }>,
    pk: &RingPubKey<{ DILITHIUM2.k }>,
    other_pubkeys: &[RingPubKey<{ DILITHIUM2.k }>],
    msg: &[u8],
) -> RingSig<{ DILITHIUM2.l }, { DILITHIUM2.k }>
where
    R: rand::RngCore + rand::CryptoRng,
{
    dilithium_ring_signature::<
        { DILITHIUM2.l },
        { DILITHIUM2.k },
        { DILITHIUM2.l * DILITHIUM2.k },
        { DILITHIUM2.w1_poly_packed_len },
        R,
    >(&DILITHIUM2, rng, sk, pk, other_pubkeys, msg)
}
pub fn dilithium3_ring_signature<R>(
    rng: &mut R,
    sk: &RingSecretKey<{ DILITHIUM3.l }, { DILITHIUM3.k }>,
    pk: &RingPubKey<{ DILITHIUM3.k }>,
    other_pubkeys: &[RingPubKey<{ DILITHIUM3.k }>],
    msg: &[u8],
) -> RingSig<{ DILITHIUM3.l }, { DILITHIUM3.k }>
where
    R: rand::RngCore + rand::CryptoRng,
{
    dilithium_ring_signature::<
        { DILITHIUM3.l },
        { DILITHIUM3.k },
        { DILITHIUM3.l * DILITHIUM3.k },
        { DILITHIUM3.w1_poly_packed_len },
        R,
    >(&DILITHIUM3, rng, sk, pk, other_pubkeys, msg)
}
pub fn dilithium5_ring_signature<R>(
    rng: &mut R,
    sk: &RingSecretKey<{ DILITHIUM5.l }, { DILITHIUM5.k }>,
    pk: &RingPubKey<{ DILITHIUM5.k }>,
    other_pubkeys: &[RingPubKey<{ DILITHIUM5.k }>],
    msg: &[u8],
) -> RingSig<{ DILITHIUM5.l }, { DILITHIUM5.k }>
where
    R: rand::RngCore + rand::CryptoRng,
{
    dilithium_ring_signature::<
        { DILITHIUM5.l },
        { DILITHIUM5.k },
        { DILITHIUM5.l * DILITHIUM5.k },
        { DILITHIUM5.w1_poly_packed_len },
        R,
    >(&DILITHIUM5, rng, sk, pk, other_pubkeys, msg)
}

fn dilithium_ring_signature<
    const L: usize,
    const K: usize,
    const KL: usize,
    const W1PACKEDLEN: usize,
    R,
>(
    p: &DilithiumParams,
    rng: &mut R,
    sk: &RingSecretKey<L, K>,
    pk: &RingPubKey<K>,
    other_pubkeys: &[RingPubKey<K>],
    msg: &[u8],
) -> RingSig<L, K>
where
    R: rand::RngCore + rand::CryptoRng,
{
    let ringsigs = dilithium_ring_signature_inner::<L, K, KL, W1PACKEDLEN, R>(
        p,
        rng,
        sk,
        pk,
        other_pubkeys,
        msg,
    );
    ctx_into_sig(&ringsigs)
}

fn dilithium_ring_signature_inner<
    const L: usize,
    const K: usize,
    const KL: usize,
    const W1PACKEDLEN: usize,
    R,
>(
    p: &DilithiumParams,
    rng: &mut R,
    sk: &RingSecretKey<L, K>,
    pk: &RingPubKey<K>,
    other_pubkeys: &[RingPubKey<K>],
    msg: &[u8],
) -> vec::Vec<RingSigCtx<L, K, W1PACKEDLEN>>
where
    R: rand::RngCore + rand::CryptoRng,
{
    // Assert that the other pubkeys are already sorted
    assert!(other_pubkeys.windows(2).all(|w| w[0].rho < w[1].rho));

    // Simulate other signatures
    let mut ringsigs: vec::Vec<RingSigCtx<L, K, W1PACKEDLEN>> = vec::Vec::new();
    let mut other_pubkeys = vec::Vec::from(other_pubkeys);
    other_pubkeys.sort_by_key(|pk| pk.rho);
    for pubkey in &other_pubkeys {
        ringsigs.push(dilithium_ring_simulate::<K, L, KL, W1PACKEDLEN, R>(
            rng, p, pubkey,
        ));
    }

    // Precompute mu
    let mut keccak = keccak::KeccakState::default();
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    // Mitigate length-extension attacks by binding the amount of
    // participants in the ring signature.
    // TODO: Absorb tr instead of rho for each public key (or just absorb the whole public key)
    let participants = u32::try_from(other_pubkeys.len() + 1).expect("too many ring participants");
    xof.update(&participants.to_le_bytes());
    // Absorb rho for each public key
    let mut rhos = ringsigs.iter().map(|cx| cx.rho).collect::<vec::Vec<_>>();
    rhos.push(pk.rho);
    rhos.sort();
    let mu = compute_mu(&rhos, msg);

    // Start making the "real" signature
    let real = dilithium_ring_real::<K, L, KL, W1PACKEDLEN>(p, sk, pk, &mu, &ringsigs);
    ringsigs.push(real);
    ringsigs.sort_by_key(|ctx| ctx.rho);
    ringsigs
}

fn dilithium_ring_simulate<
    const K: usize,
    const L: usize,
    const KL: usize,
    const W1PACKEDLEN: usize,
    R,
>(
    rng: &mut R,
    p: &DilithiumParams,
    pk: &RingPubKey<K>,
) -> RingSigCtx<L, K, W1PACKEDLEN>
where
    R: rand::RngCore + rand::CryptoRng,
{
    let mut keccak = keccak::KeccakState::default();

    let mut attempt = 0;
    loop {
        attempt += 1;
        if attempt > p.max_attempts {
            panic!("max attempts exceeded");
        }

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

        // Sample challenge
        let mut c = poly::Poly::zero();
        challenge::sample_in_ball(p, &mut c, &ctilde, &mut keccak);
        let mut chat = c;
        ntt::poly_ntt(&mut chat);

        // Compute A*z
        let mut mat = [poly::Poly::zero(); KL];
        expanda::polyvec_matrix_expand(p, &mut keccak, &mut mat, &pk.rho);
        let mut az = [poly::Poly::zero(); K];
        poly::polyvec_matrix_pointwise_montgomery(p, &mut az, &mat, &zhat);
        ntt::polyvec_invntt_tomont(&mut az);

        // Compute c*t
        let mut that = pk.t;
        ntt::polyvec_ntt(&mut that);
        poly::polyvec_pointwise_montgomery_inplace(&mut that, &chat);
        ntt::polyvec_invntt_tomont(&mut that);
        let mut ct = that;
        poly::polyvec_pointwise(&mut ct, &mut reduce::reduce32);
        poly::polyvec_pointwise(&mut ct, &mut reduce::caddq);

        // Compute r1 and r0
        let mut r = az;
        poly::polyvec_sub(&mut r, &ct);
        poly::polyvec_pointwise(&mut r, &mut reduce::reduce32);
        poly::polyvec_pointwise(&mut r, &mut reduce::caddq);
        let mut r1 = r;
        let mut r0 = r;
        poly::polyvec_pointwise(&mut r1, &mut |coeff| rounding::highbits(p, coeff));
        poly::polyvec_pointwise(&mut r0, &mut |coeff| rounding::lowbits(p, coeff));

        // Do r0-check
        if poly::polyvec_chknorm(&r0, p.gamma2 - p.beta).is_err() {
            continue;
        }

        // Pack computed r1 into the commitment w1
        let mut w1packed = [[0; W1PACKEDLEN]; K];
        for i in 0..p.k {
            packing::pack_poly_w1(p, &mut w1packed[i], &r1[i]);
        }

        debug_assert_eq!(&compute_commitment(p, mat, z, c, pk.t), &r1);

        // Return ~c, w1
        return RingSigCtx {
            rho: pk.rho,
            z,
            ctilde,
            w1packed,
        };
    }
}

fn dilithium_ring_real<
    const K: usize,
    const L: usize,
    const KL: usize,
    const W1PACKEDLEN: usize,
>(
    p: &DilithiumParams,
    sk: &RingSecretKey<L, K>,
    pk: &RingPubKey<K>,
    mu: &[u8; CRHBYTES],
    simulated: &[RingSigCtx<L, K, W1PACKEDLEN>],
) -> RingSigCtx<L, K, W1PACKEDLEN> {
    let mut w1packed = [[0; W1PACKEDLEN]; K];

    let mut nonce = 0u16;
    let mut mat = [poly::Poly::zero(); KL];
    let mut y = [poly::Poly::zero(); L];
    let mut w1 = [poly::Poly::zero(); K];
    let mut w0 = [poly::Poly::zero(); K];
    let mut h = [poly::Poly::zero(); K];
    let mut cp = poly::Poly::zero();
    let mut keccak = keccak::KeccakState::default();
    let mut rhoprime = [0; CRHBYTES];

    let mut s1 = sk.s1;
    let mut s2 = sk.s2;

    // Compute rhoprime := CRH(K || mu)
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(&sk.key);
    xof.update(mu);
    xof.finalize_xof().read(&mut rhoprime);

    // Expand matrix and transform vectors
    crate::expanda::polyvec_matrix_expand(p, &mut keccak, &mut mat, &pk.rho);
    crate::ntt::polyvec_ntt(&mut s1);
    crate::ntt::polyvec_ntt(&mut s2);

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

        // Pack w1 into w1packed
        for i in 0..p.k {
            packing::pack_poly_w1(p, &mut w1packed[i], &w1[i]);
        }

        // Make sorted list of commitments
        let mut commitments = vec::Vec::new();
        for cx in simulated {
            commitments.push((cx.rho, cx.w1packed));
        }
        commitments.push((pk.rho, w1packed));
        commitments.sort_by_key(|(rho, _)| *rho);
        let commitments: vec::Vec<[[u8; W1PACKEDLEN]; K]> = commitments
            .into_iter()
            .map(|(_, w1packed)| w1packed)
            .collect();
        let mut ctilde = compute_challenge(mu, &commitments);

        // Compute c1 = c - c2 - c3 - ...
        for cx in simulated {
            for idx in 0..SEEDBYTES {
                ctilde[idx] ^= cx.ctilde[idx];
            }
        }
        let mut c = poly::Poly::zero();
        crate::challenge::sample_in_ball(p, &mut c, &ctilde, &mut keccak);
        cp = c;
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

        // Write signature
        return RingSigCtx {
            ctilde,
            rho: pk.rho,
            z,
            w1packed,
        };
    }

    // TODO: LEFT HERE
    // I just wrote this function, but nothing has been tested yet.
    // We should now add debug tests to ensure that the ring signatures are
    // correctly generated.
}

pub fn dilithium2_ring_verify(
    pks: &[RingPubKey<{ DILITHIUM2.k }>],
    msg: &[u8],
    sig: &RingSig<{ DILITHIUM2.l }, { DILITHIUM2.k }>,
) -> bool {
    dilithium_ring_verify::<
        { DILITHIUM2.l },
        { DILITHIUM2.k },
        { DILITHIUM2.k * DILITHIUM2.l },
        { DILITHIUM2.w1_poly_packed_len },
    >(&DILITHIUM2, pks, msg, sig)
}
pub fn dilithium3_ring_verify(
    pks: &[RingPubKey<{ DILITHIUM3.k }>],
    msg: &[u8],
    sig: &RingSig<{ DILITHIUM3.l }, { DILITHIUM3.k }>,
) -> bool {
    dilithium_ring_verify::<
        { DILITHIUM3.l },
        { DILITHIUM3.k },
        { DILITHIUM3.k * DILITHIUM3.l },
        { DILITHIUM3.w1_poly_packed_len },
    >(&DILITHIUM3, pks, msg, sig)
}
pub fn dilithium5_ring_verify(
    pks: &[RingPubKey<{ DILITHIUM5.k }>],
    msg: &[u8],
    sig: &RingSig<{ DILITHIUM5.l }, { DILITHIUM5.k }>,
) -> bool {
    dilithium_ring_verify::<
        { DILITHIUM5.l },
        { DILITHIUM5.k },
        { DILITHIUM5.k * DILITHIUM5.l },
        { DILITHIUM5.w1_poly_packed_len },
    >(&DILITHIUM5, pks, msg, sig)
}

fn dilithium_ring_verify<
    const L: usize,
    const K: usize,
    const KL: usize,
    const W1PACKEDLEN: usize,
>(
    p: &DilithiumParams,
    pks: &[RingPubKey<K>],
    msg: &[u8],
    sig: &RingSig<L, K>,
) -> bool {
    // TODO: `sig` type should be an actual sig (not context)

    assert_eq!(sig.len(), pks.len());
    let keccak = &mut crate::keccak::KeccakState::default();

    // Compute mu
    let rhos = pks.iter().map(|pk| pk.rho).collect::<vec::Vec<_>>();
    let mu = compute_mu(&rhos, msg);

    // For all signatures, compute the corresponding commitments
    let mut commitments = vec::Vec::with_capacity(sig.len());
    for (pk, part) in Iterator::zip(pks.iter(), sig.iter()) {
        // Check z norm
        if poly::polyvec_chknorm(&part.z, p.gamma1 - p.beta).is_err() {
            return false;
        }

        // Expand matrix
        let mut mat = [poly::Poly::zero(); KL];
        expanda::polyvec_matrix_expand(p, keccak, &mut mat, &pk.rho);

        // Sample challenge
        let mut c = poly::Poly::zero();
        crate::challenge::sample_in_ball(p, &mut c, &part.ctilde, keccak);

        // Compute commitment
        let w1 = compute_commitment(p, mat, part.z, c, pk.t);
        let mut w1packed = [[0; W1PACKEDLEN]; K];
        for idx in 0..K {
            packing::pack_poly_w1(p, &mut w1packed[idx], &w1[idx]);
        }
        commitments.push(w1packed);
    }

    // Compute main challenge
    let main_ctilde = compute_challenge(&mu, &commitments);

    // Check if the parts-challenges sum to the main challenge
    let mut parts_ctilde = [0; SEEDBYTES];
    for part in sig {
        for idx in 0..SEEDBYTES {
            parts_ctilde[idx] ^= part.ctilde[idx];
        }
    }

    assert_eq!(parts_ctilde, main_ctilde);
    true
}

fn compute_mu(rhos: &[[u8; SEEDBYTES]], msg: &[u8]) -> [u8; CRHBYTES] {
    let mut keccak = crate::keccak::KeccakState::default();
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    for rho in rhos {
        xof.update(rho);
    }
    xof.update(msg);
    let mut mu = [0; CRHBYTES];
    xof.finalize_xof().read(&mut mu);
    mu
}

/// Compute the challenge polynomial from mu and a list of packed w1 commitments.
fn compute_challenge<const K: usize, const W1PACKEDLEN: usize>(
    mu: &[u8; CRHBYTES],
    commitments: &[[[u8; W1PACKEDLEN]; K]],
) -> [u8; SEEDBYTES] {
    // Call random oracle with commitments in order of pubkey rho
    let mut keccak = crate::keccak::KeccakState::default();
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(mu);
    for commitment in commitments {
        for poly in commitment {
            xof.update(poly);
        }
    }
    let mut ctilde = [0; SEEDBYTES];
    xof.finalize_xof().read(&mut ctilde);
    ctilde
}

fn compute_commitment<const L: usize, const K: usize, const KL: usize>(
    p: &DilithiumParams,
    mat: [poly::Poly; KL],
    mut z: [poly::Poly; L],
    mut c: poly::Poly,
    mut t: [poly::Poly; K],
) -> [poly::Poly; K] {
    // Compute A*z
    ntt::polyvec_ntt(&mut z);
    let mut az = [poly::Poly::zero(); K];
    poly::polyvec_matrix_pointwise_montgomery(p, &mut az, &mat, &z);
    ntt::polyvec_invntt_tomont(&mut az);

    // Compute A*z - c*t
    ntt::poly_ntt(&mut c);
    ntt::polyvec_ntt(&mut t);
    poly::polyvec_pointwise_montgomery_inplace(&mut t, &c);
    ntt::polyvec_invntt_tomont(&mut t);
    poly::polyvec_sub(&mut az, &t);
    poly::polyvec_pointwise(&mut az, &mut reduce::reduce32);
    poly::polyvec_pointwise(&mut az, &mut reduce::caddq);

    // Compute w1' := HighBits(r)
    let mut w1 = az;
    poly::polyvec_pointwise(&mut w1, &mut |coeff| rounding::highbits(p, coeff));
    w1
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;
    use crate::DilithiumParams;

    struct NotRandom {
        i: u64,
    }

    const TESTS: u64 = 1000;

    impl rand::RngCore for NotRandom {
        fn next_u32(&mut self) -> u32 {
            self.i += 1;
            self.i as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.i += 1;
            self.i
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for i in dest.iter_mut() {
                *i = self.i as u8;
                self.i += 1;
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand::CryptoRng for NotRandom {}

    fn setup_sig<const L: usize, const K: usize, const KL: usize, const W1PACKEDLEN: usize>(
        p: &DilithiumParams,
        seed: u64,
    ) -> (
        (RingSecretKey<L, K>, RingPubKey<K>),
        vec::Vec<RingPubKey<K>>,
        vec::Vec<RingSigCtx<L, K, W1PACKEDLEN>>,
    ) {
        let mut rng = NotRandom { i: seed };
        let mut seed1 = [0u8; 32];
        rng.fill_bytes(&mut seed1);
        let mut seed2 = [0u8; 32];
        rng.fill_bytes(&mut seed2);
        let (sk0, pk0) = dilithium_ring_keypair::<L, K, KL, W1PACKEDLEN>(p, &seed1);
        let (_, pk1) = dilithium_ring_keypair::<L, K, KL, W1PACKEDLEN>(p, &seed2);

        let sig = dilithium_ring_signature_inner::<L, K, KL, W1PACKEDLEN, _>(
            p,
            &mut rng,
            &sk0,
            &pk0,
            &[pk1],
            &[],
        );

        let mut pks = vec![pk0, pk1];
        pks.sort_by_key(|pk| pk.rho);
        ((sk0, pk0), pks, sig)
    }

    #[test]
    fn test_challenges_sum() {
        const P: DilithiumParams = DILITHIUM2;

        for i in 0..TESTS {
            let (_, pks, sig) =
                setup_sig::<{ P.l }, { P.k }, { P.l * P.k }, { P.w1_poly_packed_len }>(&P, i);

            let mut ctilde_from_parts = [0; SEEDBYTES];
            for part in &sig {
                for idx in 0..SEEDBYTES {
                    ctilde_from_parts[idx] ^= part.ctilde[idx];
                }
            }

            let mu = compute_mu(&[pks[0].rho, pks[1].rho], &[]);
            let ctilde_from_commitments =
                compute_challenge(&mu, &[sig[0].w1packed, sig[1].w1packed]);

            assert_eq!(ctilde_from_parts, ctilde_from_commitments);
        }
    }

    #[test]
    fn test_verify_functional() {
        const P: DilithiumParams = DILITHIUM2;
        for i in 0..TESTS {
            let (_, pks, sig) =
                setup_sig::<{ P.l }, { P.k }, { P.l * P.k }, { P.w1_poly_packed_len }>(&P, i);
            assert!(sig.windows(2).all(|w| w[0].rho < w[1].rho));

            let sig = ctx_into_sig(&sig);

            let verified = dilithium_ring_verify::<
                { P.l },
                { P.k },
                { P.l * P.k },
                { P.w1_poly_packed_len },
            >(&P, &pks, &[], &sig);

            // Assert that sig.rhos are sorted
            assert!(verified);
        }
    }
}
