#![allow(clippy::needless_range_loop)]

use crate::params::*;
use crate::{challenge, expanda, ntt, reduce, DilithiumParams};
use crate::{keccak, packing, poly};
use digest::{ExtendableOutput, Update, XofReader};
use rand::{self, Rng};
use std::vec;

#[derive(Debug, Clone, Copy)]
struct RingSecretKey<const L: usize, const K: usize> {
    key: [u8; SEEDBYTES],
    s1: [poly::Poly; L],
    s2: [poly::Poly; K],
}

#[derive(Debug, Clone, Copy)]
struct RingPubKey<const K: usize> {
    rho: [u8; SEEDBYTES],
    t: [poly::Poly; K],
}

#[derive(Debug, Clone, Copy)]
struct RingSigPart<const L: usize, const K: usize> {
    // XXX: ctilde and rho are only here for debugging for now
    ctilde: [u8; SEEDBYTES],
    rho: [u8; SEEDBYTES],
    z: [poly::Poly; L],
    hints: [poly::Poly; K],
}

type RingSig<const L: usize, const K: usize> = vec::Vec<RingSigPart<L, K>>;

#[derive(Debug, Clone, Copy)]
struct RingSigCtx<const L: usize, const K: usize, const W1PACKEDLEN: usize> {
    rho: [u8; SEEDBYTES],
    z: [poly::Poly; L],
    hints: [poly::Poly; K],
    ctilde: [u8; SEEDBYTES],
    w1packed: [[u8; W1PACKEDLEN]; K],
}

fn dilithium_ring_keypair<
    const K: usize,
    const L: usize,
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

fn dilithium_ring_signature<
    const K: usize,
    const L: usize,
    const KL: usize,
    const W1PACKEDLEN: usize,
    R,
>(
    p: &DilithiumParams,
    mut rng: R,
    sk: &RingSecretKey<L, K>,
    pk: &RingPubKey<K>,
    other_pubkeys: &[RingPubKey<K>],
    msg: &[u8],
) -> vec::Vec<RingSigCtx<L, K, W1PACKEDLEN>>
where
    R: rand::RngCore + rand::CryptoRng,
{
    // Simulate other signatures
    let mut ringsigs: vec::Vec<RingSigCtx<L, K, W1PACKEDLEN>> = vec::Vec::new();
    for pubkey in other_pubkeys {
        ringsigs.push(dilithium_ring_simulate::<K, L, KL, W1PACKEDLEN, R>(
            &mut rng, p, pubkey,
        ));
    }
    ringsigs.sort_by_key(|ctx| ctx.rho);

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
    // ringsigs
    //     .into_iter()
    //     .map(|cx| RingSigPart {
    //         ctilde: cx.ctilde,
    //         rho: cx.rho,
    //         z: cx.z,
    //         hints: cx.hints,
    //     })
    //     .collect()
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
    expanda::polyvec_matrix_expand(p, &mut keccak, &mut mat, &pk.rho);
    let mut az = [poly::Poly::zero(); K];
    poly::polyvec_matrix_pointwise_montgomery(p, &mut az, &mat, &z);
    ntt::polyvec_invntt_tomont(&mut az);

    // Sample challenge
    let mut c = poly::Poly::zero();
    challenge::sample_in_ball(p, &mut c, &ctilde, &mut keccak);
    let mut chat = c;
    ntt::poly_ntt(&mut chat);

    // Extract t1 and t0
    let mut t = pk.t;
    let mut t1 = pk.t;
    let mut t0 = pk.t;
    poly::polyvec_pointwise(&mut t, &mut crate::reduce::caddq);
    for (t0_elem, t1_elem) in &mut t0.iter_mut().zip(&mut t1.iter_mut()) {
        for (t0_coeff, t1_coeff) in t0_elem.coeffs.iter_mut().zip(t1_elem.coeffs.iter_mut()) {
            (*t0_coeff, *t1_coeff) = crate::rounding::power2round(*t1_coeff);
        }
    }

    // Compute ct, ct1, and ct0
    let mulc = |v: [poly::Poly; K]| {
        let mut vhat = v;
        ntt::polyvec_ntt(&mut vhat);
        poly::polyvec_pointwise_montgomery_inplace(&mut vhat, &chat);
        ntt::polyvec_invntt_tomont(&mut vhat);
        let mut cv = vhat;
        poly::polyvec_pointwise(&mut cv, &mut reduce::reduce32);
        cv
    };
    let ct = mulc(t);
    let ct0 = mulc(t0);

    // Perform r0-check
    if poly::polyvec_chknorm(&ct0, p.gamma2).is_err() {
        todo!("{:?}", &ct0);
    }

    // Compute r = Az - ct
    let mut r = az;
    poly::polyvec_sub(&mut r, &ct);
    poly::polyvec_pointwise(&mut r, &mut reduce::reduce32);
    poly::polyvec_pointwise(&mut r, &mut reduce::caddq);

    // Compute hints
    let mut r0 = [poly::Poly::zero(); K];
    poly::polyveck_decompose(p, &mut r, &mut r0);
    let r1 = r;
    poly::polyvec_add(&mut r0, &ct0);
    let hints_popcount = poly::polyvec_make_hint(p, &mut r0, &r);
    if hints_popcount > p.omega {
        todo!("cannot construct hints that will recover r");
    }
    let hints = r0;

    // Pack computed r1 into the commitment w1
    let mut w1packed = [[0; W1PACKEDLEN]; K];
    for i in 0..p.k {
        packing::pack_poly_w1(p, &mut w1packed[i], &r1[i]);
    }

    // Return ~c, w1
    RingSigCtx {
        rho: pk.rho,
        z,
        hints,
        ctilde,
        w1packed,
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
    let mut t1 = [poly::Poly::zero(); K];
    let mut t0 = [poly::Poly::zero(); K];
    let mut w1 = [poly::Poly::zero(); K];
    let mut w0 = [poly::Poly::zero(); K];
    let mut h = [poly::Poly::zero(); K];
    let mut cp = poly::Poly::zero();
    let mut keccak = keccak::KeccakState::default();
    let mut rhoprime = [0; CRHBYTES];

    let mut s1 = sk.s1;
    let mut s2 = sk.s2;

    // Extract t1 and t0
    for idx in 0..K {
        for idx2 in 0..N {
            let t_coeff = pk.t[idx].coeffs[idx2];
            let (t0_coeff, t1_coeff) = crate::rounding::power2round(t_coeff);
            t0[idx].coeffs[idx2] = t0_coeff;
            t1[idx].coeffs[idx2] = t1_coeff;
        }
    }

    // Compute rhoprime := CRH(K || mu)
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(&sk.key);
    xof.update(mu);
    xof.finalize_xof().read(&mut rhoprime);

    // Expand matrix and transform vectors
    crate::expanda::polyvec_matrix_expand(p, &mut keccak, &mut mat, &pk.rho);
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
        std::dbg!(ctilde);

        // Compute c1 = c - c2 - c3 - ...
        for ctx in simulated {
            for idx in 0..SEEDBYTES {
                ctilde[idx] ^= ctx.ctilde[idx];
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

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;
    use crate::DilithiumParams;

    struct NotRandom {
        i: u64,
    }

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
    ) -> (
        (RingSecretKey<L, K>, RingPubKey<K>),
        vec::Vec<RingPubKey<K>>,
        vec::Vec<RingSigCtx<L, K, W1PACKEDLEN>>,
    ) {
        let mut rng = NotRandom { i: 0 };
        let mut seed1 = [0u8; 32];
        rng.fill_bytes(&mut seed1);
        let mut seed2 = [0u8; 32];
        rng.fill_bytes(&mut seed2);
        let (sk0, pk0) = dilithium_ring_keypair::<K, L, KL, W1PACKEDLEN>(p, &seed1);
        let (_, pk1) = dilithium_ring_keypair::<K, L, KL, W1PACKEDLEN>(p, &seed2);

        let sig = dilithium_ring_signature::<K, L, KL, W1PACKEDLEN, _>(
            p,
            &mut rng,
            &sk0,
            &pk0,
            &[pk1],
            &[],
        );

        ((sk0, pk0), vec![pk0, pk1], sig)
    }

    #[test]
    fn test_challenges_sum() {
        const p: DilithiumParams = DILITHIUM2;
        let ((sk0, pk0), pks, sig) =
            setup_sig::<{ p.l }, { p.k }, { p.l * p.k }, { p.w1_poly_packed_len }>(&p);

        let mut ctilde_from_parts = [0; SEEDBYTES];
        for part in &sig {
            for idx in 0..SEEDBYTES {
                ctilde_from_parts[idx] ^= part.ctilde[idx];
            }
        }

        let mu = compute_mu(&[pks[0].rho, pks[1].rho], &[]);
        let ctilde_from_commitments = compute_challenge(&mu, &[sig[0].w1packed, sig[1].w1packed]);

        assert_eq!(ctilde_from_parts, ctilde_from_commitments);
    }
}
