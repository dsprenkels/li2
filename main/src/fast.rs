use crate::params::*;
use crate::{keccak, packing, poly};
use digest::{ExtendableOutput, Update, XofReader};

#[cfg(feature = "rand")]
pub fn dilithium2_keygen<R>(sk: &mut [u8], pk: &mut [u8], rng: &mut R) -> Result<(), crate::Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    const P: DilithiumParams = DILITHIUM2;
    dilithium_keygen::<{ P.k }, { P.l }, { P.k * P.l }, _>(&P, sk, pk, rng)
}

#[cfg(feature = "rand")]
pub fn dilithium3_keygen<R>(sk: &mut [u8], pk: &mut [u8], rng: &mut R) -> Result<(), crate::Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    const P: DilithiumParams = DILITHIUM3;
    dilithium_keygen::<{ P.k }, { P.l }, { P.k * P.l }, _>(&P, sk, pk, rng)
}

#[cfg(feature = "rand")]
pub fn dilithium5_keygen<R>(sk: &mut [u8], pk: &mut [u8], rng: &mut R) -> Result<(), crate::Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    const P: DilithiumParams = DILITHIUM5;
    dilithium_keygen::<{ P.k }, { P.l }, { P.k * P.l }, _>(&P, sk, pk, rng)
}

#[cfg(feature = "rand")]
fn dilithium_keygen<const K: usize, const L: usize, const KL: usize, R>(
    p: &'static DilithiumParams,
    sk: &mut [u8],
    pk: &mut [u8],
    rng: &mut R,
) -> Result<(), crate::Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    let mut seed = [0; SEEDBYTES];
    rng.fill_bytes(&mut seed);
    dilithium_keygen_from_seed::<K, L, KL>(p, sk, pk, &mut seed)
}

pub fn dilithium2_keygen_from_seed(
    sk: &mut [u8],
    pk: &mut [u8],
    seed: &[u8],
) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM2;
    dilithium_keygen_from_seed::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, pk, seed)
}

pub fn dilithium3_keygen_from_seed(
    sk: &mut [u8],
    pk: &mut [u8],
    seed: &[u8],
) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM3;
    dilithium_keygen_from_seed::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, pk, seed)
}

pub fn dilithium5_keygen_from_seed(
    sk: &mut [u8],
    pk: &mut [u8],
    seed: &[u8],
) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM5;
    dilithium_keygen_from_seed::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, pk, seed)
}

fn dilithium_keygen_from_seed<const K: usize, const L: usize, const KL: usize>(
    p: &'static DilithiumParams,
    sk: &mut [u8],
    pk: &mut [u8],
    seed: &[u8],
) -> Result<(), crate::Error> {
    debug_assert_eq!(KL, K * L);
    debug_assert_eq!(seed.len(), SEEDBYTES);

    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut tr = [0u8; CRHBYTES];
    let mut mat = [poly::Poly::zero(); KL];
    let mut s1 = [poly::Poly::zero(); L];
    let mut s2 = [poly::Poly::zero(); K];
    let mut t0 = [poly::Poly::zero(); K];
    let mut t1 = [poly::Poly::zero(); K];
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
    poly::polyvec_matrix_pointwise_montgomery(p, &mut t1, &mat, &*&mut s1hat);
    poly::polyvec_pointwise(&mut t1, crate::reduce::reduce32);
    crate::ntt::polyvec_invntt_tomont(&mut t1);

    // Add error vector s2
    poly::polyvec_add(&mut t1, &*&mut s2);

    // Extract t1 and write public key
    poly::polyvec_pointwise(&mut t1, crate::reduce::caddq);
    for (t0_elem, t1_elem) in &mut t0.iter_mut().zip(&mut t1.iter_mut()) {
        for (t0_coeff, t1_coeff) in t0_elem.coeffs.iter_mut().zip(t1_elem.coeffs.iter_mut()) {
            (*t0_coeff, *t1_coeff) = crate::rounding::power2round(*t1_coeff);
        }
    }
    packing::pack_pk(p, pk, rho, &t1);

    // Compute H(rho, t1) and write secret key
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(pk);
    xof.finalize_xof().read(&mut tr);

    packing::pack_sk(p, sk, rho, &tr, key, &mut t0, &mut s1, &mut s2);
    Ok(())
}

pub fn dilithium2_signature(sk: &[u8], m: &[u8], sig: &mut [u8]) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM2;
    dilithium_signature::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, m, &[0; SEEDBYTES], sig)?;
    Ok(())
}

pub fn dilithium3_signature(sk: &[u8], m: &[u8], sig: &mut [u8]) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM3;
    dilithium_signature::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, m, &[0; SEEDBYTES], sig)?;
    Ok(())
}

pub fn dilithium5_signature(sk: &[u8], m: &[u8], sig: &mut [u8]) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM5;
    dilithium_signature::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, m, &[0; SEEDBYTES], sig)?;
    Ok(())
}

#[cfg(feature = "rand")]
pub fn dilithium2_signature_randomized<R>(
    sk: &[u8],
    m: &[u8],
    sig: &mut [u8],
    rng: &mut R,
) -> Result<(), crate::Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    const P: DilithiumParams = DILITHIUM2;
    let mut rnd = [0; SEEDBYTES];
    rng.fill_bytes(&mut rnd);
    dilithium_signature::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, m, &rnd, sig)?;
    Ok(())
}

#[cfg(feature = "rand")]
pub fn dilithium3_signature_randomized<R>(
    sk: &[u8],
    m: &[u8],
    sig: &mut [u8],
    rng: &mut R,
) -> Result<(), crate::Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    const P: DilithiumParams = DILITHIUM3;
    let mut rnd = [0; SEEDBYTES];
    rng.fill_bytes(&mut rnd);
    dilithium_signature::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, m, &rnd, sig)?;
    Ok(())
}

#[cfg(feature = "rand")]
pub fn dilithium5_signature_randomized<R>(
    sk: &[u8],
    m: &[u8],
    sig: &mut [u8],
    rng: &mut R,
) -> Result<(), crate::Error>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    const P: DilithiumParams = DILITHIUM5;
    let mut rnd = [0; SEEDBYTES];
    rng.fill_bytes(&mut rnd);
    dilithium_signature::<{ P.k }, { P.l }, { P.k * P.l }>(&P, sk, m, &rnd, sig)?;
    Ok(())
}

fn dilithium_signature<const K: usize, const L: usize, const KL: usize>(
    p: &'static DilithiumParams,
    sk: &[u8],
    m: &[u8],
    rnd: &[u8],
    sigbytes: &mut [u8],
) -> Result<(), crate::Error> {
    debug_assert_eq!(KL, K * L);
    debug_assert_eq!(rnd.len(), SEEDBYTES);

    let mut nonce = 0u16;
    let mut seedbuf = [0u8; 2 * SEEDBYTES + 3 * CRHBYTES];
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

    let (rho, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
    let (tr, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
    let (key, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
    let (mu, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
    let (rhoprime, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
    debug_assert_eq!(seedbuf, &[]);
    packing::unpack_sk(p, rho, tr, key, &mut t0, &mut s1, &mut s2, sk);

    // Compute mu := CRH(tr || msg)
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(tr);
    xof.update(m);
    xof.finalize_xof().read(mu);

    // Compute rhoprime := CRH(K || mu)
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(key);
    xof.update(rnd);
    xof.update(mu);
    xof.finalize_xof().read(rhoprime);

    // Expand matrix and transform vectors
    crate::expanda::polyvec_matrix_expand(p, &mut keccak, &mut mat, rho);
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
        crate::expandmask::polyvecl_uniform_gamma1(p, &mut y, rhoprime, nonce, &mut keccak);
        nonce += 1;

        // Matrix-vector multiplication
        let mut z = y;
        crate::ntt::polyvec_ntt(&mut z);
        poly::polyvec_matrix_pointwise_montgomery(p, &mut w1, &mat, &z);
        poly::polyvec_pointwise(&mut w1, crate::reduce::reduce32);
        crate::ntt::polyvec_invntt_tomont(&mut w1);

        // Decompose w and call the random oracle
        poly::polyvec_pointwise(&mut w1, crate::reduce::caddq);
        poly::polyveck_decompose(p, &mut w1, &mut w0);
        packing::pack_polyvec_w1(p, &mut sigbytes[0..p.k * p.w1_poly_packed_len], &w1);

        // Compute challenge
        let mut xof = keccak::SHAKE256::new(&mut keccak);
        xof.update(mu);
        let w1_packed = &&mut sigbytes[0..p.k * p.w1_poly_packed_len];
        xof.update(w1_packed);
        let ctilde = &mut &mut sigbytes[..SEEDBYTES];
        xof.finalize_xof().read(ctilde);
        crate::challenge::sample_in_ball(p, &mut cp, &sigbytes[0..SEEDBYTES], &mut keccak);
        crate::ntt::poly_ntt(&mut cp);

        // Compute z, reject if it reveals secret
        poly::polyvec_pointwise_montgomery(&mut z, &cp, &s1);
        crate::ntt::polyvec_invntt_tomont(&mut z);
        poly::polyvec_add(&mut z, &y);
        poly::polyvec_pointwise(&mut z, crate::reduce::reduce32);
        if poly::polyvec_chknorm(&z, p.gamma1 - p.beta).is_err() {
            continue 'rej;
        }

        // Check that subtracting cs2 does not change high bits of w and
        // low bits do not reveal secret information
        poly::polyvec_pointwise_montgomery(&mut h, &cp, &s2);
        crate::ntt::polyvec_invntt_tomont(&mut h);
        poly::polyvec_sub(&mut w0, &h);
        poly::polyvec_pointwise(&mut w0, crate::reduce::reduce32);
        if poly::polyvec_chknorm(&w0, p.gamma2 - p.beta).is_err() {
            continue 'rej;
        }

        // Compute hints for w1
        poly::polyvec_pointwise_montgomery(&mut h, &cp, &t0);
        crate::ntt::polyvec_invntt_tomont(&mut h);
        poly::polyvec_pointwise(&mut h, crate::reduce::reduce32);
        if poly::polyvec_chknorm(&h, p.gamma2).is_err() {
            continue 'rej;
        }
        poly::polyvec_add(&mut w0, &h);
        let hints_popcount = poly::polyvec_make_hint(p, &mut w0, &w1);
        if hints_popcount > p.omega {
            continue 'rej;
        }

        // Write signature
        let mut tmp = [0; SEEDBYTES];
        tmp.copy_from_slice(&sigbytes[0..SEEDBYTES]);
        packing::pack_sig(p, sigbytes, &tmp, &z, &w0);
        break 'rej;
    }
    Ok(())
}

pub fn dilithium2_verify(pk: &[u8], m: &[u8], sig: &[u8]) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM2;
    dilithium_verify::<{ P.k }, { P.l }, { P.k * P.l }, { P.k * P.w1_poly_packed_len }>(
        &P, pk, m, sig,
    )
}

pub fn dilithium3_verify(pk: &[u8], m: &[u8], sig: &[u8]) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM3;
    dilithium_verify::<{ P.k }, { P.l }, { P.k * P.l }, { P.k * P.w1_poly_packed_len }>(
        &P, pk, m, sig,
    )
}

pub fn dilithium5_verify(pk: &[u8], m: &[u8], sig: &[u8]) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM5;
    dilithium_verify::<{ P.k }, { P.l }, { P.k * P.l }, { P.k * P.w1_poly_packed_len }>(
        &P, pk, m, sig,
    )
}

fn dilithium_verify<
    const K: usize,
    const L: usize,
    const KL: usize,
    const KW1POLYPACKEDLEN: usize,
>(
    p: &'static DilithiumParams,
    pk_bytes: &[u8],
    m: &[u8],
    sig_bytes: &[u8],
) -> Result<(), crate::Error> {
    debug_assert_eq!(KL, K * L);

    let mut buf = [0; KW1POLYPACKEDLEN];
    let mut rho = [0; SEEDBYTES];
    let mut mu = [0; CRHBYTES];
    let mut tr = [0; CRHBYTES];
    let mut c = [0; SEEDBYTES];
    let mut c2 = [0; SEEDBYTES];
    let mut cp = poly::Poly::zero();
    let mut mat: [poly::Poly; KL] = [poly::Poly::zero(); KL];
    let mut z = [poly::Poly::zero(); L];
    let mut t1 = [poly::Poly::zero(); K];
    let mut w1 = [poly::Poly::zero(); K];
    let mut h = [poly::Poly::zero(); K];
    let mut keccak = keccak::KeccakState::default();

    packing::unpack_pk(p, &mut rho, &mut t1, pk_bytes);
    packing::unpack_sig(p, &mut c, &mut z, &mut h, sig_bytes)?;
    poly::polyvec_chknorm(&z, p.gamma1 - p.beta).map_err(|()| crate::Error::default())?;

    // Compute tr := H(pk)
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(pk_bytes);
    xof.finalize_xof().read(&mut tr);

    // Compute mu := CRH(tr, msg)
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(&tr);
    xof.update(m);
    xof.finalize_xof().read(&mut mu);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    crate::challenge::sample_in_ball(p, &mut cp, &c, &mut keccak);
    crate::expanda::polyvec_matrix_expand(p, &mut keccak, &mut mat, &rho);

    crate::ntt::polyvec_ntt(&mut z);
    poly::polyvec_matrix_pointwise_montgomery(p, &mut w1, &mat, &z);

    crate::ntt::poly_ntt(&mut cp);
    poly::polyvec_pointwise(&mut t1, |x| x << D);
    crate::ntt::polyvec_ntt(&mut t1);
    poly::polyvec_pointwise_montgomery_inplace(&mut t1, &*&mut cp);
    poly::polyvec_sub(&mut w1, &*&mut t1);
    poly::polyvec_pointwise(&mut w1, crate::reduce::reduce32);
    crate::ntt::polyvec_invntt_tomont(&mut w1);

    // Reconstruct w1
    poly::polyvec_pointwise(&mut w1, crate::reduce::caddq);
    poly::polyvec_use_hint(p, &mut w1, &*&mut h);
    packing::pack_polyvec_w1(p, &mut buf, &*&mut w1);

    // Call random oracle and verify challenge
    let mut xof = keccak::SHAKE256::new(&mut keccak);
    xof.update(&mu);
    xof.update(&buf);
    xof.finalize_xof().read(&mut c2);
    if c == c2 {
        return Ok(());
    }
    Err(crate::Error::default())
}

#[cfg(test)]
mod tests {
    #![deny(_old_code)]

    extern crate std;

    use super::*;
    use signature::{Signer, Verifier};

    #[test]
    #[ignore = "todo"]
    fn test_keygen_from_seed() {
        todo!()
        // TODO: Check whether t0 + t1 << D == t
        // TODO: Check whether A*s1 + s2 == t
    }

    #[test]
    #[ignore = "CRYSTALS-Dilithium repo is outdated"]
    fn test_empty_message() {
        let seed = [0; SEEDBYTES];
        let mut sk = [0; DILITHIUM3.secret_key_len];
        let mut pk = [0; DILITHIUM3.public_key_len];
        let mut sig = [0; DILITHIUM3.signature_len];

        dilithium3_keygen_from_seed(&mut sk, &mut pk, &seed).expect("keygen");

        let sigbytes_expected = unsafe {
            let mut sig = [0; DILITHIUM3.signature_len];
            let mut siglen = 0;
            crystals_dilithium_sys::dilithium3::pqcrystals_dilithium3_ref_signature(
                sig.as_mut_ptr(),
                &mut siglen,
                [].as_ptr(),
                0,
                sk.as_ptr(),
            );
            assert_eq!(siglen, DILITHIUM3.signature_len, "siglen mismatch");
            sig
        };

        dilithium3_signature(&sk, &[], &mut sig).expect("signature");

        assert_eq!(&sig[..], &sigbytes_expected[..], "signature mismatch");

        let verified = dilithium3_verify(&pk, &[], &sig);
        assert!(verified.is_ok())
    }

    #[test]
    #[cfg(feature = "rand")]
    fn test_dilithium2_randomized_signatures_different() {
        const p: DilithiumParams = DILITHIUM2;
        do_test_randomized_signatures_different::<{p.k}, {p.l}, {p.k * p.l}, {p.k * p.w1_poly_packed_len}>(&p);
    }

    #[test]
    #[cfg(feature = "rand")]
    fn test_dilithium3_randomized_signatures_different() {
        const p: DilithiumParams = DILITHIUM3;
        do_test_randomized_signatures_different::<{p.k}, {p.l}, {p.k * p.l}, {p.k * p.w1_poly_packed_len}>(&p);
    }

    #[test]
    #[cfg(feature = "rand")]
    fn test_dilithium5_randomized_signatures_different() {
        const p: DilithiumParams = DILITHIUM5;
        do_test_randomized_signatures_different::<{p.k}, {p.l}, {p.k * p.l}, {p.k * p.w1_poly_packed_len}>(&p);
    }

    #[cfg(feature = "rand")]
    fn do_test_randomized_signatures_different<const K:  usize, const L:  usize, const KL:  usize, const KW1POLYPACKEDLEN: usize>(p: &'static DilithiumParams) {
        let seed = [0; SEEDBYTES];
        let mut sk = vec![0; p.secret_key_len];
        let mut pk = vec![0; p.public_key_len];
        let mut rnd = [0; SEEDBYTES];
        let mut sig = vec![0; p.signature_len];
        let mut sig2 = vec![0; p.signature_len];

        dilithium_keygen_from_seed::<K, L, KL>(p, &mut sk, &mut pk, &seed).expect("keygen");
        dilithium_signature::<K, L, KL>(p, &sk, &[], &rnd, &mut sig).expect("signature");
        rnd[0] += 1;
        dilithium_signature::<K, L, KL>(p, &sk, &[], &rnd, &mut sig2).expect("signature");

        assert!(dilithium_verify::<K, L, KL, KW1POLYPACKEDLEN>(p, &pk, &[], &sig).is_ok());
        assert!(dilithium_verify::<K, L, KL, KW1POLYPACKEDLEN>(p, &pk, &[], &sig2).is_ok());
        assert_ne!(sig, sig2);
    }
}
