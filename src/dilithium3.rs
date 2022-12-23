use crate::{
    params::{DilithiumImpl, CRHBYTES, DILITHIUM3, SEEDBYTES},
    variants::{Dilithium3, DilithiumVariant, PublicKey, SecretKey, Signature, SEED_SIZE},
    Error,
};
use crystals_dilithium_sys as refimpl;
use refimpl::dilithium3::*;

struct KeygenMemoryPool<'a> {
    sk: &'a mut [u8],
    pk: &'a mut [u8],
    seedbuf: &'a mut [u8; 2 * SEEDBYTES + CRHBYTES],
    tr: &'a mut [u8; SEEDBYTES],
    mat: &'a mut [poly],
    s1: &'a mut [poly],
    s1hat: &'a mut [poly],
    s2: &'a mut [poly],
    t0: &'a mut [poly],
    t1: &'a mut [poly],
}

#[inline]
pub fn dilithium3_keygen_from_seed(
    seed: &[u8],
) -> Result<(SecretKey<Dilithium3>, PublicKey<Dilithium3>), crate::Error> {
    let mut sk = [0u8; Dilithium3::SECKEY_SIZE];
    let mut pk = [0u8; Dilithium3::PUBKEY_SIZE];
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut tr = [0u8; SEEDBYTES];
    let mut mat = <[poly; DILITHIUM3.k as usize * DILITHIUM3.l as usize]>::default();
    let mut s1 = <[poly; DILITHIUM3.l as usize]>::default();
    let mut s1hat = <[poly; DILITHIUM3.l as usize]>::default();
    let mut s2 = <[poly; DILITHIUM3.k as usize]>::default();
    let mut t = <[poly; DILITHIUM3.k as usize]>::default();
    let mut t0 = <[poly; DILITHIUM3.k as usize]>::default();
    let mut t1 = <[poly; DILITHIUM3.k as usize]>::default();

    const DI: DilithiumImpl = DILITHIUM3;
    let mem = KeygenMemoryPool {
        sk: &mut sk,
        pk: &mut pk,
        seedbuf: &mut seedbuf,
        tr: &mut tr,
        mat: &mut mat,
        s1: &mut s1,
        s1hat: &mut s1hat,
        s2: &mut s2,
        t0: &mut t0,
        t1: &mut t1,
    };
    dilithium_keygen_from_seed(&DI, mem, seed)?;
    Ok((SecretKey { bytes: sk }, PublicKey { bytes: pk }))
}

fn dilithium_keygen_from_seed(
    di: &'static DilithiumImpl,
    mem: KeygenMemoryPool<'_>,
    seed: &[u8],
) -> Result<(), crate::Error> {
    debug_assert_eq!(seed.len(), SEEDBYTES);

    unsafe {
        let mat_ptr: *mut polyvecl = core::mem::transmute(mem.mat.as_mut_ptr());
        let s1_ptr: *mut polyvecl = core::mem::transmute(mem.s1.as_mut_ptr());
        let s1hat_ptr: *mut polyvecl = core::mem::transmute(mem.s1hat.as_mut_ptr());
        let s2_ptr: *mut polyveck = core::mem::transmute(mem.s2.as_mut_ptr());
        let t1_ptr: *mut polyveck = core::mem::transmute(mem.t1.as_mut_ptr());
        let t0_ptr: *mut polyveck = core::mem::transmute(mem.t0.as_mut_ptr());

        mem.seedbuf[0..SEEDBYTES].copy_from_slice(seed);
        pqcrystals_dilithium_fips202_ref_shake256(
            mem.seedbuf.as_mut_ptr(),
            mem.seedbuf.len(),
            mem.seedbuf.as_ptr(),
            SEEDBYTES,
        );

        let (rho, seedbuf) = mem.seedbuf.split_at_mut(SEEDBYTES);
        let (rhoprime, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
        let (key, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
        debug_assert_eq!(seedbuf, &[]);

        // Expand matrix
        pqcrystals_dilithium3_ref_polyvec_matrix_expand(mat_ptr, rho.as_ptr());

        // Sample short vectors s1 and s2
        // TODO: Uniform sampling must be specified for variants!
        pqcrystals_dilithium3_ref_polyvecl_uniform_eta(s1_ptr, rhoprime.as_ptr(), 0);
        pqcrystals_dilithium3_ref_polyveck_uniform_eta(s2_ptr, rhoprime.as_mut_ptr(), di.l);

        // Matrix-vector multiplication
        s1hat_ptr.copy_from_nonoverlapping(s1_ptr, 1);
        pqcrystals_dilithium3_ref_polyvecl_ntt(s1hat_ptr);
        pqcrystals_dilithium3_ref_polyvec_matrix_pointwise_montgomery(t1_ptr, mat_ptr, s1hat_ptr);
        pqcrystals_dilithium3_ref_polyveck_reduce(t1_ptr);
        pqcrystals_dilithium3_ref_polyveck_invntt_tomont(t1_ptr);

        // Add error vector s2
        pqcrystals_dilithium3_ref_polyveck_add(t1_ptr, t1_ptr, s2_ptr);

        // Extract t1 and write public key
        pqcrystals_dilithium3_ref_polyveck_caddq(t1_ptr);
        pqcrystals_dilithium3_ref_polyveck_power2round(t1_ptr, t0_ptr, t1_ptr);
        pqcrystals_dilithium3_ref_pack_pk(mem.pk.as_mut_ptr(), rho.as_ptr(), t1_ptr);

        // Compute H(rho, t1) and write secret key
        pqcrystals_dilithium_fips202_ref_shake256(
            mem.tr.as_mut_ptr(),
            SEEDBYTES,
            mem.pk.as_mut_ptr(),
            mem.pk.len(),
        );
        pqcrystals_dilithium3_ref_pack_sk(
            mem.sk.as_mut_ptr(),
            rho.as_ptr(),
            mem.tr.as_ptr(),
            key.as_ptr(),
            t0_ptr,
            s1_ptr,
            s2_ptr,
        );
    }
    Ok(())
}

#[derive(Debug)]
struct SignMemoryPool<'a> {
    sigbytes: &'a mut [u8],
    seedbuf: &'a mut [u8],
    mat: &'a mut [poly],
    s1: &'a mut [poly],
    y: &'a mut [poly],
    z: &'a mut [poly],
    t0: &'a mut [poly],
    s2: &'a mut [poly],
    w1: &'a mut [poly],
    w0: &'a mut [poly],
    h: &'a mut [poly],
    cp: &'a mut poly,
    state: &'a mut keccak_state,
}

pub fn dilithium3_signature(
    sk: &SecretKey<Dilithium3>,
    m: &[u8],
) -> Result<Signature<Dilithium3>, crate::Error> {
    let mut sigbytes = [0; Dilithium3::SIG_SIZE];
    let mut seedbuf = [0u8; 3 * SEEDBYTES + 2 * CRHBYTES];
    let mut mat = <[poly; DILITHIUM3.k as usize * DILITHIUM3.l as usize]>::default();
    let mut s1 = <[poly; DILITHIUM3.l as usize]>::default();
    let mut y = <[poly; DILITHIUM3.l as usize]>::default();
    let mut z = <[poly; DILITHIUM3.l as usize]>::default();
    let mut t0 = <[poly; DILITHIUM3.k as usize]>::default();
    let mut s2 = <[poly; DILITHIUM3.k as usize]>::default();
    let mut w1 = <[poly; DILITHIUM3.k as usize]>::default();
    let mut w0 = <[poly; DILITHIUM3.k as usize]>::default();
    let mut h = <[poly; DILITHIUM3.k as usize]>::default();
    let mut cp = poly::default();
    let mut state = keccak_state::default();

    const DI: DilithiumImpl = DILITHIUM3;
    let mem = SignMemoryPool {
        sigbytes: &mut sigbytes[..],
        seedbuf: &mut seedbuf[..],
        mat: &mut mat[..],
        s1: &mut s1[..],
        y: &mut y[..],
        z: &mut z[..],
        t0: &mut t0[..],
        s2: &mut s2[..],
        w1: &mut w1[..],
        w0: &mut w0[..],
        h: &mut h[..],
        cp: &mut cp,
        state: &mut state,
    };

    dilithium_signature(&DI, mem, sk, m)?;
    Ok(Signature { bytes: sigbytes })
}

fn dilithium_signature(
    di: &'static DilithiumImpl,
    mut mem: SignMemoryPool<'_>,
    sk: &SecretKey<Dilithium3>,
    m: &[u8],
) -> Result<(), crate::Error> {
    let mut nonce = 0u16;

    unsafe {
        let mat_ptr: *mut polyvecl = core::mem::transmute(mem.mat.as_mut_ptr());
        let s1_ptr: *mut polyvecl = core::mem::transmute(mem.s1.as_mut_ptr());
        let y_ptr: *mut polyvecl = core::mem::transmute(mem.y.as_mut_ptr());
        let z_ptr: *mut polyvecl = core::mem::transmute(mem.z.as_mut_ptr());
        let t0_ptr: *mut polyveck = core::mem::transmute(mem.t0.as_mut_ptr());
        let s2_ptr: *mut polyveck = core::mem::transmute(mem.s2.as_mut_ptr());
        let w1_ptr: *mut polyveck = core::mem::transmute(mem.w1.as_mut_ptr());
        let w0_ptr: *mut polyveck = core::mem::transmute(mem.w0.as_mut_ptr());
        let h_ptr: *mut polyveck = core::mem::transmute(mem.h.as_mut_ptr());

        let seedbuf = &mut mem.seedbuf;
        let (rho, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
        let (tr, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
        let (key, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
        let (mu, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
        let (rhoprime, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
        debug_assert_eq!(seedbuf, &[]);
        pqcrystals_dilithium3_ref_unpack_sk(
            rho.as_mut_ptr(),
            tr.as_mut_ptr(),
            key.as_mut_ptr(),
            t0_ptr,
            s1_ptr,
            s2_ptr,
            sk.bytes.as_ptr(),
        );

        // Compute mu := CRH(tr || msg)
        pqcrystals_dilithium_fips202_ref_shake256_init(mem.state);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(mem.state, tr.as_ptr(), SEEDBYTES);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(mem.state, m.as_ptr(), m.len());
        pqcrystals_dilithium_fips202_ref_shake256_finalize(mem.state);
        pqcrystals_dilithium_fips202_ref_shake256_squeeze(mu.as_mut_ptr(), CRHBYTES, mem.state);

        // Compute rhoprime := CRH(K || mu)
        pqcrystals_dilithium_fips202_ref_shake256_init(mem.state);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(mem.state, key.as_ptr(), SEEDBYTES);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(mem.state, mu.as_ptr(), CRHBYTES);
        pqcrystals_dilithium_fips202_ref_shake256_finalize(mem.state);
        pqcrystals_dilithium_fips202_ref_shake256_squeeze(
            rhoprime.as_mut_ptr(),
            CRHBYTES,
            mem.state,
        );

        // Expand matrix and transform vectors
        pqcrystals_dilithium3_ref_polyvec_matrix_expand(mat_ptr, rho.as_ptr());
        pqcrystals_dilithium3_ref_polyvecl_ntt(s1_ptr);
        pqcrystals_dilithium3_ref_polyveck_ntt(s2_ptr);
        pqcrystals_dilithium3_ref_polyveck_ntt(t0_ptr);

        'rej: loop {
            // Sample intermediate vector y
            pqcrystals_dilithium3_ref_polyvecl_uniform_gamma1(y_ptr, rhoprime.as_ptr(), nonce);
            nonce += 1;

            // Matrix-vector multiplication
            z_ptr.copy_from_nonoverlapping(y_ptr, 1);
            pqcrystals_dilithium3_ref_polyvecl_ntt(z_ptr);
            pqcrystals_dilithium3_ref_polyvec_matrix_pointwise_montgomery(w1_ptr, mat_ptr, z_ptr);
            pqcrystals_dilithium3_ref_polyveck_reduce(w1_ptr);
            pqcrystals_dilithium3_ref_polyveck_invntt_tomont(w1_ptr);

            // Decompose w and call the random oracle
            pqcrystals_dilithium3_ref_polyveck_caddq(w1_ptr);
            pqcrystals_dilithium3_ref_polyveck_decompose(w1_ptr, w0_ptr, w1_ptr);
            pqcrystals_dilithium3_ref_polyveck_pack_w1(mem.sigbytes.as_mut_ptr(), w1_ptr);

            // Compute challenge
            pqcrystals_dilithium_fips202_ref_shake256_init(mem.state);
            pqcrystals_dilithium_fips202_ref_shake256_absorb(mem.state, mu.as_ptr(), CRHBYTES);
            pqcrystals_dilithium_fips202_ref_shake256_absorb(
                mem.state,
                mem.sigbytes.as_ptr(),
                DILITHIUM3.k as usize * POLYW1_PACKEDBYTES as usize,
            );
            pqcrystals_dilithium_fips202_ref_shake256_finalize(mem.state);
            pqcrystals_dilithium_fips202_ref_shake256_squeeze(
                mem.sigbytes.as_mut_ptr(),
                SEEDBYTES,
                mem.state,
            );
            pqcrystals_dilithium3_ref_poly_challenge(mem.cp, mem.sigbytes.as_ptr());
            pqcrystals_dilithium3_ref_poly_ntt(mem.cp);

            // Compute z, reject if it reveals secret
            pqcrystals_dilithium3_ref_polyvecl_pointwise_poly_montgomery(z_ptr, mem.cp, s1_ptr);
            pqcrystals_dilithium3_ref_polyvecl_invntt_tomont(z_ptr);
            pqcrystals_dilithium3_ref_polyvecl_add(z_ptr, z_ptr, y_ptr);
            pqcrystals_dilithium3_ref_polyvecl_reduce(z_ptr);
            if 0 != pqcrystals_dilithium3_ref_polyvecl_chknorm(z_ptr, (GAMMA1 - BETA) as i32) {
                continue 'rej;
            }

            // Check that subtracting cs2 does not change high bits of w and
            // low bits do not reveal secret information
            pqcrystals_dilithium3_ref_polyveck_pointwise_poly_montgomery(h_ptr, mem.cp, s2_ptr);
            pqcrystals_dilithium3_ref_polyveck_invntt_tomont(h_ptr);
            pqcrystals_dilithium3_ref_polyveck_sub(w0_ptr, w0_ptr, h_ptr);
            pqcrystals_dilithium3_ref_polyveck_reduce(w0_ptr);
            if 0 != pqcrystals_dilithium3_ref_polyveck_chknorm(w0_ptr, (GAMMA2 - BETA) as i32) {
                continue 'rej;
            }

            // Compute hints for w1
            pqcrystals_dilithium3_ref_polyveck_pointwise_poly_montgomery(h_ptr, mem.cp, t0_ptr);
            pqcrystals_dilithium3_ref_polyveck_invntt_tomont(h_ptr);
            pqcrystals_dilithium3_ref_polyveck_reduce(h_ptr);
            if 0 != pqcrystals_dilithium3_ref_polyveck_chknorm(h_ptr, GAMMA2 as i32) {
                continue 'rej;
            }
            pqcrystals_dilithium3_ref_polyveck_add(w0_ptr, w0_ptr, h_ptr);
            let n = pqcrystals_dilithium3_ref_polyveck_make_hint(h_ptr, w0_ptr, w1_ptr);
            if n > OMEGA {
                continue 'rej;
            }

            // Write signature
            pqcrystals_dilithium3_ref_pack_sig(
                mem.sigbytes.as_mut_ptr(),
                mem.sigbytes.as_ptr(),
                z_ptr,
                h_ptr,
            );
            break 'rej;
        }
    }
    Ok(())
}

pub fn dilithium3_verify(
    pk: &PublicKey<Dilithium3>,
    m: &[u8],
    sig: &Signature<Dilithium3>,
) -> Result<(), Error> {
    unsafe {
        let mut buf = [0; K as usize * POLYW1_PACKEDBYTES as usize];
        let mut rho = [0; SEEDBYTES];
        let mut mu = [0; CRHBYTES];
        let mut c = [0; SEEDBYTES];
        let mut c2 = [0; SEEDBYTES];
        let mut cp = poly::default();
        let mut mat = <[polyvecl; DILITHIUM3.k as usize]>::default();
        let mut z = polyvecl::default();
        let mut t1 = polyveck::default();
        let mut w1 = polyveck::default();
        let mut h = polyveck::default();
        let mut state = keccak_state::default();

        pqcrystals_dilithium3_ref_unpack_pk(rho.as_mut_ptr(), &mut t1, pk.bytes.as_ptr());
        if 0 != pqcrystals_dilithium3_ref_unpack_sig(
            c.as_mut_ptr(),
            &mut z,
            &mut h,
            sig.bytes.as_ptr(),
        ) {
            return Err(Error::InvalidSignature);
        }
        if 0 != pqcrystals_dilithium3_ref_polyvecl_chknorm(&z, (GAMMA1 - BETA) as i32) {
            return Err(Error::InvalidSignature);
        }

        // Compute tr := H(pk)
        pqcrystals_dilithium_fips202_ref_shake256_init(&mut state);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(
            &mut state,
            pk.bytes.as_ptr(),
            CRYPTO_PUBLICKEYBYTES as usize,
        );
        pqcrystals_dilithium_fips202_ref_shake256_finalize(&mut state);
        pqcrystals_dilithium_fips202_ref_shake256_squeeze(mu.as_mut_ptr(), SEEDBYTES, &mut state);

        // Compute mu := CRH(tr, msg)
        pqcrystals_dilithium_fips202_ref_shake256_init(&mut state);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(&mut state, mu.as_ptr(), SEEDBYTES);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(&mut state, m.as_ptr(), m.len());
        pqcrystals_dilithium_fips202_ref_shake256_finalize(&mut state);
        pqcrystals_dilithium_fips202_ref_shake256_squeeze(mu.as_mut_ptr(), CRHBYTES, &mut state);

        /* Matrix-vector multiplication; compute Az - c2^dt1 */
        pqcrystals_dilithium3_ref_poly_challenge(&mut cp, c.as_ptr());
        pqcrystals_dilithium3_ref_polyvec_matrix_expand(mat.as_mut_ptr(), rho.as_ptr());

        pqcrystals_dilithium3_ref_polyvecl_ntt(&mut z);
        pqcrystals_dilithium3_ref_polyvec_matrix_pointwise_montgomery(&mut w1, mat.as_ptr(), &z);

        pqcrystals_dilithium3_ref_poly_ntt(&mut cp);
        pqcrystals_dilithium3_ref_polyveck_shiftl(&mut t1);
        pqcrystals_dilithium3_ref_polyveck_ntt(&mut t1);
        pqcrystals_dilithium3_ref_polyveck_pointwise_poly_montgomery(&mut t1, &cp, &t1);

        pqcrystals_dilithium3_ref_polyveck_sub(&mut w1, &w1, &t1);
        pqcrystals_dilithium3_ref_polyveck_reduce(&mut w1);
        pqcrystals_dilithium3_ref_polyveck_invntt_tomont(&mut w1);

        // Reconstruct w1
        pqcrystals_dilithium3_ref_polyveck_caddq(&mut w1);
        pqcrystals_dilithium3_ref_polyveck_use_hint(&mut w1, &w1, &h);
        pqcrystals_dilithium3_ref_polyveck_pack_w1(buf.as_mut_ptr(), &w1);

        // Call random oracle and verify challenge
        pqcrystals_dilithium_fips202_ref_shake256_init(&mut state);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(&mut state, mu.as_ptr(), CRHBYTES);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(
            &mut state,
            buf.as_ptr(),
            K as usize * POLYW1_PACKEDBYTES as usize,
        );
        pqcrystals_dilithium_fips202_ref_shake256_finalize(&mut state);
        pqcrystals_dilithium_fips202_ref_shake256_squeeze(c2.as_mut_ptr(), SEEDBYTES, &mut state);
        if c == c2 {
            return Ok(());
        }
    }
    Err(crate::Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    #![deny(dead_code)]

    extern crate std;

    use core::ptr::null_mut;

    use super::*;
    use std::{dbg, prelude::*, println};

    #[test]
    fn test_refimpl_kat() {
        let mut seeds = [[0; 48]; 100];
        let mut msgs = [[0; 3300]; 100];

        let mut entropy_input = [0; 48];
        for (idx, b) in entropy_input.iter_mut().enumerate() {
            *b = idx as u8;
        }

        // Simulate generating the request KAT file
        unsafe {
            randombytes_init(entropy_input.as_mut_ptr(), null_mut(), 256);
        }
        for (idx, seed) in seeds.iter_mut().enumerate() {
            let mlen = 33 * (idx + 1);
            unsafe {
                randombytes(seed.as_mut_ptr(), seed.len() as u64);
                randombytes(msgs[idx].as_mut_ptr(), mlen as u64);
            }
        }

        // Simulate generating the response KAT file and verify
        for (idx, seed) in seeds.iter_mut().enumerate() {
            unsafe {
                let mlen = 33 * (idx + 1);
                let msg = &msgs[idx][0..mlen];
                let mut sk_expected = [0; CRYPTO_SECRETKEYBYTES as usize];
                let mut pk_expected = [0; CRYPTO_PUBLICKEYBYTES as usize];
                let mut sig_expected = [0; CRYPTO_BYTES as usize];
                let ref mut siglen = 0;

                // Generate the expected values
                randombytes_init(seed.as_mut_ptr(), null_mut(), 256);
                if 0 != pqcrystals_dilithium3_ref_keypair(
                    pk_expected.as_mut_ptr(),
                    sk_expected.as_mut_ptr(),
                ) {
                    panic!("KAT keypair failed");
                }
                if 0 != pqcrystals_dilithium3_ref_signature(
                    sig_expected.as_mut_ptr(),
                    siglen,
                    msg.as_ptr(),
                    mlen,
                    sk_expected.as_ptr(),
                ) {
                    panic!("KAT signature failed");
                }
                let verify_exptected = 0
                    == pqcrystals_dilithium3_ref_verify(
                        sig_expected.as_ptr(),
                        *siglen,
                        msg.as_ptr(),
                        mlen,
                        pk_expected.as_ptr(),
                    );
                assert_eq!(*siglen, CRYPTO_BYTES as usize);

                // Generate the actual values
                randombytes_init(seed.as_mut_ptr(), null_mut(), 256);
                let mut keygen_seed = [0; SEEDBYTES];
                randombytes(keygen_seed.as_mut_ptr(), SEEDBYTES as u64);
                let (sk_actual, pk_actual) = dilithium3_keygen_from_seed(&keygen_seed).unwrap();
                let sig_actual = dilithium3_signature(&sk_actual, msg).unwrap();
                let verify_actual = dilithium3_verify(&pk_actual, msg, &sig_actual);

                assert_eq!(sk_actual.bytes, sk_expected);
                assert_eq!(pk_actual.bytes, pk_expected);
                assert_eq!(sig_actual.bytes, sig_expected);
                assert_eq!(verify_actual.is_ok(), verify_exptected);
            }
        }
    }

    #[test]
    fn test_keygen_from_seed() {
        // TODO: LEFT HERE
        // Need to accurately test with the reference whether a generated key
        // is completely correct; first for Dilithium3 and then for Dilithium2
        // and Dilithium5

        let seed = [0; SEED_SIZE];
        let (sk_actual, pk_actual) = dilithium3_keygen_from_seed(&seed).unwrap();

        // TODO: Check whether t0 + t1 << D == t
        // TODO: Check whether A*s1 + s2 == t
    }

    #[test]
    fn test_empty_message() {
        let seed = [0; SEED_SIZE];
        let (sk, pk) = dilithium3_keygen_from_seed(&seed).unwrap();

        let sigbytes_expected = unsafe {
            let mut sig = [0; Dilithium3::SIG_SIZE];
            let mut siglen = 0;
            pqcrystals_dilithium3_ref_signature(
                sig.as_mut_ptr(),
                &mut siglen,
                [].as_ptr(),
                0,
                sk.bytes.as_ptr(),
            );
            assert_eq!(siglen, Dilithium3::SIG_SIZE, "siglen mismatch");
            sig
        };
        let sig_actual = dilithium3_signature(&sk, &[]).unwrap();
        let sigbytes_actual = sig_actual.bytes;

        assert_eq!(
            &sigbytes_actual[..],
            &sigbytes_expected[..],
            "signature mismatch"
        );

        let verified = dilithium3_verify(&pk, &[], &sig_actual);
        assert!(verified.is_ok())
    }
}
