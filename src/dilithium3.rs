use crate::{
    params::{CRHBYTES, DILITHIUM3, SEEDBYTES},
    variants::{Dilithium3, DilithiumVariant, PublicKey, SecretKey, Signature, SEED_SIZE},
};
use crystals_dilithium_sys as refimpl;
use refimpl::dilithium3::*;

pub fn dilithium3_keygen_from_seed(
    seed: &[u8],
) -> Result<(SecretKey<Dilithium3>, PublicKey<Dilithium3>), crate::Error> {
    if seed.len() != SEED_SIZE {
        return Err(crate::Error::InternalError);
    }

    let mut sk = [0u8; Dilithium3::SECKEY_SIZE];
    let mut pk = [0u8; Dilithium3::PUBKEY_SIZE];

    unsafe {
        let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
        let mut tr = [0u8; SEEDBYTES];

        seedbuf[0..SEEDBYTES].copy_from_slice(seed);
        pqcrystals_dilithium_fips202_ref_shake256(
            &mut seedbuf as *mut u8,
            seedbuf.len(),
            &seedbuf as *const u8,
            SEEDBYTES,
        );

        let (rho, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
        let (rhoprime, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
        let (key, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
        debug_assert_eq!(seedbuf, &[]);

        // Expand matrix
        let mut mat: [polyvecl; DILITHIUM3.k as usize] = Default::default();
        pqcrystals_dilithium3_ref_polyvec_matrix_expand(
            &mut mat as *mut polyvecl,
            rho as *mut _ as *const _,
        );

        // Sample short vectors s1 and s2
        let mut s1: polyvecl = Default::default();
        let mut s2: polyveck = Default::default();
        pqcrystals_dilithium3_ref_polyvecl_uniform_eta(
            &mut s1 as *mut polyvecl,
            rhoprime as *mut _ as *const _,
            0,
        );
        pqcrystals_dilithium3_ref_polyveck_uniform_eta(
            &mut s2 as *mut polyveck,
            rhoprime as *const _ as *mut _,
            DILITHIUM3.l,
        );

        // Matrix-vector multiplication
        let mut s1hat: polyvecl = s1;
        let mut t: polyveck = Default::default();
        pqcrystals_dilithium3_ref_polyvecl_ntt(&mut s1hat as *mut _);
        pqcrystals_dilithium3_ref_polyvec_matrix_pointwise_montgomery(
            &mut t as *mut _,
            &mat as *const _,
            &s1hat,
        );
        pqcrystals_dilithium3_ref_polyveck_reduce(&mut t as *mut _);
        pqcrystals_dilithium3_ref_polyveck_invntt_tomont(&mut t as *mut _);

        // Add error vector s2
        pqcrystals_dilithium3_ref_polyveck_add(&mut t, &t, &s2);

        // Extract t1 and write public key
        let mut t0: polyveck = Default::default();
        let mut t1: polyveck = Default::default();
        pqcrystals_dilithium3_ref_polyveck_caddq(&mut t);
        pqcrystals_dilithium3_ref_polyveck_power2round(&mut t1, &mut t0, &t);
        pqcrystals_dilithium3_ref_pack_pk(&mut pk as *mut _, rho as *mut _ as *const _, &t1);

        // Compute H(rho, t1) and write secret key
        pqcrystals_dilithium_fips202_ref_shake256(
            &mut tr as *mut _,
            SEEDBYTES,
            &mut pk as *mut _,
            pk.len(),
        );
        pqcrystals_dilithium3_ref_pack_sk(
            &mut sk as *mut _,
            rho as *mut _ as *const _,
            &tr as *const _,
            key as *mut _ as *const _,
            &t0,
            &s1,
            &s2,
        );
    }

    Ok((SecretKey { bytes: sk }, PublicKey { bytes: pk }))
}

pub fn dilithium3_signature(
    sk: SecretKey<Dilithium3>,
    m: &[u8],
) -> Result<Signature<Dilithium3>, crate::Error> {
    let mut sigbytes = [0; Dilithium3::SIG_SIZE];

    unsafe {
        let mut seedbuf = [0u8; 3 * SEEDBYTES + 2 * CRHBYTES];
        let mut nonce = 0u16;
        let mut mat: [polyvecl; DILITHIUM3.k as usize] = Default::default();
        let mut s1: polyvecl = Default::default();
        let mut y: polyvecl = Default::default();
        let mut z: polyvecl = Default::default();
        let mut t0: polyveck = Default::default();
        let mut s2: polyveck = Default::default();
        let mut w1: polyveck = Default::default();
        let mut w0: polyveck = Default::default();
        let mut h: polyveck = Default::default();
        let mut cp: poly = Default::default();
        let mut state: keccak_state = Default::default();

        let (rho, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
        let (tr, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
        let (key, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
        let (mu, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
        let (rhoprime, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
        debug_assert_eq!(seedbuf, &[]);
        pqcrystals_dilithium3_ref_unpack_sk(
            rho.as_mut_ptr() as *mut _,
            tr.as_mut_ptr() as *mut _,
            key.as_mut_ptr() as *mut _,
            &mut t0 as *mut _,
            &mut s1 as *mut _,
            &mut s2 as *mut _,
            sk.bytes.as_ptr(),
        );

        // Compute mu := CRH(tr || msg)
        pqcrystals_dilithium_fips202_ref_shake256_init(&mut state);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(&mut state, tr.as_ptr(), SEEDBYTES);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(&mut state, m.as_ptr(), m.len());
        pqcrystals_dilithium_fips202_ref_shake256_finalize(&mut state);
        pqcrystals_dilithium_fips202_ref_shake256_squeeze(mu.as_mut_ptr(), CRHBYTES, &mut state);

        // Compute rhoprime := CRH(K || mu)
        pqcrystals_dilithium_fips202_ref_shake256_init(&mut state);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(&mut state, key.as_ptr(), SEEDBYTES);
        pqcrystals_dilithium_fips202_ref_shake256_absorb(&mut state, mu.as_ptr(), CRHBYTES);
        pqcrystals_dilithium_fips202_ref_shake256_finalize(&mut state);
        pqcrystals_dilithium_fips202_ref_shake256_squeeze(
            rhoprime.as_mut_ptr(),
            CRHBYTES,
            &mut state,
        );

        // Expand matrix and transform vectors
        pqcrystals_dilithium3_ref_polyvec_matrix_expand(&mut mat as *mut _, rho.as_ptr());
        pqcrystals_dilithium3_ref_polyvecl_ntt(&mut s1);
        pqcrystals_dilithium3_ref_polyveck_ntt(&mut s2);
        pqcrystals_dilithium3_ref_polyveck_ntt(&mut t0);

        'rej: loop {
            // Sample intermediate vector y
            pqcrystals_dilithium3_ref_polyvecl_uniform_gamma1(&mut y, rhoprime.as_ptr(), nonce);
            nonce += 1;

            // Matrix-vector multiplication
            z = y;
            pqcrystals_dilithium3_ref_polyvecl_ntt(&mut z);
            pqcrystals_dilithium3_ref_polyvec_matrix_pointwise_montgomery(
                &mut w1,
                &mat as *const _,
                &z,
            );
            pqcrystals_dilithium3_ref_polyveck_reduce(&mut w1);
            pqcrystals_dilithium3_ref_polyveck_invntt_tomont(&mut w1);

            // Decompose w and call the random oracle
            pqcrystals_dilithium3_ref_polyveck_caddq(&mut w1);
            pqcrystals_dilithium3_ref_polyveck_decompose(&mut w1, &mut w0, &w1);
            pqcrystals_dilithium3_ref_polyveck_pack_w1(sigbytes.as_mut_ptr(), &w1);

            // Compute challenge
            pqcrystals_dilithium_fips202_ref_shake256_init(&mut state);
            pqcrystals_dilithium_fips202_ref_shake256_absorb(&mut state, mu.as_ptr(), CRHBYTES);
            pqcrystals_dilithium_fips202_ref_shake256_absorb(
                &mut state,
                sigbytes.as_ptr(),
                DILITHIUM3.k as usize * POLYW1_PACKEDBYTES as usize,
            );
            pqcrystals_dilithium_fips202_ref_shake256_finalize(&mut state);
            pqcrystals_dilithium_fips202_ref_shake256_squeeze(
                sigbytes.as_mut_ptr(),
                SEEDBYTES,
                &mut state,
            );
            pqcrystals_dilithium3_ref_poly_challenge(&mut cp, sigbytes.as_ptr());
            pqcrystals_dilithium3_ref_poly_ntt(&mut cp);

            // Compute z, reject if it reveals secret
            pqcrystals_dilithium3_ref_polyvecl_pointwise_poly_montgomery(&mut z, &cp, &s1);
            pqcrystals_dilithium3_ref_polyvecl_invntt_tomont(&mut z);
            pqcrystals_dilithium3_ref_polyvecl_add(&mut z, &z, &y);
            pqcrystals_dilithium3_ref_polyvecl_reduce(&mut z);
            if 0 != pqcrystals_dilithium3_ref_polyvecl_chknorm(&z, (GAMMA1 - BETA) as i32) {
                continue 'rej;
            }

            // Check that subtracting cs2 does not change high bits of w and
            // low bits do not reveal secret information
            pqcrystals_dilithium3_ref_polyveck_pointwise_poly_montgomery(&mut h, &cp, &s2);
            pqcrystals_dilithium3_ref_polyveck_invntt_tomont(&mut h);
            pqcrystals_dilithium3_ref_polyveck_sub(&mut w0, &w0, &h);
            pqcrystals_dilithium3_ref_polyveck_reduce(&mut w0);
            if 0 != pqcrystals_dilithium3_ref_polyveck_chknorm(&w0, (GAMMA2 - BETA) as i32) {
                continue 'rej;
            }

            // Compute hints for w1
            pqcrystals_dilithium3_ref_polyveck_pointwise_poly_montgomery(&mut h, &cp, &t0);
            pqcrystals_dilithium3_ref_polyveck_invntt_tomont(&mut h);
            pqcrystals_dilithium3_ref_polyveck_reduce(&mut h);
            if 0 != pqcrystals_dilithium3_ref_polyveck_chknorm(&h, GAMMA2 as i32) {
                continue 'rej;
            }
            pqcrystals_dilithium3_ref_polyveck_add(&mut w0, &w0, &h);
            let n = pqcrystals_dilithium3_ref_polyveck_make_hint(&mut h, &w0, &w1);
            if n > OMEGA {
                continue 'rej;
            }

            // Write signature
            pqcrystals_dilithium3_ref_pack_sig(sigbytes.as_mut_ptr(), sigbytes.as_ptr(), &z, &h);
            break 'rej;
        }
    }
    Ok(Signature { bytes: sigbytes })
}

#[cfg(test)]
mod tests {
    #![deny(dead_code)]

    use super::*;

    #[test]
    fn test_keygen_from_seed() {
        let seed = [0; SEED_SIZE];
        let (sk_actual, pk_actual) = dilithium3_keygen_from_seed(&seed).unwrap();

        // TODO: Check whether t0 + t1 << D == t
        // TODO: Check whether A*s1 + s2 == t
    }

    #[test]
    fn test_signature_empty_message() {
        let seed = [0; SEED_SIZE];
        let (sk, _) = dilithium3_keygen_from_seed(&seed).unwrap();

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
        let sigbytes_actual = dilithium3_signature(sk, &[]).unwrap().bytes;

        assert_eq!(
            &sigbytes_actual[..],
            &sigbytes_expected[..],
            "signature mismatch"
        );
    }
}
