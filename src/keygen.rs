use crate::{
    params::{CRHBYTES, DILTIHIUM3, SEEDBYTES},
    variants::{Dilithium3, DilithiumVariant, PublicKey, SecretKey, SEED_SIZE},
};
use crystals_dilithium_sys as refimpl;
use refimpl::dilithium3::*;

pub fn dilithium3_keygen_from_seed(
    seed: &[u8],
) -> Option<(
    SecretKey<{ Dilithium3::SECKEY_SIZE }>,
    PublicKey<{ Dilithium3::PUBKEY_SIZE }>,
)> {
    if seed.len() != SEED_SIZE {
        return None;
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
        let (rhoprime, key) = seedbuf.split_at_mut(CRHBYTES);

        // Expand matrix
        let mut mat: [polyvecl; DILTIHIUM3.k as usize] = Default::default();
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
            DILTIHIUM3.l,
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
    Some((SecretKey { bytes: sk }, PublicKey { bytes: pk }))
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_from_seed() {
        let seed = [0; 32];
        let (sk_actual, pk_actual) = dilithium3_keygen_from_seed(&seed).unwrap();

        // TODO: Check whether t0 + t1 << D == t
        // TODO: Check whether A*s1 + s2 == t
    }
}
