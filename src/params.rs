use core::{marker::PhantomData, mem::transmute};

use crate::variants::DilithiumVariant;
use crystals_dilithium_sys::{dilithium2, dilithium3, dilithium5};

pub(crate) const N: usize = 256;
pub(crate) const SEEDBYTES: usize = 32;
pub(crate) const CRHBYTES: usize = 64;

pub trait DilithiumTypes {
    type Poly;
}

#[derive(Debug)]
pub struct GenericTypes;
#[derive(Debug)]
pub struct AVX2Types;
#[derive(Debug)]
pub struct LowMemoryTypes;

impl DilithiumTypes for GenericTypes {
    type Poly = [u32; N];
}

// TODO: impl DilithiumTypes for AVX2Types
// TODO: impl DilithiumTypes for LowMemoryTypes

pub(crate) struct DilithiumImpl {
    // Basic parameters
    pub(crate) k: u16,
    pub(crate) l: u16,
    pub(crate) max_attempts: u16,


    pub K: u32,
    pub L: u32,
    pub ETA: u32,
    pub TAU: u32,
    pub BETA: u32,
    pub GAMMA1: u32,
    pub GAMMA2: u32,
    pub OMEGA: u32,
    pub POLYT1_PACKEDBYTES: u32,
    pub POLYT0_PACKEDBYTES: u32,
    pub POLYVECH_PACKEDBYTES: u32,
    pub POLYZ_PACKEDBYTES: u32,
    pub POLYW1_PACKEDBYTES: u32,
    pub POLYETA_PACKEDBYTES: u32,
    pub CRYPTO_PUBLICKEYBYTES: u32,
    pub CRYPTO_SECRETKEYBYTES: u32,
    pub CRYPTO_BYTES: u32,
    
    // Impl-independent functions
    pub shake256_init: unsafe extern "C" fn(state: *mut dilithium3::keccak_state),
    pub shake256_absorb:
        unsafe extern "C" fn(state: *mut dilithium3::keccak_state, in_: *const u8, inlen: usize),
    pub shake256_finalize: unsafe extern "C" fn(state: *mut dilithium3::keccak_state),
    pub shake256_squeeze:
        unsafe extern "C" fn(out: *mut u8, outlen: usize, state: *mut dilithium3::keccak_state),

    // Impl-dependent functions
    pub poly_ntt: unsafe fn(v: *mut dilithium3::poly),
    pub polyvec_matrix_expand: unsafe fn(mat: *mut dilithium3::polyvecl, rho: *const u8),
    pub polyvec_matrix_pointwise_montgomery: unsafe fn(
        t: *mut dilithium3::polyveck,
        mat: *const dilithium3::polyvecl,
        v: *const dilithium3::polyvecl,
    ),
    pub polyveck_add: unsafe fn(
        w: *mut dilithium3::polyveck,
        u: *const dilithium3::polyveck,
        v: *const dilithium3::polyveck,
    ),
    pub polyveck_caddq: unsafe fn(v: *mut dilithium3::polyveck),
    pub polyveck_invntt_tomont: unsafe fn(v: *mut dilithium3::polyveck),
    pub polyveck_ntt: unsafe fn(v: *mut dilithium3::polyveck),
    pub polyveck_power2round: unsafe fn(
        v1: *mut dilithium3::polyveck,
        v0: *mut dilithium3::polyveck,
        v: *const dilithium3::polyveck,
    ),
    pub polyveck_reduce: unsafe fn(v: *mut dilithium3::polyveck),
    pub polyveck_uniform_eta: unsafe fn(v: *mut dilithium3::polyveck, seed: *const u8, nonce: u16),
    pub polyvecl_ntt: unsafe fn(v: *mut dilithium3::polyvecl),
    pub polyvecl_uniform_eta: unsafe fn(v: *mut dilithium3::polyvecl, seed: *const u8, nonce: u16),

    pub polyveck_decompose: unsafe fn(
        v1: *mut dilithium3::polyveck,
        v0: *mut dilithium3::polyveck,
        v: *const dilithium3::polyveck,
    ),
    pub polyveck_pack_w1: unsafe fn(r: *mut u8, w1: *const dilithium3::polyveck),
    pub poly_challenge: unsafe fn(c: *mut dilithium3::poly, seed: *const u8),
    pub polyvecl_pointwise_poly_montgomery: unsafe fn(
        r: *mut dilithium3::polyvecl,
        a: *const dilithium3::poly,
        v: *const dilithium3::polyvecl,
    ),
    pub polyvecl_invntt_tomont: unsafe fn(v: *mut dilithium3::polyvecl),
    pub polyvecl_add: unsafe fn(
        w: *mut dilithium3::polyvecl,
        u: *const dilithium3::polyvecl,
        v: *const dilithium3::polyvecl,
    ),
    pub polyvecl_reduce: unsafe fn(v: *mut dilithium3::polyvecl),
    pub polyvecl_chknorm: unsafe fn(v: *const dilithium3::polyvecl, B: i32) -> core::ffi::c_int,
    pub polyveck_chknorm: unsafe fn(v: *const dilithium3::polyveck, B: i32) -> core::ffi::c_int,
    pub polyveck_pointwise_poly_montgomery: unsafe fn(
        r: *mut dilithium3::polyveck,
        a: *const dilithium3::poly,
        v: *const dilithium3::polyveck,
    ),
    pub polyveck_sub: unsafe fn(
        w: *mut dilithium3::polyveck,
        u: *const dilithium3::polyveck,
        v: *const dilithium3::polyveck,
    ),
    pub polyveck_make_hint: unsafe fn(
        h: *mut dilithium3::polyveck,
        v0: *const dilithium3::polyveck,
        v1: *const dilithium3::polyveck,
    ) -> core::ffi::c_uint,
    pub pack_sig: unsafe fn(
        sig: *mut u8,
        c: *const u8,
        z: *const dilithium3::polyvecl,
        h: *const dilithium3::polyveck,
    ),
    pub unpack_sk: unsafe fn(
        rho: *mut u8,
        tr: *mut u8,
        key: *mut u8,
        t0: *mut dilithium3::polyveck,
        s1: *mut dilithium3::polyvecl,
        s2: *mut dilithium3::polyveck,
        sk: *const u8,
    ),
    pub pack_pk: unsafe fn(pk: *mut u8, rho: *const u8, t1: *const dilithium3::polyveck),
    pub pack_sk: unsafe fn(
        sk: *mut u8,
        rho: *const u8,
        tr: *const u8,
        key: *const u8,
        t0: *const dilithium3::polyveck,
        s1: *const dilithium3::polyvecl,
        s2: *const dilithium3::polyveck,
    ),
    pub polyvecl_uniform_gamma1:
        unsafe fn(v: *mut dilithium3::polyvecl, seed: *const u8, nonce: u16),
    pub unpack_pk: unsafe fn(rho: *mut u8, t1: *mut dilithium3::polyveck, pk: *const u8),

    pub polyveck_shiftl: unsafe fn(v: *mut dilithium3::polyveck),
    pub polyveck_use_hint: unsafe fn(
        w: *mut dilithium3::polyveck,
        v: *const dilithium3::polyveck,
        h: *const dilithium3::polyveck,
    ),

    pub unpack_sig: unsafe fn(
        c: *mut u8,
        z: *mut dilithium3::polyvecl,
        h: *mut dilithium3::polyveck,
        sig: *const u8,
    ) -> ::core::ffi::c_int,
}

#[allow(non_snake_case)]
pub(crate) const DILITHIUM2: DilithiumImpl = DilithiumImpl {
    k: 4,
    l: 4,
    max_attempts: 331,
    
    K: dilithium2::K,
    L: dilithium2::L,
    ETA: dilithium2::ETA,
    TAU: dilithium2::TAU,
    BETA: dilithium2::BETA,
    GAMMA1: dilithium2::GAMMA1,
    GAMMA2: dilithium2::GAMMA2,
    OMEGA: dilithium2::OMEGA,
    POLYT1_PACKEDBYTES: dilithium2::POLYT1_PACKEDBYTES,
    POLYT0_PACKEDBYTES: dilithium2::POLYT0_PACKEDBYTES,
    POLYVECH_PACKEDBYTES: dilithium2::POLYVECH_PACKEDBYTES,
    POLYZ_PACKEDBYTES: dilithium2::POLYZ_PACKEDBYTES,
    POLYW1_PACKEDBYTES: dilithium2::POLYW1_PACKEDBYTES,
    POLYETA_PACKEDBYTES: dilithium2::POLYETA_PACKEDBYTES,
    CRYPTO_PUBLICKEYBYTES: dilithium2::CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES: dilithium2::CRYPTO_SECRETKEYBYTES,
    CRYPTO_BYTES: dilithium2::CRYPTO_BYTES,

    shake256_init: dilithium3::pqcrystals_dilithium_fips202_ref_shake256_init,
    shake256_absorb: dilithium3::pqcrystals_dilithium_fips202_ref_shake256_absorb,
    shake256_finalize: dilithium3::pqcrystals_dilithium_fips202_ref_shake256_finalize,
    shake256_squeeze: dilithium3::pqcrystals_dilithium_fips202_ref_shake256_squeeze,
    polyvec_matrix_expand: |mat, rho| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyvec_matrix_expand(transmute(mat), rho)
    },

    polyvecl_uniform_eta: |v, seed, nonce| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_uniform_eta(transmute(v), seed, nonce)
    },
    polyveck_uniform_eta: |v, seed, nonce| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_uniform_eta(transmute(v), seed, nonce)
    },
    polyvecl_ntt: |v| unsafe { dilithium2::pqcrystals_dilithium2_ref_polyvecl_ntt(transmute(v)) },
    poly_ntt: |v| unsafe { dilithium2::pqcrystals_dilithium2_ref_poly_ntt(transmute(v)) },
    polyveck_ntt: |v| unsafe { dilithium2::pqcrystals_dilithium2_ref_polyveck_ntt(transmute(v)) },
    polyvec_matrix_pointwise_montgomery: |t, mat, v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyvec_matrix_pointwise_montgomery(
            transmute(t),
            transmute(mat),
            transmute(v),
        )
    },
    polyveck_reduce: |v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_reduce(transmute(v))
    },
    polyveck_invntt_tomont: |v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_invntt_tomont(transmute(v))
    },
    polyveck_add: |w, u, v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_add(transmute(w), transmute(u), transmute(v))
    },
    polyveck_caddq: |v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_caddq(transmute(v))
    },
    polyveck_power2round: |v1, v0, v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_power2round(
            transmute(v1),
            transmute(v0),
            transmute(v),
        )
    },

    polyveck_decompose: |v1, v0, v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_decompose(
            transmute(v1),
            transmute(v0),
            transmute(v),
        )
    },
    polyveck_pack_w1: |r, w1| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_pack_w1(r, transmute(w1))
    },
    poly_challenge: |c, seed| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_poly_challenge(transmute(c), seed)
    },
    polyvecl_pointwise_poly_montgomery: |r, a, v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_pointwise_poly_montgomery(
            transmute(r),
            transmute(a),
            transmute(v),
        )
    },
    polyvecl_invntt_tomont: |v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_invntt_tomont(transmute(v))
    },
    polyvecl_add: |w, u, v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_add(transmute(w), transmute(u), transmute(v))
    },
    polyvecl_reduce: |v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_reduce(transmute(v))
    },
    polyvecl_chknorm: |v, B| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_chknorm(transmute(v), B)
    },
    polyveck_chknorm: |v, B| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_chknorm(transmute(v), B)
    },
    polyveck_pointwise_poly_montgomery: |r, a, v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_pointwise_poly_montgomery(
            transmute(r),
            transmute(a),
            transmute(v),
        )
    },
    polyveck_sub: |w, u, v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_sub(transmute(w), transmute(u), transmute(v))
    },
    polyveck_make_hint: |h, v0, v1| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_make_hint(
            transmute(h),
            transmute(v0),
            transmute(v1),
        )
    },
    pack_sig: |sig, c, z, h| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_pack_sig(
            sig,
            transmute(c),
            transmute(z),
            transmute(h),
        )
    },
    unpack_sk: |rho, tr, key, t0, s1, s2, sk| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_unpack_sk(rho, tr, key, transmute(t0), transmute(s1), transmute(s2), sk)
    },
    pack_pk: |pk, rho, t1| unsafe { dilithium2::pqcrystals_dilithium2_ref_pack_pk(pk, rho, transmute(t1)) },
    pack_sk: |sk, rho, tr, key, t0, s1, s2| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_pack_sk(sk, rho, tr, key, transmute(t0), transmute(s1), transmute(s2))
    },
    polyvecl_uniform_gamma1: |v, seed, nonce| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_uniform_gamma1(transmute(v), seed, nonce)
    },
    unpack_pk: |rho, t1, pk| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_unpack_pk(rho, transmute(t1), pk)
    },

    polyveck_shiftl: |v| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_shiftl(transmute(v))
    },
    polyveck_use_hint: |w, v, h| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_use_hint(
            transmute(w),
            transmute(v),
            transmute(h),
        )
    },
    unpack_sig: |c, z, h, sig| unsafe {
        dilithium2::pqcrystals_dilithium2_ref_unpack_sig(
            transmute(c),
            transmute(z),
            transmute(h),
            sig,
        )
    },
};

#[allow(non_snake_case)]
pub(crate) const DILITHIUM3: DilithiumImpl = DilithiumImpl {
    k: 6,
    l: 5,
    max_attempts: 406,

    K: dilithium3::K,
    L: dilithium3::L,
    ETA: dilithium3::ETA,
    TAU: dilithium3::TAU,
    BETA: dilithium3::BETA,
    GAMMA1: dilithium3::GAMMA1,
    GAMMA2: dilithium3::GAMMA2,
    OMEGA: dilithium3::OMEGA,
    POLYT1_PACKEDBYTES: dilithium3::POLYT1_PACKEDBYTES,
    POLYT0_PACKEDBYTES: dilithium3::POLYT0_PACKEDBYTES,
    POLYVECH_PACKEDBYTES: dilithium3::POLYVECH_PACKEDBYTES,
    POLYZ_PACKEDBYTES: dilithium3::POLYZ_PACKEDBYTES,
    POLYW1_PACKEDBYTES: dilithium3::POLYW1_PACKEDBYTES,
    POLYETA_PACKEDBYTES: dilithium3::POLYETA_PACKEDBYTES,
    CRYPTO_PUBLICKEYBYTES: dilithium3::CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES: dilithium3::CRYPTO_SECRETKEYBYTES,
    CRYPTO_BYTES: dilithium3::CRYPTO_BYTES,




    shake256_init: dilithium3::pqcrystals_dilithium_fips202_ref_shake256_init,
    shake256_absorb: dilithium3::pqcrystals_dilithium_fips202_ref_shake256_absorb,
    shake256_finalize: dilithium3::pqcrystals_dilithium_fips202_ref_shake256_finalize,
    shake256_squeeze: dilithium3::pqcrystals_dilithium_fips202_ref_shake256_squeeze,
    polyvec_matrix_expand: |mat, rho| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyvec_matrix_expand(mat, rho)
    },

    polyvecl_uniform_eta: |v, seed, nonce| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_uniform_eta(transmute(v), seed, nonce)
    },
    polyveck_uniform_eta: |v, seed, nonce| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_uniform_eta(transmute(v), seed, nonce)
    },
    poly_ntt: |v| unsafe { dilithium3::pqcrystals_dilithium3_ref_poly_ntt(transmute(v)) },
    polyvecl_ntt: |v| unsafe { dilithium3::pqcrystals_dilithium3_ref_polyvecl_ntt(transmute(v)) },
    polyveck_ntt: |v| unsafe { dilithium3::pqcrystals_dilithium3_ref_polyveck_ntt(transmute(v)) },
    polyvec_matrix_pointwise_montgomery: |t, mat, v| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyvec_matrix_pointwise_montgomery(
            transmute(t),
            transmute(mat),
            transmute(v),
        )
    },
    polyveck_reduce: |v| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_reduce(transmute(v))
    },
    polyveck_invntt_tomont: |v| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_invntt_tomont(transmute(v))
    },
    polyveck_add: |w, u, v| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_add(transmute(w), transmute(u), transmute(v))
    },
    polyveck_caddq: |v| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_caddq(transmute(v))
    },
    polyveck_power2round: |v1, v0, v| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_power2round(
            transmute(v1),
            transmute(v0),
            transmute(v),
        )
    },

    polyveck_decompose: |v1, v0, v| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_decompose(v1, v0, v)
    },
    polyveck_pack_w1: |r, w1| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_pack_w1(r, w1)
    },
    poly_challenge: |c, seed| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_poly_challenge(c, seed)
    },
    polyvecl_pointwise_poly_montgomery: |r, a, v| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_pointwise_poly_montgomery(r, a, v)
    },
    polyvecl_invntt_tomont: |v| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_invntt_tomont(v)
    },
    polyvecl_add: |w, u, v| unsafe { dilithium3::pqcrystals_dilithium3_ref_polyvecl_add(w, u, v) },
    polyvecl_reduce: |v| unsafe { dilithium3::pqcrystals_dilithium3_ref_polyvecl_reduce(v) },
    polyvecl_chknorm: |v, B| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_chknorm(v, B)
    },
    polyveck_chknorm: |v, B| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_chknorm(v, B)
    },
    polyveck_pointwise_poly_montgomery: |r, a, v| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_pointwise_poly_montgomery(r, a, v)
    },
    polyveck_sub: |w, u, v| unsafe { dilithium3::pqcrystals_dilithium3_ref_polyveck_sub(w, u, v) },
    polyveck_make_hint: |h, v0, v1| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_make_hint(h, v0, v1)
    },
    pack_sig: |sig, c, z, h| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_pack_sig(sig, c, z, h)
    },
    unpack_sk: |rho, tr, key, t0, s1, s2, sk| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_unpack_sk(rho, tr, key, t0, s1, s2, sk)
    },
    pack_pk: |pk, rho, t1| unsafe { dilithium3::pqcrystals_dilithium3_ref_pack_pk(pk, rho, t1) },
    pack_sk: |sk, rho, tr, key, t0, s1, s2| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_pack_sk(sk, rho, tr, key, t0, s1, s2)
    },
    polyvecl_uniform_gamma1: |v, seed, nonce| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_uniform_gamma1(v, seed, nonce)
    },
    unpack_pk: |rho, t1, pk| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_unpack_pk(rho, t1, pk)
    },

    polyveck_shiftl: |v| unsafe { dilithium3::pqcrystals_dilithium3_ref_polyveck_shiftl(v) },
    polyveck_use_hint: |w, v, h| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_use_hint(w, v, h)
    },
    unpack_sig: |c, z, h, sig| unsafe {
        dilithium3::pqcrystals_dilithium3_ref_unpack_sig(c, z, h, sig)
    },
};

// const DILITHIUM5: DilithiumImpl<GenericTypes> = DilithiumImpl {
//     k: 8,
//     l: 7,

//     max_attempts: 295,

//     expand_mask
// };

#[cfg(test)]
mod tests {
    use super::*;
    use crystals_dilithium_sys as refimpl;

    #[test]
    #[ignore = "still rapidly developing impl"]
    fn test_vtable_size() {
        assert_eq!(core::mem::size_of::<DilithiumImpl>(), 0);
    }

    #[test]
    fn test_dilithium2_params() {
        use refimpl::dilithium2::*;

        assert_eq!(u32::from(DILITHIUM2.k), K);
        assert_eq!(u32::from(DILITHIUM2.l), L);
    }

    #[test]
    fn test_dilithium3_params() {
        use refimpl::dilithium3::*;

        assert_eq!(u32::from(DILITHIUM3.k), K);
        assert_eq!(u32::from(DILITHIUM3.l), L);
    }
}
