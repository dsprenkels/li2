use core::mem::transmute;

use crystals_dilithium_sys::{dilithium2, dilithium3, dilithium5};

use crate::params::DilithiumParams;

type poly = dilithium3::poly;
type polyvecl = dilithium3::polyvecl;
type polyveck = dilithium3::polyveck;

#[allow(non_snake_case)]
pub(crate) trait DilithiumVariant {
    unsafe fn poly_ntt(&self, v: *mut poly);
    unsafe fn polyvec_matrix_expand(&self, mat: *mut polyvecl, rho: *const u8);
    unsafe fn polyvec_matrix_pointwise_montgomery(
        &self,
        t: *mut polyveck,
        mat: *const polyvecl,
        v: *const polyvecl,
    );
    unsafe fn polyveck_add(&self, w: *mut polyveck, u: *const polyveck, v: *const polyveck);
    unsafe fn polyveck_caddq(&self, v: *mut polyveck);
    unsafe fn polyveck_invntt_tomont(&self, v: *mut polyveck);
    unsafe fn polyveck_ntt(&self, v: *mut polyveck);
    unsafe fn polyveck_power2round(&self, v1: *mut polyveck, v0: *mut polyveck, v: *const polyveck);
    unsafe fn polyveck_reduce(&self, v: *mut polyveck);
    unsafe fn polyveck_uniform_eta(&self, v: *mut polyveck, seed: *const u8, nonce: u16);
    unsafe fn polyvecl_ntt(&self, v: *mut polyvecl);
    unsafe fn polyvecl_uniform_eta(&self, v: *mut polyvecl, seed: *const u8, nonce: u16);

    unsafe fn polyveck_decompose(&self, v1: *mut polyveck, v0: *mut polyveck, v: *const polyveck);
    unsafe fn polyveck_pack_w1(&self, r: *mut u8, w1: *const polyveck);
    unsafe fn poly_challenge(&self, c: *mut poly, seed: *const u8);
    unsafe fn polyvecl_pointwise_poly_montgomery(
        &self,
        r: *mut polyvecl,
        a: *const poly,
        v: *const polyvecl,
    );
    unsafe fn polyvecl_invntt_tomont(&self, v: *mut polyvecl);
    unsafe fn polyvecl_add(&self, w: *mut polyvecl, u: *const polyvecl, v: *const polyvecl);
    unsafe fn polyvecl_reduce(&self, v: *mut polyvecl);
    unsafe fn polyvecl_chknorm(&self, v: *const polyvecl, B: i32) -> core::ffi::c_int;
    unsafe fn polyveck_chknorm(&self, v: *const polyveck, B: i32) -> core::ffi::c_int;
    unsafe fn polyveck_pointwise_poly_montgomery(
        &self,
        r: *mut polyveck,
        a: *const poly,
        v: *const polyveck,
    );
    unsafe fn polyveck_sub(&self, w: *mut polyveck, u: *const polyveck, v: *const polyveck);
    unsafe fn polyveck_make_hint(
        &self,
        h: *mut polyveck,
        v0: *const polyveck,
        v1: *const polyveck,
    ) -> core::ffi::c_uint;
    unsafe fn pack_sig(&self, sig: *mut u8, c: *const u8, z: *const polyvecl, h: *const polyveck);
    unsafe fn unpack_sk(
        &self,
        rho: *mut u8,
        tr: *mut u8,
        key: *mut u8,
        t0: *mut polyveck,
        s1: *mut polyvecl,
        s2: *mut polyveck,
        sk: *const u8,
    );
    unsafe fn pack_pk(&self, pk: *mut u8, rho: *const u8, t1: *const polyveck);
    unsafe fn pack_sk(
        &self,
        sk: *mut u8,
        rho: *const u8,
        tr: *const u8,
        key: *const u8,
        t0: *const polyveck,
        s1: *const polyvecl,
        s2: *const polyveck,
    );

    unsafe fn polyvecl_uniform_gamma1(&self, v: *mut polyvecl, seed: *const u8, nonce: u16);
    unsafe fn unpack_pk(&self, rho: *mut u8, t1: *mut polyveck, pk: *const u8);

    unsafe fn polyveck_shiftl(&self, v: *mut polyveck);
    unsafe fn polyveck_use_hint(&self, w: *mut polyveck, v: *const polyveck, h: *const polyveck);

    unsafe fn unpack_sig(
        &self,
        c: *mut u8,
        z: *mut polyvecl,
        h: *mut polyveck,
        sig: *const u8,
    ) -> ::core::ffi::c_int;
}

#[derive(Debug)]
pub(crate) struct Dilithium2;
#[derive(Debug)]
pub(crate) struct Dilithium3;
#[derive(Debug)]
pub(crate) struct Dilithium5;

impl DilithiumVariant for Dilithium2 {
    unsafe fn poly_ntt(&self, v: *mut poly) {
        dilithium2::pqcrystals_dilithium2_ref_poly_ntt(transmute(v))
    }

    unsafe fn polyvec_matrix_expand(&self, mat: *mut polyvecl, rho: *const u8) {
        dilithium2::pqcrystals_dilithium2_ref_polyvec_matrix_expand(transmute(mat), rho)
    }

    unsafe fn polyvec_matrix_pointwise_montgomery(
        &self,
        t: *mut polyveck,
        mat: *const polyvecl,
        v: *const polyvecl,
    ) {
        dilithium2::pqcrystals_dilithium2_ref_polyvec_matrix_pointwise_montgomery(
            transmute(t),
            transmute(mat),
            transmute(v),
        )
    }

    unsafe fn polyveck_add(&self, w: *mut polyveck, u: *const polyveck, v: *const polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_add(transmute(w), transmute(u), transmute(v))
    }

    unsafe fn polyveck_caddq(&self, v: *mut polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_caddq(transmute(v))
    }

    unsafe fn polyveck_invntt_tomont(&self, v: *mut polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_invntt_tomont(transmute(v))
    }

    unsafe fn polyveck_ntt(&self, v: *mut polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_ntt(transmute(v))
    }

    unsafe fn polyveck_power2round(
        &self,
        v1: *mut polyveck,
        v0: *mut polyveck,
        v: *const polyveck,
    ) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_power2round(
            transmute(v1),
            transmute(v0),
            transmute(v),
        )
    }

    unsafe fn polyveck_reduce(&self, v: *mut polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_reduce(transmute(v))
    }

    unsafe fn polyveck_uniform_eta(&self, v: *mut polyveck, seed: *const u8, nonce: u16) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_uniform_eta(transmute(v), seed, nonce)
    }

    unsafe fn polyvecl_ntt(&self, v: *mut polyvecl) {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_ntt(transmute(v))
    }

    unsafe fn polyvecl_uniform_eta(&self, v: *mut polyvecl, seed: *const u8, nonce: u16) {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_uniform_eta(transmute(v), seed, nonce)
    }

    unsafe fn polyveck_decompose(&self, v1: *mut polyveck, v0: *mut polyveck, v: *const polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_decompose(
            transmute(v1),
            transmute(v0),
            transmute(v),
        )
    }

    unsafe fn polyveck_pack_w1(&self, r: *mut u8, w1: *const polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_pack_w1(r, transmute(w1))
    }

    unsafe fn poly_challenge(&self, c: *mut poly, seed: *const u8) {
        dilithium2::pqcrystals_dilithium2_ref_poly_challenge(transmute(c), seed)
    }

    unsafe fn polyvecl_pointwise_poly_montgomery(
        &self,
        r: *mut polyvecl,
        a: *const poly,
        v: *const polyvecl,
    ) {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_pointwise_poly_montgomery(
            transmute(r),
            transmute(a),
            transmute(v),
        )
    }

    unsafe fn polyvecl_invntt_tomont(&self, v: *mut polyvecl) {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_invntt_tomont(transmute(v))
    }

    unsafe fn polyvecl_add(&self, w: *mut polyvecl, u: *const polyvecl, v: *const polyvecl) {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_add(transmute(w), transmute(u), transmute(v))
    }

    unsafe fn polyvecl_reduce(&self, v: *mut polyvecl) {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_reduce(transmute(v))
    }

    unsafe fn polyvecl_chknorm(&self, v: *const polyvecl, B: i32) -> core::ffi::c_int {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_chknorm(transmute(v), B)
    }

    unsafe fn polyveck_chknorm(&self, v: *const polyveck, B: i32) -> core::ffi::c_int {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_chknorm(transmute(v), B)
    }

    unsafe fn polyveck_pointwise_poly_montgomery(
        &self,
        r: *mut polyveck,
        a: *const poly,
        v: *const polyveck,
    ) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_pointwise_poly_montgomery(
            transmute(r),
            transmute(a),
            transmute(v),
        )
    }

    unsafe fn polyveck_sub(&self, w: *mut polyveck, u: *const polyveck, v: *const polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_sub(transmute(w), transmute(u), transmute(v))
    }

    unsafe fn polyveck_make_hint(
        &self,
        h: *mut polyveck,
        v0: *const polyveck,
        v1: *const polyveck,
    ) -> core::ffi::c_uint {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_make_hint(
            transmute(h),
            transmute(v0),
            transmute(v1),
        )
    }

    unsafe fn pack_sig(&self, sig: *mut u8, c: *const u8, z: *const polyvecl, h: *const polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_pack_sig(sig, c, transmute(z), transmute(h))
    }

    unsafe fn unpack_sk(
        &self,
        rho: *mut u8,
        tr: *mut u8,
        key: *mut u8,
        t0: *mut polyveck,
        s1: *mut polyvecl,
        s2: *mut polyveck,
        sk: *const u8,
    ) {
        dilithium2::pqcrystals_dilithium2_ref_unpack_sk(
            rho,
            tr,
            key,
            transmute(t0),
            transmute(s1),
            transmute(s2),
            sk,
        )
    }

    unsafe fn pack_pk(&self, pk: *mut u8, rho: *const u8, t1: *const polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_pack_pk(pk, rho, transmute(t1))
    }

    unsafe fn pack_sk(
        &self,
        sk: *mut u8,
        rho: *const u8,
        tr: *const u8,
        key: *const u8,
        t0: *const polyveck,
        s1: *const polyvecl,
        s2: *const polyveck,
    ) {
        dilithium2::pqcrystals_dilithium2_ref_pack_sk(
            sk,
            rho,
            tr,
            key,
            transmute(t0),
            transmute(s1),
            transmute(s2),
        )
    }

    unsafe fn polyvecl_uniform_gamma1(&self, v: *mut polyvecl, seed: *const u8, nonce: u16) {
        dilithium2::pqcrystals_dilithium2_ref_polyvecl_uniform_gamma1(transmute(v), seed, nonce)
    }

    unsafe fn unpack_pk(&self, rho: *mut u8, t1: *mut polyveck, pk: *const u8) {
        dilithium2::pqcrystals_dilithium2_ref_unpack_pk(rho, transmute(t1), pk)
    }

    unsafe fn polyveck_shiftl(&self, v: *mut polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_shiftl(transmute(v))
    }

    unsafe fn polyveck_use_hint(&self, w: *mut polyveck, v: *const polyveck, h: *const polyveck) {
        dilithium2::pqcrystals_dilithium2_ref_polyveck_use_hint(
            transmute(w),
            transmute(v),
            transmute(h),
        )
    }

    unsafe fn unpack_sig(
        &self,
        c: *mut u8,
        z: *mut polyvecl,
        h: *mut polyveck,
        sig: *const u8,
    ) -> core::ffi::c_int {
        dilithium2::pqcrystals_dilithium2_ref_unpack_sig(c, transmute(z), transmute(h), sig)
    }
}

impl DilithiumVariant for Dilithium3 {
    unsafe fn poly_ntt(&self, v: *mut poly) {
        dilithium3::pqcrystals_dilithium3_ref_poly_ntt(v)
    }

    unsafe fn polyvec_matrix_expand(&self, mat: *mut polyvecl, rho: *const u8) {
        dilithium3::pqcrystals_dilithium3_ref_polyvec_matrix_expand(mat, rho)
    }

    unsafe fn polyvec_matrix_pointwise_montgomery(
        &self,
        t: *mut polyveck,
        mat: *const polyvecl,
        v: *const polyvecl,
    ) {
        dilithium3::pqcrystals_dilithium3_ref_polyvec_matrix_pointwise_montgomery(t, mat, v)
    }

    unsafe fn polyveck_add(&self, w: *mut polyveck, u: *const polyveck, v: *const polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_add(w, u, v)
    }

    unsafe fn polyveck_caddq(&self, v: *mut polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_caddq(v)
    }

    unsafe fn polyveck_invntt_tomont(&self, v: *mut polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_invntt_tomont(v)
    }

    unsafe fn polyveck_ntt(&self, v: *mut polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_ntt(v)
    }

    unsafe fn polyveck_power2round(
        &self,
        v1: *mut polyveck,
        v0: *mut polyveck,
        v: *const polyveck,
    ) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_power2round(v1, v0, v)
    }

    unsafe fn polyveck_reduce(&self, v: *mut polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_reduce(v)
    }

    unsafe fn polyveck_uniform_eta(&self, v: *mut polyveck, seed: *const u8, nonce: u16) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_uniform_eta(v, seed, nonce)
    }

    unsafe fn polyvecl_ntt(&self, v: *mut polyvecl) {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_ntt(v)
    }

    unsafe fn polyvecl_uniform_eta(&self, v: *mut polyvecl, seed: *const u8, nonce: u16) {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_uniform_eta(v, seed, nonce)
    }

    unsafe fn polyveck_decompose(&self, v1: *mut polyveck, v0: *mut polyveck, v: *const polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_decompose(v1, v0, v)
    }

    unsafe fn polyveck_pack_w1(&self, r: *mut u8, w1: *const polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_pack_w1(r, w1)
    }

    unsafe fn poly_challenge(&self, c: *mut poly, seed: *const u8) {
        dilithium3::pqcrystals_dilithium3_ref_poly_challenge(c, seed)
    }

    unsafe fn polyvecl_pointwise_poly_montgomery(
        &self,
        r: *mut polyvecl,
        a: *const poly,
        v: *const polyvecl,
    ) {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_pointwise_poly_montgomery(r, a, v)
    }

    unsafe fn polyvecl_invntt_tomont(&self, v: *mut polyvecl) {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_invntt_tomont(v)
    }

    unsafe fn polyvecl_add(&self, w: *mut polyvecl, u: *const polyvecl, v: *const polyvecl) {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_add(w, u, v)
    }

    unsafe fn polyvecl_reduce(&self, v: *mut polyvecl) {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_reduce(v)
    }

    unsafe fn polyvecl_chknorm(&self, v: *const polyvecl, B: i32) -> core::ffi::c_int {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_chknorm(v, B)
    }

    unsafe fn polyveck_chknorm(&self, v: *const polyveck, B: i32) -> core::ffi::c_int {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_chknorm(v, B)
    }

    unsafe fn polyveck_pointwise_poly_montgomery(
        &self,
        r: *mut polyveck,
        a: *const poly,
        v: *const polyveck,
    ) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_pointwise_poly_montgomery(r, a, v)
    }

    unsafe fn polyveck_sub(&self, w: *mut polyveck, u: *const polyveck, v: *const polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_sub(w, u, v)
    }

    unsafe fn polyveck_make_hint(
        &self,
        h: *mut polyveck,
        v0: *const polyveck,
        v1: *const polyveck,
    ) -> core::ffi::c_uint {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_make_hint(h, v0, v1)
    }

    unsafe fn pack_sig(&self, sig: *mut u8, c: *const u8, z: *const polyvecl, h: *const polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_pack_sig(sig, c, z, h)
    }

    unsafe fn unpack_sk(
        &self,
        rho: *mut u8,
        tr: *mut u8,
        key: *mut u8,
        t0: *mut polyveck,
        s1: *mut polyvecl,
        s2: *mut polyveck,
        sk: *const u8,
    ) {
        dilithium3::pqcrystals_dilithium3_ref_unpack_sk(rho, tr, key, t0, s1, s2, sk)
    }

    unsafe fn pack_pk(&self, pk: *mut u8, rho: *const u8, t1: *const polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_pack_pk(pk, rho, t1)
    }

    unsafe fn pack_sk(
        &self,
        sk: *mut u8,
        rho: *const u8,
        tr: *const u8,
        key: *const u8,
        t0: *const polyveck,
        s1: *const polyvecl,
        s2: *const polyveck,
    ) {
        dilithium3::pqcrystals_dilithium3_ref_pack_sk(sk, rho, tr, key, t0, s1, s2)
    }

    unsafe fn polyvecl_uniform_gamma1(&self, v: *mut polyvecl, seed: *const u8, nonce: u16) {
        dilithium3::pqcrystals_dilithium3_ref_polyvecl_uniform_gamma1(v, seed, nonce)
    }

    unsafe fn unpack_pk(&self, rho: *mut u8, t1: *mut polyveck, pk: *const u8) {
        dilithium3::pqcrystals_dilithium3_ref_unpack_pk(rho, t1, pk)
    }

    unsafe fn polyveck_shiftl(&self, v: *mut polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_shiftl(v)
    }

    unsafe fn polyveck_use_hint(&self, w: *mut polyveck, v: *const polyveck, h: *const polyveck) {
        dilithium3::pqcrystals_dilithium3_ref_polyveck_use_hint(w, v, h)
    }

    unsafe fn unpack_sig(
        &self,
        c: *mut u8,
        z: *mut polyvecl,
        h: *mut polyveck,
        sig: *const u8,
    ) -> core::ffi::c_int {
        dilithium3::pqcrystals_dilithium3_ref_unpack_sig(c, z, h, sig)
    }
}

impl DilithiumVariant for Dilithium5 {
    unsafe fn poly_ntt(&self, v: *mut poly) {
        dilithium5::pqcrystals_dilithium5_ref_poly_ntt(transmute(v))
    }

    unsafe fn polyvec_matrix_expand(&self, mat: *mut polyvecl, rho: *const u8) {
        dilithium5::pqcrystals_dilithium5_ref_polyvec_matrix_expand(transmute(mat), rho)
    }

    unsafe fn polyvec_matrix_pointwise_montgomery(
        &self,
        t: *mut polyveck,
        mat: *const polyvecl,
        v: *const polyvecl,
    ) {
        dilithium5::pqcrystals_dilithium5_ref_polyvec_matrix_pointwise_montgomery(
            transmute(t),
            transmute(mat),
            transmute(v),
        )
    }

    unsafe fn polyveck_add(&self, w: *mut polyveck, u: *const polyveck, v: *const polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_add(transmute(w), transmute(u), transmute(v))
    }

    unsafe fn polyveck_caddq(&self, v: *mut polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_caddq(transmute(v))
    }

    unsafe fn polyveck_invntt_tomont(&self, v: *mut polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_invntt_tomont(transmute(v))
    }

    unsafe fn polyveck_ntt(&self, v: *mut polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_ntt(transmute(v))
    }

    unsafe fn polyveck_power2round(
        &self,
        v1: *mut polyveck,
        v0: *mut polyveck,
        v: *const polyveck,
    ) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_power2round(
            transmute(v1),
            transmute(v0),
            transmute(v),
        )
    }

    unsafe fn polyveck_reduce(&self, v: *mut polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_reduce(transmute(v))
    }

    unsafe fn polyveck_uniform_eta(&self, v: *mut polyveck, seed: *const u8, nonce: u16) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_uniform_eta(transmute(v), seed, nonce)
    }

    unsafe fn polyvecl_ntt(&self, v: *mut polyvecl) {
        dilithium5::pqcrystals_dilithium5_ref_polyvecl_ntt(transmute(v))
    }

    unsafe fn polyvecl_uniform_eta(&self, v: *mut polyvecl, seed: *const u8, nonce: u16) {
        dilithium5::pqcrystals_dilithium5_ref_polyvecl_uniform_eta(transmute(v), seed, nonce)
    }

    unsafe fn polyveck_decompose(&self, v1: *mut polyveck, v0: *mut polyveck, v: *const polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_decompose(
            transmute(v1),
            transmute(v0),
            transmute(v),
        )
    }

    unsafe fn polyveck_pack_w1(&self, r: *mut u8, w1: *const polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_pack_w1(r, transmute(w1))
    }

    unsafe fn poly_challenge(&self, c: *mut poly, seed: *const u8) {
        dilithium5::pqcrystals_dilithium5_ref_poly_challenge(transmute(c), seed)
    }

    unsafe fn polyvecl_pointwise_poly_montgomery(
        &self,
        r: *mut polyvecl,
        a: *const poly,
        v: *const polyvecl,
    ) {
        dilithium5::pqcrystals_dilithium5_ref_polyvecl_pointwise_poly_montgomery(
            transmute(r),
            transmute(a),
            transmute(v),
        )
    }

    unsafe fn polyvecl_invntt_tomont(&self, v: *mut polyvecl) {
        dilithium5::pqcrystals_dilithium5_ref_polyvecl_invntt_tomont(transmute(v))
    }

    unsafe fn polyvecl_add(&self, w: *mut polyvecl, u: *const polyvecl, v: *const polyvecl) {
        dilithium5::pqcrystals_dilithium5_ref_polyvecl_add(transmute(w), transmute(u), transmute(v))
    }

    unsafe fn polyvecl_reduce(&self, v: *mut polyvecl) {
        dilithium5::pqcrystals_dilithium5_ref_polyvecl_reduce(transmute(v))
    }

    unsafe fn polyvecl_chknorm(&self, v: *const polyvecl, B: i32) -> core::ffi::c_int {
        dilithium5::pqcrystals_dilithium5_ref_polyvecl_chknorm(transmute(v), B)
    }

    unsafe fn polyveck_chknorm(&self, v: *const polyveck, B: i32) -> core::ffi::c_int {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_chknorm(transmute(v), B)
    }

    unsafe fn polyveck_pointwise_poly_montgomery(
        &self,
        r: *mut polyveck,
        a: *const poly,
        v: *const polyveck,
    ) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_pointwise_poly_montgomery(
            transmute(r),
            transmute(a),
            transmute(v),
        )
    }

    unsafe fn polyveck_sub(&self, w: *mut polyveck, u: *const polyveck, v: *const polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_sub(transmute(w), transmute(u), transmute(v))
    }

    unsafe fn polyveck_make_hint(
        &self,
        h: *mut polyveck,
        v0: *const polyveck,
        v1: *const polyveck,
    ) -> core::ffi::c_uint {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_make_hint(
            transmute(h),
            transmute(v0),
            transmute(v1),
        )
    }

    unsafe fn pack_sig(&self, sig: *mut u8, c: *const u8, z: *const polyvecl, h: *const polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_pack_sig(sig, c, transmute(z), transmute(h))
    }

    unsafe fn unpack_sk(
        &self,
        rho: *mut u8,
        tr: *mut u8,
        key: *mut u8,
        t0: *mut polyveck,
        s1: *mut polyvecl,
        s2: *mut polyveck,
        sk: *const u8,
    ) {
        dilithium5::pqcrystals_dilithium5_ref_unpack_sk(
            rho,
            tr,
            key,
            transmute(t0),
            transmute(s1),
            transmute(s2),
            sk,
        )
    }

    unsafe fn pack_pk(&self, pk: *mut u8, rho: *const u8, t1: *const polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_pack_pk(pk, rho, transmute(t1))
    }

    unsafe fn pack_sk(
        &self,
        sk: *mut u8,
        rho: *const u8,
        tr: *const u8,
        key: *const u8,
        t0: *const polyveck,
        s1: *const polyvecl,
        s2: *const polyveck,
    ) {
        dilithium5::pqcrystals_dilithium5_ref_pack_sk(
            sk,
            rho,
            tr,
            key,
            transmute(t0),
            transmute(s1),
            transmute(s2),
        )
    }

    unsafe fn polyvecl_uniform_gamma1(&self, v: *mut polyvecl, seed: *const u8, nonce: u16) {
        dilithium5::pqcrystals_dilithium5_ref_polyvecl_uniform_gamma1(transmute(v), seed, nonce)
    }

    unsafe fn unpack_pk(&self, rho: *mut u8, t1: *mut polyveck, pk: *const u8) {
        dilithium5::pqcrystals_dilithium5_ref_unpack_pk(rho, transmute(t1), pk)
    }

    unsafe fn polyveck_shiftl(&self, v: *mut polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_shiftl(transmute(v))
    }

    unsafe fn polyveck_use_hint(&self, w: *mut polyveck, v: *const polyveck, h: *const polyveck) {
        dilithium5::pqcrystals_dilithium5_ref_polyveck_use_hint(
            transmute(w),
            transmute(v),
            transmute(h),
        )
    }

    unsafe fn unpack_sig(
        &self,
        c: *mut u8,
        z: *mut polyvecl,
        h: *mut polyveck,
        sig: *const u8,
    ) -> core::ffi::c_int {
        dilithium5::pqcrystals_dilithium5_ref_unpack_sig(c, transmute(z), transmute(h), sig)
    }
}

#[cfg(test)]
mod tests {
    static_assertions::assert_obj_safe!(super::DilithiumVariant);
}
