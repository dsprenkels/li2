#![no_std]

#[cfg(target_arch = "arm")]
extern crate panic_halt;

use core::{ffi::c_int, slice};

#[no_mangle]
unsafe extern "C" fn LI2_dilithium2_keygen_from_seed(
    sk: *mut u8,
    pk: *mut u8,
    seed: *const u8,
) -> c_int {
    let seed = slice::from_raw_parts(seed, li2::SEEDBYTES);
    let sk = slice::from_raw_parts_mut(sk, li2::DILITHIUM2.secret_key_len);
    let pk = slice::from_raw_parts_mut(pk, li2::DILITHIUM2.public_key_len);
    if li2::dilithium2_keygen_from_seed(sk, pk, seed).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
unsafe extern "C" fn LI2_dilithium3_keygen_from_seed(
    sk: *mut u8,
    pk: *mut u8,
    seed: *const u8,
) -> c_int {
    let seed = slice::from_raw_parts(seed, li2::SEEDBYTES);
    let sk = slice::from_raw_parts_mut(sk, li2::DILITHIUM3.secret_key_len);
    let pk = slice::from_raw_parts_mut(pk, li2::DILITHIUM3.public_key_len);
    if li2::dilithium3_keygen_from_seed(sk, pk, seed).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
unsafe extern "C" fn LI2_dilithium5_keygen_from_seed(
    sk: *mut u8,
    pk: *mut u8,
    seed: *const u8,
) -> c_int {
    let seed = slice::from_raw_parts(seed, li2::SEEDBYTES);
    let sk = slice::from_raw_parts_mut(sk, li2::DILITHIUM5.secret_key_len);
    let pk = slice::from_raw_parts_mut(pk, li2::DILITHIUM5.public_key_len);
    if li2::dilithium5_keygen_from_seed(sk, pk, seed).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
unsafe extern "C" fn LI2_dilithium2_signature(
    sk: *const u8,
    m: *const u8,
    mlen: usize,
    sig: *mut u8,
) -> c_int {
    let sk = slice::from_raw_parts(sk, li2::DILITHIUM2.secret_key_len);
    let m = slice::from_raw_parts(m, mlen);
    let sig = slice::from_raw_parts_mut(sig, li2::DILITHIUM2.signature_len);
    if li2::dilithium2_signature(sk, m, sig).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
unsafe extern "C" fn LI2_dilithium3_signature(
    sk: *const u8,
    m: *const u8,
    mlen: usize,
    sig: *mut u8,
) -> c_int {
    let sk = slice::from_raw_parts(sk, li2::DILITHIUM3.secret_key_len);
    let m = slice::from_raw_parts(m, mlen);
    let sig = slice::from_raw_parts_mut(sig, li2::DILITHIUM3.signature_len);
    if li2::dilithium3_signature(sk, m, sig).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
unsafe extern "C" fn LI2_dilithium5_signature(
    sk: *const u8,
    m: *const u8,
    mlen: usize,
    sig: *mut u8,
) -> c_int {
    let sk = slice::from_raw_parts(sk, li2::DILITHIUM5.secret_key_len);
    let m = slice::from_raw_parts(m, mlen);
    let sig = slice::from_raw_parts_mut(sig, li2::DILITHIUM5.signature_len);
    if li2::dilithium5_signature(sk, m, sig).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
unsafe extern "C" fn LI2_dilithium2_verify(
    pk: *const u8,
    m: *const u8,
    mlen: usize,
    sig: *const u8,
) -> c_int {
    let pk = slice::from_raw_parts(pk, li2::DILITHIUM2.public_key_len);
    let m = slice::from_raw_parts(m, mlen);
    let sig = slice::from_raw_parts(sig, li2::DILITHIUM2.signature_len);
    if li2::dilithium2_verify(pk, m, sig).is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
unsafe extern "C" fn LI2_dilithium3_verify(
    pk: *const u8,
    m: *const u8,
    mlen: usize,
    sig: *const u8,
) -> c_int {
    let pk = slice::from_raw_parts(pk, li2::DILITHIUM3.public_key_len);
    let m = slice::from_raw_parts(m, mlen);
    let sig = slice::from_raw_parts(sig, li2::DILITHIUM3.signature_len);
    if li2::dilithium3_verify(pk, m, sig).is_ok() {
        0
    } else {
        -1
    }
}
#[no_mangle]
unsafe extern "C" fn LI2_dilithium5_verify(
    pk: *const u8,
    m: *const u8,
    mlen: usize,
    sig: *const u8,
) -> c_int {
    let pk = slice::from_raw_parts(pk, li2::DILITHIUM5.public_key_len);
    let m = slice::from_raw_parts(m, mlen);
    let sig = slice::from_raw_parts(sig, li2::DILITHIUM5.signature_len);
    if li2::dilithium5_verify(pk, m, sig).is_ok() {
        0
    } else {
        -1
    }
}
