use once_cell::sync::Lazy;
use std::ptr::null_mut;
use std::sync::Mutex;

use li2::{Signer, Verifier};

// Unfortunately the deterministic KAT rng state is global.
static KAT_RNG_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::default());

#[test]
fn kat_dilithium2() {
    use crystals_dilithium_sys::dilithium2::*;
    use li2::dilithium2;

    let rng_guard = KAT_RNG_MUTEX.lock();

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
            let mut sk_expected = vec![0; CRYPTO_SECRETKEYBYTES as usize];
            let mut pk_expected = vec![0; CRYPTO_PUBLICKEYBYTES as usize];
            let mut sig_expected = vec![0; CRYPTO_BYTES as usize];
            let ref mut siglen = 0;

            // Generate the expected values
            randombytes_init(seed.as_mut_ptr(), null_mut(), 256);
            if 0 != pqcrystals_dilithium2_ref_keypair(
                pk_expected.as_mut_ptr(),
                sk_expected.as_mut_ptr(),
            ) {
                panic!("KAT keypair failed");
            }
            if 0 != pqcrystals_dilithium2_ref_signature(
                sig_expected.as_mut_ptr(),
                siglen,
                msg.as_ptr(),
                mlen,
                sk_expected.as_ptr(),
            ) {
                panic!("KAT signature failed");
            }
            let verify_expected = 0
                == pqcrystals_dilithium2_ref_verify(
                    sig_expected.as_ptr(),
                    *siglen,
                    msg.as_ptr(),
                    mlen,
                    pk_expected.as_ptr(),
                );
            assert_eq!(*siglen, sig_expected.len());

            // Generate the actual values
            randombytes_init(seed.as_mut_ptr(), null_mut(), 256);
            let mut keygen_seed = [0; dilithium2::SEED_LENGTH];
            randombytes(keygen_seed.as_mut_ptr(), dilithium2::SEED_LENGTH as u64);
            let keypair = dilithium2::Keypair::generate_from_seed(&keygen_seed).unwrap();
            let sk_actual = keypair.secret;
            let pk_actual = keypair.public;
            let sig_actual = sk_actual.sign(msg);
            let verify_actual = pk_actual.verify(msg, &sig_actual);

            assert_eq!(
                pk_actual.as_ref(),
                &pk_expected[..],
                "public keys did not match"
            );
            assert_eq!(
                sk_actual.as_ref(),
                &sk_expected[..],
                "secret keys did not match"
            );
            assert_eq!(
                sig_actual.as_ref(),
                &sig_expected[..],
                "signatures did not match"
            );
            assert_eq!(verify_actual.is_ok(), verify_expected);
        }
    }

    drop(rng_guard);
}

#[test]
fn kat_dilithium3() {
    use crystals_dilithium_sys::dilithium3::*;
    use li2::dilithium3;

    let rng_guard = KAT_RNG_MUTEX.lock();

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
            let mut sk_expected = vec![0; CRYPTO_SECRETKEYBYTES as usize];
            let mut pk_expected = vec![0; CRYPTO_PUBLICKEYBYTES as usize];
            let mut sig_expected = vec![0; CRYPTO_BYTES as usize];
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
            let verify_expected = 0
                == pqcrystals_dilithium3_ref_verify(
                    sig_expected.as_ptr(),
                    *siglen,
                    msg.as_ptr(),
                    mlen,
                    pk_expected.as_ptr(),
                );
            assert_eq!(*siglen, sig_expected.len());

            // Generate the actual values
            randombytes_init(seed.as_mut_ptr(), null_mut(), 256);
            let mut keygen_seed = [0; dilithium3::SEED_LENGTH];
            randombytes(keygen_seed.as_mut_ptr(), dilithium3::SEED_LENGTH as u64);
            let keypair = dilithium3::Keypair::generate_from_seed(&keygen_seed).unwrap();
            let sk_actual = keypair.secret;
            let pk_actual = keypair.public;
            let sig_actual = sk_actual.sign(msg);
            let verify_actual = pk_actual.verify(msg, &sig_actual);

            assert_eq!(
                pk_actual.as_ref(),
                &pk_expected[..],
                "public keys did not match"
            );
            assert_eq!(
                sk_actual.as_ref(),
                &sk_expected[..],
                "secret keys did not match"
            );
            assert_eq!(
                sig_actual.as_ref(),
                &sig_expected[..],
                "signatures did not match"
            );
            assert_eq!(verify_actual.is_ok(), verify_expected);
        }
    }

    drop(rng_guard);
}

#[test]
fn kat_dilithium5() {
    use crystals_dilithium_sys::dilithium5::*;
    use li2::dilithium5;

    let rng_guard = KAT_RNG_MUTEX.lock();

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
            let mut sk_expected = vec![0; CRYPTO_SECRETKEYBYTES as usize];
            let mut pk_expected = vec![0; CRYPTO_PUBLICKEYBYTES as usize];
            let mut sig_expected = vec![0; CRYPTO_BYTES as usize];
            let ref mut siglen = 0;

            // Generate the expected values
            randombytes_init(seed.as_mut_ptr(), null_mut(), 256);
            if 0 != pqcrystals_dilithium5_ref_keypair(
                pk_expected.as_mut_ptr(),
                sk_expected.as_mut_ptr(),
            ) {
                panic!("KAT keypair failed");
            }
            if 0 != pqcrystals_dilithium5_ref_signature(
                sig_expected.as_mut_ptr(),
                siglen,
                msg.as_ptr(),
                mlen,
                sk_expected.as_ptr(),
            ) {
                panic!("KAT signature failed");
            }
            let verify_expected = 0
                == pqcrystals_dilithium5_ref_verify(
                    sig_expected.as_ptr(),
                    *siglen,
                    msg.as_ptr(),
                    mlen,
                    pk_expected.as_ptr(),
                );
            assert_eq!(*siglen, sig_expected.len());

            // Generate the actual values
            randombytes_init(seed.as_mut_ptr(), null_mut(), 256);
            let mut keygen_seed = [0; dilithium5::SEED_LENGTH];
            randombytes(keygen_seed.as_mut_ptr(), dilithium5::SEED_LENGTH as u64);
            let keypair = dilithium5::Keypair::generate_from_seed(&keygen_seed).unwrap();
            let sk_actual = keypair.secret;
            let pk_actual = keypair.public;
            let sig_actual = sk_actual.sign(msg);
            let verify_actual = pk_actual.verify(msg, &sig_actual);

            assert_eq!(
                pk_actual.as_ref(),
                &pk_expected[..],
                "public keys did not match"
            );
            assert_eq!(
                sk_actual.as_ref(),
                &sk_expected[..],
                "secret keys did not match"
            );
            assert_eq!(
                sig_actual.as_ref(),
                &sig_expected[..],
                "signatures did not match"
            );
            assert_eq!(verify_actual.is_ok(), verify_expected);
        }
    }

    drop(rng_guard);
}
