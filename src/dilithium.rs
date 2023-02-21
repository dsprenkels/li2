use crate::params::*;
use crate::{api, keccak, packing, poly};
use digest::{ExtendableOutput, Update, XofReader};

// TODO: LEFT HERE
//
// Translate everthing from a const table to a dyn impl with 3 structs *that
// are the memory pools* for the variant implementations.  We will have to
// add accessors (const and mut) for acessing the fields as slices.
//
// Let's then start reimplementing the C functions, I think it is wise to start
// with all the fips202 code, and then move on to the other code.
// I expect that we will have to struggle a lot with type conversions, but I
// believe you can handle that. ;)
//
// Wrt generics and constants and everything, here are some guidelines to
// follow:
//   * Everything is a slice; or really: no arrays allowed!  All the array
//     space is allocated in the memory pools by the callers.  The inner
//     functions should not allocate those themselves, unless their length
//     is the same for every variant.
//   * Parameter data should go in a `const` params struct; but
//     differing functions should use a dyn impl.
//   * Type info cannot be generic in the inner functions.  (Use slices!)

struct KeygenMemoryPool<'a> {
    sk: &'a mut [u8],
    pk: &'a mut [u8],
    seedbuf: &'a mut [u8; 2 * SEEDBYTES + CRHBYTES],
    tr: &'a mut [u8; SEEDBYTES],
    mat: &'a mut [poly::Poly],
    s1: &'a mut [poly::Poly],
    s1hat: &'a mut [poly::Poly],
    s2: &'a mut [poly::Poly],
    t0: &'a mut [poly::Poly],
    t1: &'a mut [poly::Poly],
    keccak: &'a mut crate::keccak::KeccakState,
}

pub(crate) fn dilithium2_keygen_from_seed(
    seed: &[u8],
) -> Result<
    (
        api::SecretKey<api::Dilithium2>,
        api::PublicKey<api::Dilithium2>,
    ),
    crate::Error,
> {
    const P: DilithiumParams = DILITHIUM2;
    let mut sk = [0u8; P.secret_key_len];
    let mut pk = [0u8; P.public_key_len];
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut tr = [0u8; SEEDBYTES];
    let mut mat = [poly::Poly::zero(); P.k * P.l];
    let mut s1 = [poly::Poly::zero(); P.l];
    let mut s1hat = [poly::Poly::zero(); P.l];
    let mut s2 = [poly::Poly::zero(); P.k];
    let mut t0 = [poly::Poly::zero(); P.k];
    let mut t1 = [poly::Poly::zero(); P.k];

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
        keccak: &mut crate::keccak::KeccakState::default(),
    };
    dilithium_keygen_from_seed(&P, mem, seed)?;
    Ok((api::SecretKey { bytes: sk }, api::PublicKey { bytes: pk }))
}

pub(crate) fn dilithium3_keygen_from_seed(
    seed: &[u8],
) -> Result<
    (
        api::SecretKey<api::Dilithium3>,
        api::PublicKey<api::Dilithium3>,
    ),
    crate::Error,
> {
    const P: DilithiumParams = DILITHIUM3;
    let mut sk = [0u8; P.secret_key_len];
    let mut pk = [0u8; P.public_key_len];
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut tr = [0u8; SEEDBYTES];
    let mut mat = [poly::Poly::zero(); P.k * P.l];
    let mut s1 = [poly::Poly::zero(); P.l];
    let mut s1hat = [poly::Poly::zero(); P.l];
    let mut s2 = [poly::Poly::zero(); P.k];
    let mut t0 = [poly::Poly::zero(); P.k];
    let mut t1 = [poly::Poly::zero(); P.k];

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
        keccak: &mut crate::keccak::KeccakState::default(),
    };
    dilithium_keygen_from_seed(&P, mem, seed)?;
    Ok((api::SecretKey { bytes: sk }, api::PublicKey { bytes: pk }))
}

pub(crate) fn dilithium5_keygen_from_seed(
    seed: &[u8],
) -> Result<
    (
        api::SecretKey<api::Dilithium5>,
        api::PublicKey<api::Dilithium5>,
    ),
    crate::Error,
> {
    const P: DilithiumParams = DILITHIUM5;
    let mut sk = [0u8; P.secret_key_len];
    let mut pk = [0u8; P.public_key_len];
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut tr = [0u8; SEEDBYTES];
    let mut mat = [poly::Poly::zero(); P.k * P.l];
    let mut s1 = [poly::Poly::zero(); P.l];
    let mut s1hat = [poly::Poly::zero(); P.l];
    let mut s2 = [poly::Poly::zero(); P.k];
    let mut t0 = [poly::Poly::zero(); P.k];
    let mut t1 = [poly::Poly::zero(); P.k];

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
        keccak: &mut crate::keccak::KeccakState::default(),
    };
    dilithium_keygen_from_seed(&P, mem, seed)?;
    Ok((api::SecretKey { bytes: sk }, api::PublicKey { bytes: pk }))
}

fn dilithium_keygen_from_seed(
    p: &'static DilithiumParams,
    mem: KeygenMemoryPool<'_>,
    seed: &[u8],
) -> Result<(), crate::Error> {
    debug_assert_eq!(seed.len(), SEEDBYTES);

    let mut xof = keccak::SHAKE256::new(mem.keccak);
    xof.update(seed);
    xof.finalize_xof().read(mem.seedbuf);

    let (rho, seedbuf) = mem.seedbuf.split_at_mut(SEEDBYTES);
    let (rhoprime, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
    let (key, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
    debug_assert_eq!(seedbuf, &[]);

    // Expand matrix
    crate::expanda::polyvec_matrix_expand(p, mem.keccak, mem.mat, rho);

    // Sample short vectors s1 and s2
    let mut nonce = 0;
    let s1_mut: &mut [poly::Poly] = &mut *mem.s1;
    let s2_mut: &mut [poly::Poly] = &mut *mem.s2;
    nonce += crate::expands::polyvec_uniform_eta(p, mem.keccak, s1_mut, rhoprime, nonce);
    crate::expands::polyvec_uniform_eta(p, mem.keccak, s2_mut, rhoprime, nonce);

    // Matrix-vector multiplication
    mem.s1hat.copy_from_slice(&mem.s1);
    crate::ntt::polyvec_ntt(&mut *mem.s1hat);
    poly::polyvec_matrix_pointwise_montgomery(p, &mut *mem.t1, mem.mat, &*mem.s1hat);
    poly::polyvec_pointwise(&mut *mem.t1, crate::reduce::reduce32);
    crate::ntt::polyvec_invntt_tomont(&mut *mem.t1);

    // Add error vector s2
    poly::polyvec_add(&mut *mem.t1, &*mem.s2);

    // Extract t1 and write public key
    poly::polyvec_pointwise(&mut *mem.t1, crate::reduce::caddq);
    for (t0_elem, t1_elem) in mem.t0.iter_mut().zip(mem.t1.iter_mut()) {
        for (t0_coeff, t1_coeff) in t0_elem.coeffs.iter_mut().zip(t1_elem.coeffs.iter_mut()) {
            (*t0_coeff, *t1_coeff) = crate::rounding::power2round(*t1_coeff);
        }
    }
    packing::pack_pk(p, mem.pk, rho, mem.t1);

    // Compute H(rho, t1) and write secret key
    let mut xof = keccak::SHAKE256::new(mem.keccak);
    xof.update(mem.pk);
    xof.finalize_xof().read(mem.tr);

    packing::pack_sk(p, mem.sk, rho, mem.tr, key, mem.t0, mem.s1, mem.s2);
    Ok(())
}

struct SignMemoryPool<'a> {
    sigbytes: &'a mut [u8],
    seedbuf: &'a mut [u8],
    mat: &'a mut [poly::Poly],
    s1: &'a mut [poly::Poly],
    y: &'a mut [poly::Poly],
    z: &'a mut [poly::Poly],
    t0: &'a mut [poly::Poly],
    s2: &'a mut [poly::Poly],
    w1: &'a mut [poly::Poly],
    w0: &'a mut [poly::Poly],
    h: &'a mut [poly::Poly],
    cp: &'a mut poly::Poly,
    keccak: &'a mut crate::keccak::KeccakState,
}

pub(crate) fn dilithium2_signature(
    sk: &api::SecretKey<api::Dilithium2>,
    msg: &[u8],
) -> Result<api::Signature<api::Dilithium2>, crate::Error> {
    const P: DilithiumParams = DILITHIUM2;
    let mut sigbytes = [0; P.signature_len];
    let mut seedbuf = [0u8; 3 * SEEDBYTES + 2 * CRHBYTES];
    let mut mat = [poly::Poly::zero(); P.k * P.l];
    let mut s1 = [poly::Poly::zero(); P.l];
    let mut y = [poly::Poly::zero(); P.l];
    let mut z = [poly::Poly::zero(); P.l];
    let mut t0 = [poly::Poly::zero(); P.k];
    let mut s2 = [poly::Poly::zero(); P.k];
    let mut w1 = [poly::Poly::zero(); P.k];
    let mut w0 = [poly::Poly::zero(); P.k];
    let mut h = [poly::Poly::zero(); P.k];
    let mut cp = poly::Poly::zero();

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
        keccak: &mut crate::keccak::KeccakState::default(),
    };
    dilithium_signature(&P, mem, &sk.bytes, msg)?;
    Ok(api::Signature { bytes: sigbytes })
}

pub(crate) fn dilithium3_signature(
    sk: &api::SecretKey<api::Dilithium3>,
    m: &[u8],
) -> Result<api::Signature<api::Dilithium3>, crate::Error> {
    const P: DilithiumParams = DILITHIUM3;
    let mut sigbytes = [0; P.signature_len];
    let mut seedbuf = [0u8; 3 * SEEDBYTES + 2 * CRHBYTES];
    let mut mat = [poly::Poly::zero(); P.k * P.l];
    let mut s1 = [poly::Poly::zero(); P.l];
    let mut y = [poly::Poly::zero(); P.l];
    let mut z = [poly::Poly::zero(); P.l];
    let mut t0 = [poly::Poly::zero(); P.k];
    let mut s2 = [poly::Poly::zero(); P.k];
    let mut w1 = [poly::Poly::zero(); P.k];
    let mut w0 = [poly::Poly::zero(); P.k];
    let mut h = [poly::Poly::zero(); P.k];
    let mut cp = poly::Poly::zero();

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
        keccak: &mut crate::keccak::KeccakState::default(),
    };

    dilithium_signature(&P, mem, &sk.bytes, m)?;
    Ok(api::Signature { bytes: sigbytes })
}

pub(crate) fn dilithium5_signature(
    sk: &api::SecretKey<api::Dilithium5>,
    m: &[u8],
) -> Result<api::Signature<api::Dilithium5>, crate::Error> {
    const P: DilithiumParams = DILITHIUM5;
    let mut sigbytes = [0; P.signature_len];
    let mut seedbuf = [0u8; 3 * SEEDBYTES + 2 * CRHBYTES];
    let mut mat = [poly::Poly::zero(); P.k * P.l];
    let mut s1 = [poly::Poly::zero(); P.l];
    let mut y = [poly::Poly::zero(); P.l];
    let mut z = [poly::Poly::zero(); P.l];
    let mut t0 = [poly::Poly::zero(); P.k];
    let mut s2 = [poly::Poly::zero(); P.k];
    let mut w1 = [poly::Poly::zero(); P.k];
    let mut w0 = [poly::Poly::zero(); P.k];
    let mut h = [poly::Poly::zero(); P.k];
    let mut cp = poly::Poly::zero();

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
        keccak: &mut crate::keccak::KeccakState::default(),
    };

    dilithium_signature(&P, mem, &sk.bytes, m)?;
    Ok(api::Signature { bytes: sigbytes })
}

fn dilithium_signature(
    p: &'static DilithiumParams,
    mut mem: SignMemoryPool<'_>,
    sk: &[u8],
    m: &[u8],
) -> Result<(), crate::Error> {
    let mut nonce = 0u16;

    let seedbuf = &mut mem.seedbuf;
    let (rho, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
    let (tr, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
    let (key, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
    let (mu, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
    let (rhoprime, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
    debug_assert_eq!(seedbuf, &[]);
    packing::unpack_sk(p, rho, tr, key, mem.t0, mem.s1, mem.s2, sk);

    // Compute mu := CRH(tr || msg)
    let mut xof = keccak::SHAKE256::new(mem.keccak);
    xof.update(tr);
    xof.update(m);
    xof.finalize_xof().read(mu);

    // Compute rhoprime := CRH(K || mu)
    let mut xof = keccak::SHAKE256::new(mem.keccak);
    xof.update(key);
    xof.update(mu);
    xof.finalize_xof().read(rhoprime);

    // Expand matrix and transform vectors
    crate::expanda::polyvec_matrix_expand(p, mem.keccak, mem.mat, rho);
    crate::ntt::polyvec_ntt(&mut mem.s1);
    crate::ntt::polyvec_ntt(&mut mem.s2);
    crate::ntt::polyvec_ntt(&mut mem.t0);

    let mut attempt = 0;
    'rej: loop {
        attempt += 1;
        if attempt >= p.max_attempts {
            panic!("max attempts exceeded");
        }

        // Sample intermediate vector y
        crate::expandmask::polyvecl_uniform_gamma1(p, &mut mem.y, rhoprime, nonce, mem.keccak);
        nonce += 1;

        // Matrix-vector multiplication
        mem.z.copy_from_slice(mem.y);
        crate::ntt::polyvec_ntt(&mut mem.z);
        poly::polyvec_matrix_pointwise_montgomery(p, &mut mem.w1, &mem.mat, &mem.z);
        poly::polyvec_pointwise(&mut mem.w1, crate::reduce::reduce32);
        crate::ntt::polyvec_invntt_tomont(&mut mem.w1);

        // Decompose w and call the random oracle
        poly::polyvec_pointwise(&mut mem.w1, crate::reduce::caddq);
        poly::polyveck_decompose(p, &mut mem.w1, &mut mem.w0);
        packing::pack_polyvec_w1(p, &mut mem.sigbytes[0..p.k * p.w1_poly_packed_len], &mem.w1);

        // Compute challenge
        let mut xof = keccak::SHAKE256::new(mem.keccak);
        xof.update(mu);
        let w1_packed = &mem.sigbytes[0..p.k * p.w1_poly_packed_len];
        xof.update(w1_packed);
        let ctilde = &mut mem.sigbytes[..SEEDBYTES];
        xof.finalize_xof().read(ctilde);
        crate::challenge::sample_in_ball(p, &mut mem.cp, &mem.sigbytes[0..SEEDBYTES], mem.keccak);
        crate::ntt::poly_ntt(&mut mem.cp);

        // Compute z, reject if it reveals secret
        poly::polyvec_pointwise_montgomery(&mut mem.z, &mem.cp, &mem.s1);
        crate::ntt::polyvec_invntt_tomont(&mut mem.z);
        poly::polyvec_add(&mut mem.z, &mut mem.y);
        poly::polyvec_pointwise(&mut mem.z, crate::reduce::reduce32);
        if poly::polyvec_chknorm(&mem.z, p.gamma1 - p.beta).is_err() {
            continue 'rej;
        }

        // Check that subtracting cs2 does not change high bits of w and
        // low bits do not reveal secret information
        poly::polyvec_pointwise_montgomery(&mut mem.h, &mut mem.cp, &mut mem.s2);
        crate::ntt::polyvec_invntt_tomont(&mut mem.h);
        poly::polyvec_sub(&mut mem.w0, &mut mem.h);
        poly::polyvec_pointwise(&mut mem.w0, crate::reduce::reduce32);
        if poly::polyvec_chknorm(&mem.w0, p.gamma2 - p.beta).is_err() {
            continue 'rej;
        }

        // Compute hints for w1
        poly::polyvec_pointwise_montgomery(&mut mem.h, &mem.cp, &mem.t0);
        crate::ntt::polyvec_invntt_tomont(&mut mem.h);
        poly::polyvec_pointwise(&mut mem.h, crate::reduce::reduce32);
        if poly::polyvec_chknorm(&mem.h, p.gamma2).is_err() {
            continue 'rej;
        }
        poly::polyvec_add(&mut mem.w0, &mut mem.h);
        let hints_popcount = poly::polyvec_make_hint(p, &mut mem.w0, &mem.w1);
        if hints_popcount > p.omega {
            continue 'rej;
        }

        // Write signature
        let mut tmp = [0; SEEDBYTES];
        tmp.copy_from_slice(&mem.sigbytes[0..SEEDBYTES]);
        packing::pack_sig(p, mem.sigbytes, &tmp, mem.z, mem.w0);
        break 'rej;
    }
    Ok(())
}

struct VerifyMemoryPool<'a> {
    buf: &'a mut [u8],
    rho: &'a mut [u8],
    mu: &'a mut [u8],
    c: &'a mut [u8],
    c2: &'a mut [u8],
    cp: &'a mut poly::Poly,
    mat: &'a mut [poly::Poly],
    z: &'a mut [poly::Poly],
    t1: &'a mut [poly::Poly],
    w1: &'a mut [poly::Poly],
    h: &'a mut [poly::Poly],
    keccak: &'a mut crate::keccak::KeccakState,
}

pub(crate) fn dilithium2_verify(
    pk: &api::PublicKey<api::Dilithium2>,
    m: &[u8],
    sig: &api::Signature<api::Dilithium2>,
) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM2;
    let mut buf = [0; P.k * P.w1_poly_packed_len];
    let mut rho = [0; SEEDBYTES];
    let mut mu = [0; CRHBYTES];
    let mut c = [0; SEEDBYTES];
    let mut c2 = [0; SEEDBYTES];
    let mut cp = poly::Poly::zero();
    let mut mat: [poly::Poly; P.k * P.l] = [poly::Poly::zero(); P.l * P.k];
    let mut z = [poly::Poly::zero(); P.l];
    let mut t1 = [poly::Poly::zero(); P.k];
    let mut w1 = [poly::Poly::zero(); P.k];
    let mut h = [poly::Poly::zero(); P.k];

    let mem = VerifyMemoryPool {
        buf: &mut buf,
        rho: &mut rho,
        mu: &mut mu,
        c: &mut c,
        c2: &mut c2,
        cp: &mut cp,
        mat: &mut mat,
        z: &mut z,
        t1: &mut t1,
        w1: &mut w1,
        h: &mut h,
        keccak: &mut crate::keccak::KeccakState::default(),
    };

    dilithium_verify(&P, mem, &pk.bytes, m, &sig.bytes)
}

pub(crate) fn dilithium3_verify(
    pk: &api::PublicKey<api::Dilithium3>,
    m: &[u8],
    sig: &api::Signature<api::Dilithium3>,
) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM3;
    let mut buf = [0; P.k * P.w1_poly_packed_len];
    let mut rho = [0; SEEDBYTES];
    let mut mu = [0; CRHBYTES];
    let mut c = [0; SEEDBYTES];
    let mut c2 = [0; SEEDBYTES];
    let mut cp = poly::Poly::zero();
    let mut mat: [poly::Poly; P.k * P.l] = [poly::Poly::zero(); P.k * P.l];
    let mut z = [poly::Poly::zero(); P.l];
    let mut t1 = [poly::Poly::zero(); P.k];
    let mut w1 = [poly::Poly::zero(); P.k];
    let mut h = [poly::Poly::zero(); P.k];

    let mem = VerifyMemoryPool {
        buf: &mut buf,
        rho: &mut rho,
        mu: &mut mu,
        c: &mut c,
        c2: &mut c2,
        cp: &mut cp,
        mat: &mut mat,
        z: &mut z,
        t1: &mut t1,
        w1: &mut w1,
        h: &mut h,
        keccak: &mut crate::keccak::KeccakState::default(),
    };

    dilithium_verify(&P, mem, &pk.bytes, m, &sig.bytes)
}

pub(crate) fn dilithium5_verify(
    pk: &api::PublicKey<api::Dilithium5>,
    m: &[u8],
    sig: &api::Signature<api::Dilithium5>,
) -> Result<(), crate::Error> {
    const P: DilithiumParams = DILITHIUM5;
    let mut buf = [0; P.k * P.w1_poly_packed_len];
    let mut rho = [0; SEEDBYTES];
    let mut mu = [0; CRHBYTES];
    let mut c = [0; SEEDBYTES];
    let mut c2 = [0; SEEDBYTES];
    let mut cp = poly::Poly::zero();
    let mut mat: [poly::Poly; P.k * P.l] = [poly::Poly::zero(); P.k * P.l];
    let mut z = [poly::Poly::zero(); P.l];
    let mut t1 = [poly::Poly::zero(); P.k];
    let mut w1 = [poly::Poly::zero(); P.k];
    let mut h = [poly::Poly::zero(); P.k];

    let mem = VerifyMemoryPool {
        buf: &mut buf,
        rho: &mut rho,
        mu: &mut mu,
        c: &mut c,
        c2: &mut c2,
        cp: &mut cp,
        mat: &mut mat[..],
        z: &mut z,
        t1: &mut t1,
        w1: &mut w1,
        h: &mut h,
        keccak: &mut crate::keccak::KeccakState::default(),
    };

    dilithium_verify(&P, mem, &pk.bytes, m, &sig.bytes)
}

fn dilithium_verify(
    p: &'static DilithiumParams,
    mem: VerifyMemoryPool<'_>,
    pk_bytes: &[u8],
    m: &[u8],
    sig_bytes: &[u8],
) -> Result<(), crate::Error> {
    packing::unpack_pk(p, mem.rho, &mut *mem.t1, pk_bytes);
    packing::unpack_sig(p, mem.c, &mut *mem.z, &mut *mem.h, sig_bytes)?;
    poly::polyvec_chknorm(&*mem.z, p.gamma1 - p.beta)
        .map_err(|()| crate::Error::InvalidSignature)?;

    // Compute tr := H(pk)
    let mut xof = keccak::SHAKE256::new(mem.keccak);
    xof.update(pk_bytes);
    let tr = &mut mem.mu[0..SEEDBYTES];
    xof.finalize_xof().read(tr);

    // Compute mu := CRH(tr, msg)
    let mut xof = keccak::SHAKE256::new(mem.keccak);
    xof.update(tr);
    drop(tr);
    xof.update(m);
    xof.finalize_xof().read(mem.mu);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    crate::challenge::sample_in_ball(p, &mut *mem.cp, &mem.c, mem.keccak);
    crate::expanda::polyvec_matrix_expand(p, mem.keccak, mem.mat, mem.rho);

    crate::ntt::polyvec_ntt(&mut *mem.z);
    poly::polyvec_matrix_pointwise_montgomery(p, &mut *mem.w1, mem.mat, mem.z);

    crate::ntt::poly_ntt(&mut *mem.cp);
    poly::polyvec_pointwise(&mut *mem.t1, |x| x << D);
    crate::ntt::polyvec_ntt(&mut *mem.t1);
    poly::polyvec_pointwise_montgomery_inplace(&mut *mem.t1, &*mem.cp);
    poly::polyvec_sub(&mut *mem.w1, &*mem.t1);
    poly::polyvec_pointwise(&mut *mem.w1, crate::reduce::reduce32);
    crate::ntt::polyvec_invntt_tomont(&mut *mem.w1);

    // Reconstruct w1
    poly::polyvec_pointwise(&mut *mem.w1, crate::reduce::caddq);
    poly::polyvec_use_hint(p, &mut *mem.w1, &*mem.h);
    packing::pack_polyvec_w1(p, mem.buf, &*mem.w1);

    // Call random oracle and verify challenge
    let mut xof = keccak::SHAKE256::new(mem.keccak);
    xof.update(mem.mu);
    xof.update(mem.buf);
    xof.finalize_xof().read(mem.c2);
    if mem.c == mem.c2 {
        return Ok(());
    }
    Err(crate::Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    #![deny(dead_code)]

    extern crate std;

    use core::ptr::null_mut;
    use crystals_dilithium_sys::dilithium3::{randombytes, randombytes_init};
    use std::{sync::Mutex, vec};

    use once_cell::sync::Lazy;

    use super::*;

    // Unfortunately the deterministic KAT rng state is global.
    static KAT_RNG_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::default());

    macro_rules! test_refimpl_kat {
        ( $name:ident, $params:expr, $ref_keypair:expr, $ref_signature:expr, $ref_verify:expr, $actual_keygen:expr, $actual_signature:expr, $actual_verify:expr ) => {
            #[test]
            fn $name() {
                let p = $params;

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
                        let mut sk_expected = vec![0; p.secret_key_len];
                        let mut pk_expected = vec![0; p.public_key_len];
                        let mut sig_expected = vec![0; p.signature_len];
                        let ref mut siglen = 0;

                        // Generate the expected values
                        randombytes_init(seed.as_mut_ptr(), null_mut(), 256);
                        if 0 != $ref_keypair(pk_expected.as_mut_ptr(), sk_expected.as_mut_ptr()) {
                            panic!("KAT keypair failed");
                        }
                        if 0 != $ref_signature(
                            sig_expected.as_mut_ptr(),
                            siglen,
                            msg.as_ptr(),
                            mlen,
                            sk_expected.as_ptr(),
                        ) {
                            panic!("KAT signature failed");
                        }
                        let verify_expected = 0
                            == $ref_verify(
                                sig_expected.as_ptr(),
                                *siglen,
                                msg.as_ptr(),
                                mlen,
                                pk_expected.as_ptr(),
                            );
                        assert_eq!(*siglen, p.signature_len);

                        // Generate the actual values
                        randombytes_init(seed.as_mut_ptr(), null_mut(), 256);
                        let mut keygen_seed = [0; SEEDBYTES];
                        randombytes(keygen_seed.as_mut_ptr(), SEEDBYTES as u64);
                        let (sk_actual, pk_actual) = $actual_keygen(&keygen_seed).unwrap();
                        let sig_actual = $actual_signature(&sk_actual, msg).unwrap();
                        let verify_actual = $actual_verify(&pk_actual, msg, &sig_actual);

                        assert_eq!(
                            &pk_actual.bytes[..],
                            &pk_expected[..],
                            "public keys did not match"
                        );
                        assert_eq!(
                            &sk_actual.bytes[..],
                            &sk_expected[..],
                            "secret keys did not match"
                        );
                        assert_eq!(
                            &sig_actual.bytes[..],
                            &sig_expected[..],
                            "signatures did not match"
                        );
                        assert_eq!(verify_actual.is_ok(), verify_expected);
                    }
                }
                drop(rng_guard);
            }
        };
    }

    test_refimpl_kat!(
        test_refimpl_dilithium2_kat,
        DILITHIUM2,
        crystals_dilithium_sys::dilithium2::pqcrystals_dilithium2_ref_keypair,
        crystals_dilithium_sys::dilithium2::pqcrystals_dilithium2_ref_signature,
        crystals_dilithium_sys::dilithium2::pqcrystals_dilithium2_ref_verify,
        dilithium2_keygen_from_seed,
        dilithium2_signature,
        dilithium2_verify
    );
    test_refimpl_kat!(
        test_refimpl_dilithium3_kat,
        DILITHIUM3,
        crystals_dilithium_sys::dilithium3::pqcrystals_dilithium3_ref_keypair,
        crystals_dilithium_sys::dilithium3::pqcrystals_dilithium3_ref_signature,
        crystals_dilithium_sys::dilithium3::pqcrystals_dilithium3_ref_verify,
        dilithium3_keygen_from_seed,
        dilithium3_signature,
        dilithium3_verify
    );
    test_refimpl_kat!(
        test_refimpl_dilithium5_kat,
        DILITHIUM5,
        crystals_dilithium_sys::dilithium5::pqcrystals_dilithium5_ref_keypair,
        crystals_dilithium_sys::dilithium5::pqcrystals_dilithium5_ref_signature,
        crystals_dilithium_sys::dilithium5::pqcrystals_dilithium5_ref_verify,
        dilithium5_keygen_from_seed,
        dilithium5_signature,
        dilithium5_verify
    );

    #[test]
    #[ignore = "todo"]
    fn test_keygen_from_seed() {
        let seed = [0; SEEDBYTES];
        let (_sk_actual, _pk_actual) = dilithium3_keygen_from_seed(&seed).unwrap();
        todo!()

        // TODO: Check whether t0 + t1 << D == t
        // TODO: Check whether A*s1 + s2 == t
    }

    #[test]
    fn test_empty_message() {
        let seed = [0; SEEDBYTES];
        let (sk, pk) = dilithium3_keygen_from_seed(&seed).unwrap();

        let sigbytes_expected = unsafe {
            let mut sig = [0; DILITHIUM3.signature_len];
            let mut siglen = 0;
            crystals_dilithium_sys::dilithium3::pqcrystals_dilithium3_ref_signature(
                sig.as_mut_ptr(),
                &mut siglen,
                [].as_ptr(),
                0,
                sk.bytes.as_ptr(),
            );
            assert_eq!(siglen, DILITHIUM3.signature_len, "siglen mismatch");
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
