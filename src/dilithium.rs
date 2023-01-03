use crate::{
    params::{DilithiumParams, CRHBYTES, DILITHIUM2, DILITHIUM3, DILITHIUM5, SEEDBYTES},
    api::{
        Dilithium2, Dilithium3, Dilithium5, DilithiumVariant, PublicKey, SecretKey, Signature,
        SEED_SIZE,
    },
    Error,
};
use crate::{api, variants};
use crystals_dilithium_sys as refimpl;
use refimpl::dilithium3::{keccak_state, poly, polyveck, polyvecl};

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
    mat: &'a mut [poly],
    s1: &'a mut [poly],
    s1hat: &'a mut [poly],
    s2: &'a mut [poly],
    t0: &'a mut [poly],
    t1: &'a mut [poly],
}

#[inline]
pub fn dilithium2_keygen_from_seed(
    seed: &[u8],
) -> Result<
    (
        api::SecretKey<Dilithium2>,
        api::PublicKey<Dilithium2>,
    ),
    crate::Error,
> {
    const P: DilithiumParams = DILITHIUM2;
    let mut sk = [0u8; P.CRYPTO_SECRETKEYBYTES as usize];
    let mut pk = [0u8; P.CRYPTO_PUBLICKEYBYTES as usize];
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut tr = [0u8; SEEDBYTES];
    let mut mat: [poly; P.k as usize * P.l as usize] = unsafe { core::mem::zeroed() };

    let mut s1 = <[poly; P.l as usize]>::default();
    let mut s1hat = <[poly; P.l as usize]>::default();
    let mut s2 = <[poly; P.k as usize]>::default();
    let mut t0 = <[poly; P.k as usize]>::default();
    let mut t1 = <[poly; P.k as usize]>::default();

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
    dilithium_keygen_from_seed(&P, mem, seed)?;
    Ok((SecretKey { bytes: sk }, PublicKey { bytes: pk }))
}

pub fn dilithium3_keygen_from_seed(
    seed: &[u8],
) -> Result<(SecretKey<Dilithium3>, PublicKey<Dilithium3>), Error> {
    const P: DilithiumParams = DILITHIUM3;
    let mut sk = [0u8; P.CRYPTO_SECRETKEYBYTES as usize];
    let mut pk = [0u8; P.CRYPTO_PUBLICKEYBYTES as usize];
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut tr = [0u8; SEEDBYTES];
    let mut mat: [poly; P.k as usize * P.l as usize] = unsafe { core::mem::zeroed() };

    let mut s1 = <[poly; P.l as usize]>::default();
    let mut s1hat = <[poly; P.l as usize]>::default();
    let mut s2 = <[poly; P.k as usize]>::default();
    let mut t0 = <[poly; P.k as usize]>::default();
    let mut t1 = <[poly; P.k as usize]>::default();

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
    dilithium_keygen_from_seed(&P, mem, seed)?;
    Ok((SecretKey { bytes: sk }, PublicKey { bytes: pk }))
}

pub fn dilithium5_keygen_from_seed(
    seed: &[u8],
) -> Result<(SecretKey<Dilithium5>, PublicKey<Dilithium5>), Error> {
    const P: DilithiumParams = DILITHIUM5;
    let mut sk = [0u8; P.CRYPTO_SECRETKEYBYTES as usize];
    let mut pk = [0u8; P.CRYPTO_PUBLICKEYBYTES as usize];
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut tr = [0u8; SEEDBYTES];
    let mut mat: [poly; P.k as usize * P.l as usize] = unsafe { core::mem::zeroed() };
    let mut s1 = <[poly; P.l as usize]>::default();
    let mut s1hat = <[poly; P.l as usize]>::default();
    let mut s2 = <[poly; P.k as usize]>::default();
    let mut t0 = <[poly; P.k as usize]>::default();
    let mut t1 = <[poly; P.k as usize]>::default();

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
    dilithium_keygen_from_seed(&P, mem, seed)?;
    Ok((SecretKey { bytes: sk }, PublicKey { bytes: pk }))
}

fn dilithium_keygen_from_seed(
    p: &'static DilithiumParams,
    mem: KeygenMemoryPool<'_>,
    seed: &[u8],
) -> Result<(), Error> {
    let v = p.variant;

    debug_assert_eq!(seed.len(), SEEDBYTES);

    unsafe {
        let mat_ptr: *mut polyvecl = core::mem::transmute(mem.mat.as_mut_ptr());
        let s1_ptr: *mut polyvecl = core::mem::transmute(mem.s1.as_mut_ptr());
        let s1hat_ptr: *mut polyvecl = core::mem::transmute(mem.s1hat.as_mut_ptr());
        let s2_ptr: *mut polyveck = core::mem::transmute(mem.s2.as_mut_ptr());
        let t1_ptr: *mut polyveck = core::mem::transmute(mem.t1.as_mut_ptr());
        let t0_ptr: *mut polyveck = core::mem::transmute(mem.t0.as_mut_ptr());
        let mut state = keccak_state::default();
        mem.seedbuf[0..SEEDBYTES].copy_from_slice(seed);

        v.shake256_init(&mut state);
        v.shake256_absorb(&mut state, mem.seedbuf.as_ptr(), SEEDBYTES);
        v.shake256_finalize(&mut state);
        v.shake256_squeeze(mem.seedbuf.as_mut_ptr(), mem.seedbuf.len(), &mut state);

        let (rho, seedbuf) = mem.seedbuf.split_at_mut(SEEDBYTES);
        let (rhoprime, seedbuf) = seedbuf.split_at_mut(CRHBYTES);
        let (key, seedbuf) = seedbuf.split_at_mut(SEEDBYTES);
        debug_assert_eq!(seedbuf, &[]);

        // Expand matrix
        v.polyvec_matrix_expand(mat_ptr, rho.as_ptr());

        // Sample short vectors s1 and s2
        v.polyvecl_uniform_eta(s1_ptr, rhoprime.as_ptr(), 0);
        v.polyveck_uniform_eta(s2_ptr, rhoprime.as_mut_ptr(), p.l);

        // Matrix-vector multiplication
        for idx in 0..p.L as usize {
            *(*s1hat_ptr).vec.get_unchecked_mut(idx) = mem.s1[idx];
        }

        v.polyvecl_ntt(s1hat_ptr);
        v.polyvec_matrix_pointwise_montgomery(t1_ptr, mat_ptr, s1hat_ptr);
        v.polyveck_reduce(t1_ptr);
        v.polyveck_invntt_tomont(t1_ptr);

        // Add error vector s2
        v.polyveck_add(t1_ptr, t1_ptr, s2_ptr);

        // Extract t1 and write public key
        v.polyveck_caddq(t1_ptr);
        v.polyveck_power2round(t1_ptr, t0_ptr, t1_ptr);
        v.pack_pk(mem.pk.as_mut_ptr(), rho.as_ptr(), t1_ptr);

        // Compute H(rho, t1) and write secret key
        v.shake256_init(&mut state);
        v.shake256_absorb(&mut state, mem.pk.as_ptr(), mem.pk.len());
        v.shake256_finalize(&mut state);
        v.shake256_squeeze(mem.tr.as_mut_ptr(), SEEDBYTES, &mut state);
        v.pack_sk(
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

pub fn dilithium2_signature(
    sk: &SecretKey<Dilithium2>,
    m: &[u8],
) -> Result<Signature<Dilithium2>, Error> {
    const P: DilithiumParams = DILITHIUM2;
    let v = P.variant;
    let mut sigbytes = [0; P.CRYPTO_BYTES as usize];
    let mut seedbuf = [0u8; 3 * SEEDBYTES + 2 * CRHBYTES];
    let mut mat: [poly; P.k as usize * P.l as usize] = unsafe { core::mem::zeroed() };
    let mut s1 = <[poly; P.l as usize]>::default();
    let mut y = <[poly; P.l as usize]>::default();
    let mut z = <[poly; P.l as usize]>::default();
    let mut t0 = <[poly; P.k as usize]>::default();
    let mut s2 = <[poly; P.k as usize]>::default();
    let mut w1 = <[poly; P.k as usize]>::default();
    let mut w0 = <[poly; P.k as usize]>::default();
    let mut h = <[poly; P.k as usize]>::default();
    let mut cp = poly::default();
    let mut state = keccak_state::default();

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
    dilithium_signature(&P, mem, &sk.bytes, m)?;
    Ok(Signature { bytes: sigbytes })
}

pub fn dilithium3_signature(
    sk: &SecretKey<Dilithium3>,
    m: &[u8],
) -> Result<Signature<Dilithium3>, Error> {
    const P: DilithiumParams = DILITHIUM3;
    let mut sigbytes = [0; P.CRYPTO_BYTES as usize];
    let mut seedbuf = [0u8; 3 * SEEDBYTES + 2 * CRHBYTES];
    let mut mat: [poly; P.k as usize * P.l as usize] = unsafe { core::mem::zeroed() };

    let mut s1 = <[poly; P.l as usize]>::default();
    let mut y = <[poly; P.l as usize]>::default();
    let mut z = <[poly; P.l as usize]>::default();
    let mut t0 = <[poly; P.k as usize]>::default();
    let mut s2 = <[poly; P.k as usize]>::default();
    let mut w1 = <[poly; P.k as usize]>::default();
    let mut w0 = <[poly; P.k as usize]>::default();
    let mut h = <[poly; P.k as usize]>::default();
    let mut cp = poly::default();
    let mut state = keccak_state::default();

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

    dilithium_signature(&P, mem, &sk.bytes, m)?;
    Ok(Signature { bytes: sigbytes })
}

pub fn dilithium5_signature(
    sk: &SecretKey<Dilithium5>,
    m: &[u8],
) -> Result<Signature<Dilithium5>, Error> {
    const P: DilithiumParams = DILITHIUM5;
    let mut sigbytes = [0; P.CRYPTO_BYTES as usize];
    let mut seedbuf = [0u8; 3 * SEEDBYTES + 2 * CRHBYTES];
    let mut mat: [poly; P.k as usize * P.l as usize] = unsafe { core::mem::zeroed() };
    let mut s1 = <[poly; P.l as usize]>::default();
    let mut y = <[poly; P.l as usize]>::default();
    let mut z = <[poly; P.l as usize]>::default();
    let mut t0 = <[poly; P.k as usize]>::default();
    let mut s2 = <[poly; P.k as usize]>::default();
    let mut w1 = <[poly; P.k as usize]>::default();
    let mut w0 = <[poly; P.k as usize]>::default();
    let mut h = <[poly; P.k as usize]>::default();
    let mut cp = poly::default();
    let mut state = keccak_state::default();

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

    dilithium_signature(&P, mem, &sk.bytes, m)?;
    Ok(Signature { bytes: sigbytes })
}

fn dilithium_signature(
    p: &'static DilithiumParams,
    mut mem: SignMemoryPool<'_>,
    sk: &[u8],
    m: &[u8],
) -> Result<(), Error> {
    let v = p.variant;
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
        v.unpack_sk(
            rho.as_mut_ptr(),
            tr.as_mut_ptr(),
            key.as_mut_ptr(),
            t0_ptr,
            s1_ptr,
            s2_ptr,
            sk.as_ptr(),
        );

        // Compute mu := CRH(tr || msg)
        v.shake256_init(mem.state);
        v.shake256_absorb(mem.state, tr.as_ptr(), SEEDBYTES);
        v.shake256_absorb(mem.state, m.as_ptr(), m.len());
        v.shake256_finalize(mem.state);
        v.shake256_squeeze(mu.as_mut_ptr(), CRHBYTES, mem.state);

        // Compute rhoprime := CRH(K || mu)
        v.shake256_init(mem.state);
        v.shake256_absorb(mem.state, key.as_ptr(), SEEDBYTES);
        v.shake256_absorb(mem.state, mu.as_ptr(), CRHBYTES);
        v.shake256_finalize(mem.state);
        v.shake256_squeeze(rhoprime.as_mut_ptr(), CRHBYTES, mem.state);

        // Expand matrix and transform vectors
        v.polyvec_matrix_expand(mat_ptr, rho.as_ptr());
        v.polyvecl_ntt(s1_ptr);
        v.polyveck_ntt(s2_ptr);
        v.polyveck_ntt(t0_ptr);

        let mut attempt = 0;
        'rej: loop {
            attempt += 1;
            if attempt >= p.max_attempts {
                panic!("max attempts exceeded");
            }

            // Sample intermediate vector y
            v.polyvecl_uniform_gamma1(y_ptr, rhoprime.as_ptr(), nonce);
            nonce += 1;

            // Matrix-vector multiplication
            for idx in 0..p.L as usize {
                *(*z_ptr).vec.get_unchecked_mut(idx) = mem.y[idx];
            }
            v.polyvecl_ntt(z_ptr);
            v.polyvec_matrix_pointwise_montgomery(w1_ptr, mat_ptr, z_ptr);
            v.polyveck_reduce(w1_ptr);
            v.polyveck_invntt_tomont(w1_ptr);

            // Decompose w and call the random oracle
            v.polyveck_caddq(w1_ptr);
            v.polyveck_decompose(w1_ptr, w0_ptr, w1_ptr);
            v.polyveck_pack_w1(mem.sigbytes.as_mut_ptr(), w1_ptr);

            // Compute challenge
            v.shake256_init(mem.state);
            v.shake256_absorb(mem.state, mu.as_ptr(), CRHBYTES);
            v.shake256_absorb(
                mem.state,
                mem.sigbytes.as_ptr(),
                p.k as usize * p.POLYW1_PACKEDBYTES as usize,
            );
            v.shake256_finalize(mem.state);
            v.shake256_squeeze(mem.sigbytes.as_mut_ptr(), SEEDBYTES, mem.state);
            v.poly_challenge(mem.cp, mem.sigbytes.as_ptr());
            v.poly_ntt(mem.cp);

            // Compute z, reject if it reveals secret
            v.polyvecl_pointwise_poly_montgomery(z_ptr, mem.cp, s1_ptr);
            v.polyvecl_invntt_tomont(z_ptr);
            v.polyvecl_add(z_ptr, z_ptr, y_ptr);
            v.polyvecl_reduce(z_ptr);
            if 0 != v.polyvecl_chknorm(z_ptr, (p.GAMMA1 - p.BETA) as i32) {
                continue 'rej;
            }

            // Check that subtracting cs2 does not change high bits of w and
            // low bits do not reveal secret information
            v.polyveck_pointwise_poly_montgomery(h_ptr, mem.cp, s2_ptr);
            v.polyveck_invntt_tomont(h_ptr);
            v.polyveck_sub(w0_ptr, w0_ptr, h_ptr);
            v.polyveck_reduce(w0_ptr);
            if 0 != v.polyveck_chknorm(w0_ptr, (p.GAMMA2 - p.BETA) as i32) {
                continue 'rej;
            }

            // Compute hints for w1
            v.polyveck_pointwise_poly_montgomery(h_ptr, mem.cp, t0_ptr);
            v.polyveck_invntt_tomont(h_ptr);
            v.polyveck_reduce(h_ptr);
            if 0 != v.polyveck_chknorm(h_ptr, p.GAMMA2 as i32) {
                continue 'rej;
            }
            v.polyveck_add(w0_ptr, w0_ptr, h_ptr);
            let n = v.polyveck_make_hint(h_ptr, w0_ptr, w1_ptr);
            if n > p.OMEGA {
                continue 'rej;
            }

            // Write signature
            v.pack_sig(
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

#[derive(Debug)]
struct VerifyMemoryPool<'a> {
    buf: &'a mut [u8],
    rho: &'a mut [u8],
    mu: &'a mut [u8],
    c: &'a mut [u8],
    c2: &'a mut [u8],
    cp: &'a mut poly,
    mat: &'a mut [poly],
    z: &'a mut [poly],
    t1: &'a mut [poly],
    w1: &'a mut [poly],
    h: &'a mut [poly],
    state: &'a mut keccak_state,
}

pub fn dilithium2_verify(
    pk: &PublicKey<Dilithium2>,
    m: &[u8],
    sig: &Signature<Dilithium2>,
) -> Result<(), Error> {
    const di: DilithiumParams = DILITHIUM2;

    let mut buf = [0; di.K as usize * di.POLYW1_PACKEDBYTES as usize];
    let mut rho = [0; SEEDBYTES];
    let mut mu = [0; CRHBYTES];
    let mut c = [0; SEEDBYTES];
    let mut c2 = [0; SEEDBYTES];
    let mut cp = poly::default();
    let mut mat: [poly; di.k as usize * di.l as usize] = unsafe { core::mem::zeroed() };
    let mut z = <[poly; di.L as usize]>::default();
    let mut t1 = <[poly; di.K as usize]>::default();
    let mut w1 = <[poly; di.K as usize]>::default();
    let mut h = <[poly; di.K as usize]>::default();
    let mut state = keccak_state::default();

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
        state: &mut &mut state,
    };

    dilithium_verify(&di, mem, &pk.bytes, m, &sig.bytes)
}

pub fn dilithium3_verify(
    pk: &PublicKey<Dilithium3>,
    m: &[u8],
    sig: &Signature<Dilithium3>,
) -> Result<(), Error> {
    const p: DilithiumParams = DILITHIUM3;
    let v = p.variant;

    let mut buf = [0; p.K as usize * p.POLYW1_PACKEDBYTES as usize];
    let mut rho = [0; SEEDBYTES];
    let mut mu = [0; CRHBYTES];
    let mut c = [0; SEEDBYTES];
    let mut c2 = [0; SEEDBYTES];
    let mut cp = poly::default();
    let mut mat: [poly; p.k as usize * p.l as usize] = unsafe { core::mem::zeroed() };
    let mut z = <[poly; p.L as usize]>::default();
    let mut t1 = <[poly; p.K as usize]>::default();
    let mut w1 = <[poly; p.K as usize]>::default();
    let mut h = <[poly; p.K as usize]>::default();
    let mut state = keccak_state::default();

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
        state: &mut &mut state,
    };

    dilithium_verify(&p, mem, &pk.bytes, m, &sig.bytes)
}

pub fn dilithium5_verify(
    pk: &PublicKey<Dilithium5>,
    m: &[u8],
    sig: &Signature<Dilithium5>,
) -> Result<(), Error> {
    const P: DilithiumParams = DILITHIUM5;

    let mut buf = [0; P.K as usize * P.POLYW1_PACKEDBYTES as usize];
    let mut rho = [0; SEEDBYTES];
    let mut mu = [0; CRHBYTES];
    let mut c = [0; SEEDBYTES];
    let mut c2 = [0; SEEDBYTES];
    let mut cp = poly::default();
    let mut mat: [poly; P.k as usize * P.l as usize] = unsafe { core::mem::zeroed() };
    let mut z = <[poly; P.L as usize]>::default();
    let mut t1 = <[poly; P.K as usize]>::default();
    let mut w1 = <[poly; P.K as usize]>::default();
    let mut h = <[poly; P.K as usize]>::default();
    let mut state = keccak_state::default();

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
        state: &mut &mut state,
    };

    dilithium_verify(&P, mem, &pk.bytes, m, &sig.bytes)
}

fn dilithium_verify(
    p: &'static DilithiumParams,
    mem: VerifyMemoryPool<'_>,
    pk_bytes: &[u8],
    m: &[u8],
    sig_bytes: &[u8],
) -> Result<(), Error> {
    let v = p.variant;

    unsafe {
        let buf_ptr = mem.buf.as_mut_ptr();
        let rho_ptr = mem.rho.as_mut_ptr();
        let mu_ptr = mem.mu.as_mut_ptr();
        let c_ptr = mem.c.as_mut_ptr();
        let c2_ptr = mem.c2.as_mut_ptr();
        let cp_ptr = mem.cp;
        let mat_ptr = core::mem::transmute(mem.mat.as_mut_ptr());
        let z_ptr = core::mem::transmute(mem.z.as_mut_ptr());
        let t1_ptr = core::mem::transmute(mem.t1.as_mut_ptr());
        let w1_ptr = core::mem::transmute(mem.w1.as_mut_ptr());
        let h_ptr = core::mem::transmute(mem.h.as_mut_ptr());
        let state_ptr = mem.state;

        v.unpack_pk(rho_ptr, t1_ptr, pk_bytes.as_ptr());
        if 0 != v.unpack_sig(c_ptr, z_ptr, h_ptr, sig_bytes.as_ptr()) {
            return Err(Error::InvalidSignature);
        }
        if 0 != v.polyvecl_chknorm(z_ptr, (p.GAMMA1 - p.BETA) as i32) {
            return Err(Error::InvalidSignature);
        }

        // Compute tr := H(pk)
        v.shake256_init(state_ptr);
        v.shake256_absorb(
            state_ptr,
            pk_bytes.as_ptr(),
            p.CRYPTO_PUBLICKEYBYTES as usize,
        );
        v.shake256_finalize(state_ptr);
        v.shake256_squeeze(mu_ptr, SEEDBYTES, state_ptr);

        // Compute mu := CRH(tr, msg)
        v.shake256_init(state_ptr);
        v.shake256_absorb(state_ptr, mu_ptr, SEEDBYTES);
        v.shake256_absorb(state_ptr, m.as_ptr(), m.len());
        v.shake256_finalize(state_ptr);
        v.shake256_squeeze(mu_ptr, CRHBYTES, state_ptr);

        /* Matrix-vector multiplication; compute Az - c2^dt1 */
        v.poly_challenge(cp_ptr, c_ptr);
        v.polyvec_matrix_expand(mat_ptr, rho_ptr);

        v.polyvecl_ntt(z_ptr);
        v.polyvec_matrix_pointwise_montgomery(w1_ptr, mat_ptr, z_ptr);

        v.poly_ntt(cp_ptr);
        v.polyveck_shiftl(t1_ptr);
        v.polyveck_ntt(t1_ptr);
        v.polyveck_pointwise_poly_montgomery(t1_ptr, cp_ptr, t1_ptr);

        v.polyveck_sub(w1_ptr, w1_ptr, t1_ptr);
        v.polyveck_reduce(w1_ptr);
        v.polyveck_invntt_tomont(w1_ptr);

        // Reconstruct w1
        v.polyveck_caddq(w1_ptr);
        v.polyveck_use_hint(w1_ptr, w1_ptr, h_ptr);
        v.polyveck_pack_w1(buf_ptr, w1_ptr);

        // Call random oracle and verify challenge
        v.shake256_init(state_ptr);
        v.shake256_absorb(state_ptr, mu_ptr, CRHBYTES);
        v.shake256_absorb(
            state_ptr,
            buf_ptr,
            p.K as usize * p.POLYW1_PACKEDBYTES as usize,
        );
        v.shake256_finalize(state_ptr);
        v.shake256_squeeze(c2_ptr, SEEDBYTES, state_ptr);
        if mem.c == mem.c2 {
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
    use crystals_dilithium_sys::dilithium3::{randombytes, randombytes_init};
    use std::{sync::Mutex, vec};

    use once_cell::sync::Lazy;

    use super::*;

    // Unfortunately the deterministic KAT rng state is global.
    static KAT_RNG_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::default());

    macro_rules! test_refimpl_kat {
        ( $name:ident, $variant:ty, $p:expr, $ref_keypair:expr, $ref_signature:expr, $ref_verify:expr, $actual_keygen:expr, $actual_signature:expr, $actual_verify:expr ) => {
            #[test]
            fn $name() {
                type V = $variant;
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
                        let mut sk_expected = vec![0; V::SECKEY_SIZE];
                        let mut pk_expected = vec![0; V::PUBKEY_SIZE];
                        let mut sig_expected = vec![0; V::SIG_SIZE];
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
                        assert_eq!(*siglen, V::SIG_SIZE);

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
        Dilithium2,
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
        Dilithium3,
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
        Dilithium5,
        DILITHIUM5,
        crystals_dilithium_sys::dilithium5::pqcrystals_dilithium5_ref_keypair,
        crystals_dilithium_sys::dilithium5::pqcrystals_dilithium5_ref_signature,
        crystals_dilithium_sys::dilithium5::pqcrystals_dilithium5_ref_verify,
        dilithium5_keygen_from_seed,
        dilithium5_signature,
        dilithium5_verify
    );

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
            crystals_dilithium_sys::dilithium3::pqcrystals_dilithium3_ref_signature(
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
