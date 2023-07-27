pub(crate) const Q: i32 = 8380417;
pub(crate) const N: usize = 256;
pub(crate) const D: u32 = 13;

pub const SEEDBYTES: usize = 32;
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

#[derive(Debug)]
pub struct DilithiumParams {
    pub(crate) k: usize,
    pub(crate) l: usize,
    pub(crate) eta: i32,
    pub(crate) tau: u8,
    pub(crate) beta: i32,
    pub(crate) gamma1: i32,
    pub(crate) gamma2: i32,
    pub(crate) omega: usize,
    pub(crate) max_attempts: u16,

    pub(crate) t1_poly_packed_len: usize,
    pub(crate) t0_poly_packed_len: usize,
    pub(crate) z_poly_packed_len: usize,
    pub(crate) w1_poly_packed_len: usize,
    pub(crate) eta_poly_packed_len: usize,
    pub public_key_len: usize,
    pub secret_key_len: usize,
    pub signature_len: usize,
}

pub const DILITHIUM2: DilithiumParams = DilithiumParams {
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    beta: 78,
    gamma1: 2i32.pow(17),
    gamma2: (Q - 1) / 88,
    omega: 80,
    max_attempts: 331,

    t1_poly_packed_len: 320,
    t0_poly_packed_len: 416,
    z_poly_packed_len: 576,
    w1_poly_packed_len: 192,
    eta_poly_packed_len: 96,
    public_key_len: 1312,
    secret_key_len: 2560,
    signature_len: 2420,
};

pub const DILITHIUM3: DilithiumParams = DilithiumParams {
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    beta: 196,
    gamma1: 2i32.pow(19),
    gamma2: (Q - 1) / 32,
    omega: 55,
    max_attempts: 406,

    t1_poly_packed_len: 320,
    t0_poly_packed_len: 416,
    z_poly_packed_len: 640,
    w1_poly_packed_len: 128,
    eta_poly_packed_len: 128,
    public_key_len: 1952,
    secret_key_len: 4032,
    signature_len: 3293,
};

pub const DILITHIUM5: DilithiumParams = DilithiumParams {
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    beta: 120,
    gamma1: 2i32.pow(19),
    gamma2: (Q - 1) / 32,
    omega: 75,
    max_attempts: 295,

    t1_poly_packed_len: 320,
    t0_poly_packed_len: 416,
    z_poly_packed_len: 640,
    w1_poly_packed_len: 128,
    eta_poly_packed_len: 96,
    public_key_len: 2592,
    secret_key_len: 4896,
    signature_len: 4595,
};

#[cfg(test)]
mod tests {
    use core::f64::consts::E;

    use super::*;
    use crystals_dilithium_sys as refimpl;

    #[test]
    fn test_beta() {
        for p in [DILITHIUM2, DILITHIUM3, DILITHIUM5] {
            assert_eq!(p.beta, p.tau as i32 * p.eta);
        }
    }

    #[test]
    /// Assert that the probability of using `max_attempts` iterations in the
    /// rejection sampling loop corresponds to the number for which the
    /// probability of that happening is smaller than 2^-128.
    ///
    /// This test is based on Section 3.4 of the Dilithium specification
    /// (round 3), including the assumption that r0 is uniformly distributed
    /// modulo 2 * gamma2.
    fn test_max_attempts() {
        for p in [DILITHIUM2, DILITHIUM3, DILITHIUM5] {
            let n = N as f64;
            let l = p.l as f64;
            let k = p.k as f64;
            let gamma1 = p.gamma1 as f64;
            let gamma2 = p.gamma2 as f64;
            let beta = p.beta as f64;
            let max_attempts = p.max_attempts as f64;

            let exponent = -n * beta * (l / gamma1 + k / gamma2);
            let pr_reject = 1.0 - E.powf(exponent);
            let pr_complete_fail_log2 = max_attempts * pr_reject.log2();
            assert_eq!(pr_complete_fail_log2.round(), -128.0)
        }
    }

    #[test]
    fn test_dilithium2_params_ref() {
        use refimpl::dilithium2::*;

        assert_eq!(DILITHIUM2.k, K as usize);
        assert_eq!(DILITHIUM2.l, L as usize);
        assert_eq!(DILITHIUM2.eta, ETA as i32);
        assert_eq!(DILITHIUM2.tau, TAU as u8);
        assert_eq!(DILITHIUM2.beta, BETA as i32);
        assert_eq!(DILITHIUM2.gamma1, GAMMA1 as i32);
        assert_eq!(DILITHIUM2.gamma2, GAMMA2 as i32);
        assert_eq!(DILITHIUM2.omega, OMEGA as usize);

        assert_eq!(DILITHIUM2.t1_poly_packed_len, POLYT1_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM2.t0_poly_packed_len, POLYT0_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM2.z_poly_packed_len, POLYZ_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM2.w1_poly_packed_len, POLYW1_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM2.eta_poly_packed_len, POLYETA_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM2.public_key_len, CRYPTO_PUBLICKEYBYTES as usize);
        assert_eq!(DILITHIUM2.secret_key_len, CRYPTO_SECRETKEYBYTES as usize);
        assert_eq!(DILITHIUM2.signature_len, CRYPTO_BYTES as usize);
    }

    #[test]
    fn test_dilithium3_params_ref() {
        use refimpl::dilithium3::*;

        assert_eq!(DILITHIUM3.k, K as usize);
        assert_eq!(DILITHIUM3.l, L as usize);
        assert_eq!(DILITHIUM3.eta, ETA as i32);
        assert_eq!(DILITHIUM3.tau, TAU as u8);
        assert_eq!(DILITHIUM3.beta, BETA as i32);
        assert_eq!(DILITHIUM3.gamma1, GAMMA1 as i32);
        assert_eq!(DILITHIUM3.gamma2, GAMMA2 as i32);
        assert_eq!(DILITHIUM3.omega, OMEGA as usize);

        assert_eq!(DILITHIUM3.t1_poly_packed_len, POLYT1_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM3.t0_poly_packed_len, POLYT0_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM3.z_poly_packed_len, POLYZ_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM3.w1_poly_packed_len, POLYW1_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM3.eta_poly_packed_len, POLYETA_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM3.public_key_len, CRYPTO_PUBLICKEYBYTES as usize);
        assert_eq!(DILITHIUM3.secret_key_len, CRYPTO_SECRETKEYBYTES as usize);
        assert_eq!(DILITHIUM3.signature_len, CRYPTO_BYTES as usize);
    }

    #[test]
    fn test_dilithium5_params_ref() {
        use refimpl::dilithium5::*;

        assert_eq!(DILITHIUM5.k, K as usize);
        assert_eq!(DILITHIUM5.l, L as usize);
        assert_eq!(DILITHIUM5.eta, ETA as i32);
        assert_eq!(DILITHIUM5.tau, TAU as u8);
        assert_eq!(DILITHIUM5.beta, BETA as i32);
        assert_eq!(DILITHIUM5.gamma1, GAMMA1 as i32);
        assert_eq!(DILITHIUM5.gamma2, GAMMA2 as i32);
        assert_eq!(DILITHIUM5.omega, OMEGA as usize);

        assert_eq!(DILITHIUM5.t1_poly_packed_len, POLYT1_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM5.t0_poly_packed_len, POLYT0_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM5.z_poly_packed_len, POLYZ_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM5.w1_poly_packed_len, POLYW1_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM5.eta_poly_packed_len, POLYETA_PACKEDBYTES as usize);
        assert_eq!(DILITHIUM5.public_key_len, CRYPTO_PUBLICKEYBYTES as usize);
        assert_eq!(DILITHIUM5.secret_key_len, CRYPTO_SECRETKEYBYTES as usize);
        assert_eq!(DILITHIUM5.signature_len, CRYPTO_BYTES as usize);
    }
}
