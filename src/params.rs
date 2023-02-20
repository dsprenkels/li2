use crystals_dilithium_sys::{dilithium2, dilithium3, dilithium5};
// TODO: LEFT HERE
// Put the actual param values in here instead of importing them from the sys
// crate.

pub(crate) const Q: i32 = 8380417;
pub(crate) const N: usize = 256;
pub(crate) const D: u32 = 13;

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

pub(crate) struct DilithiumParams {
    pub(crate) k: usize,
    pub(crate) l: usize,
    pub(crate) max_attempts: u16,
    pub(crate) eta: i32,
    pub(crate) tau: u8,
    pub(crate) beta: i32,
    pub(crate) gamma1: i32,
    pub(crate) gamma2: i32,
    pub(crate) omega: usize,
    pub(crate) polyt1_packedbytes: usize,
    pub(crate) polyt0_packedbytes: usize,
    pub(crate) polyz_packedbytes: usize,
    pub(crate) polyw1_packedbytes: usize,
    pub(crate) polyeta_packedbytes: usize,
    pub(crate) publickeybytes: usize,
    pub(crate) secretkeybytes: usize,
    pub(crate) sigbytes: usize,
}

#[allow(non_snake_case)]
pub(crate) const DILITHIUM2: DilithiumParams = DilithiumParams {
    k: 4,
    l: 4,
    max_attempts: 331,

    eta: dilithium2::ETA as i32,
    tau: dilithium2::TAU as u8,
    beta: dilithium2::BETA as i32,
    gamma1: dilithium2::GAMMA1 as i32,
    gamma2: dilithium2::GAMMA2 as i32,
    omega: dilithium2::OMEGA as usize,
    polyt1_packedbytes: dilithium2::POLYT1_PACKEDBYTES as usize,
    polyt0_packedbytes: dilithium2::POLYT0_PACKEDBYTES as usize,
    polyz_packedbytes: dilithium2::POLYZ_PACKEDBYTES as usize,
    polyw1_packedbytes: dilithium2::POLYW1_PACKEDBYTES as usize,
    polyeta_packedbytes: dilithium2::POLYETA_PACKEDBYTES as usize,
    publickeybytes: dilithium2::CRYPTO_PUBLICKEYBYTES as usize,
    secretkeybytes: dilithium2::CRYPTO_SECRETKEYBYTES as usize,
    sigbytes: dilithium2::CRYPTO_BYTES as usize,
};

#[allow(non_snake_case)]
pub(crate) const DILITHIUM3: DilithiumParams = DilithiumParams {
    k: 6,
    l: 5,
    max_attempts: 406,

    eta: dilithium3::ETA as i32,
    tau: dilithium3::TAU as u8,
    beta: dilithium3::BETA as i32,
    gamma1: dilithium3::GAMMA1 as i32,
    gamma2: dilithium3::GAMMA2 as i32,
    omega: dilithium3::OMEGA as usize,
    polyt1_packedbytes: dilithium3::POLYT1_PACKEDBYTES as usize,
    polyt0_packedbytes: dilithium3::POLYT0_PACKEDBYTES as usize,
    polyz_packedbytes: dilithium3::POLYZ_PACKEDBYTES as usize,
    polyw1_packedbytes: dilithium3::POLYW1_PACKEDBYTES as usize,
    polyeta_packedbytes: dilithium3::POLYETA_PACKEDBYTES as usize,
    publickeybytes: dilithium3::CRYPTO_PUBLICKEYBYTES as usize,
    secretkeybytes: dilithium3::CRYPTO_SECRETKEYBYTES as usize,
    sigbytes: dilithium3::CRYPTO_BYTES as usize,
};

#[allow(non_snake_case)]
pub(crate) const DILITHIUM5: DilithiumParams = DilithiumParams {
    k: 8,
    l: 7,
    max_attempts: 295,

    eta: dilithium5::ETA as i32,
    tau: dilithium5::TAU as u8,
    beta: dilithium5::BETA as i32,
    gamma1: dilithium5::GAMMA1 as i32,
    gamma2: dilithium5::GAMMA2 as i32,
    omega: dilithium5::OMEGA as usize,
    polyt1_packedbytes: dilithium5::POLYT1_PACKEDBYTES as usize,
    polyt0_packedbytes: dilithium5::POLYT0_PACKEDBYTES as usize,
    polyz_packedbytes: dilithium5::POLYZ_PACKEDBYTES as usize,
    polyw1_packedbytes: dilithium5::POLYW1_PACKEDBYTES as usize,
    polyeta_packedbytes: dilithium5::POLYETA_PACKEDBYTES as usize,
    publickeybytes: dilithium5::CRYPTO_PUBLICKEYBYTES as usize,
    secretkeybytes: dilithium5::CRYPTO_SECRETKEYBYTES as usize,
    sigbytes: dilithium5::CRYPTO_BYTES as usize,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crystals_dilithium_sys as refimpl;

    #[test]
    fn test_dilithium2_params() {
        use refimpl::dilithium2::*;

        assert_eq!(DILITHIUM2.k, K as usize);
        assert_eq!(DILITHIUM2.l, L as usize);
    }

    #[test]
    fn test_dilithium3_params() {
        use refimpl::dilithium3::*;

        assert_eq!(DILITHIUM3.k, K as usize);
        assert_eq!(DILITHIUM3.l, L as usize);
    }

    #[test]
    fn test_dilithium5_params() {
        use refimpl::dilithium5::*;

        assert_eq!(DILITHIUM5.k, K as usize);
        assert_eq!(DILITHIUM5.l, L as usize);
    }
}
