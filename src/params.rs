use core::{marker::PhantomData, mem::transmute};

use crate::{api::DilithiumVariant, variants};
use crystals_dilithium_sys::{dilithium2, dilithium3, dilithium5};

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
    // Basic parameters
    pub(crate) k: usize,
    pub(crate) l: usize,
    pub(crate) max_attempts: u16,

    pub(crate) ETA: i32,
    pub(crate) TAU: u8,
    pub(crate) BETA: i32,
    pub(crate) GAMMA1: i32,
    pub(crate) GAMMA2: i32,
    pub(crate) OMEGA: u32,
    pub(crate) POLYT1_PACKEDBYTES: usize,
    pub(crate) POLYT0_PACKEDBYTES: usize,
    pub(crate) POLYVECH_PACKEDBYTES: usize,
    pub(crate) POLYZ_PACKEDBYTES: usize,
    pub(crate) POLYW1_PACKEDBYTES: usize,
    pub(crate) POLYETA_PACKEDBYTES: usize,
    pub(crate) CRYPTO_PUBLICKEYBYTES: usize,
    pub(crate) CRYPTO_SECRETKEYBYTES: usize,
    pub(crate) CRYPTO_BYTES: usize,

    pub(crate) variant: &'static dyn variants::DilithiumVariant,
}

#[allow(non_snake_case)]
pub(crate) const DILITHIUM2: DilithiumParams = DilithiumParams {
    k: 4,
    l: 4,
    max_attempts: 331,

    ETA: dilithium2::ETA as i32,
    TAU: dilithium2::TAU as u8,
    BETA: dilithium2::BETA as i32,
    GAMMA1: dilithium2::GAMMA1 as i32,
    GAMMA2: dilithium2::GAMMA2 as i32,
    OMEGA: dilithium2::OMEGA,
    POLYT1_PACKEDBYTES: dilithium2::POLYT1_PACKEDBYTES as usize,
    POLYT0_PACKEDBYTES: dilithium2::POLYT0_PACKEDBYTES as usize,
    POLYVECH_PACKEDBYTES: dilithium2::POLYVECH_PACKEDBYTES as usize,
    POLYZ_PACKEDBYTES: dilithium2::POLYZ_PACKEDBYTES as usize,
    POLYW1_PACKEDBYTES: dilithium2::POLYW1_PACKEDBYTES as usize,
    POLYETA_PACKEDBYTES: dilithium2::POLYETA_PACKEDBYTES as usize,
    CRYPTO_PUBLICKEYBYTES: dilithium2::CRYPTO_PUBLICKEYBYTES as usize,
    CRYPTO_SECRETKEYBYTES: dilithium2::CRYPTO_SECRETKEYBYTES as usize,
    CRYPTO_BYTES: dilithium2::CRYPTO_BYTES as usize,

    variant: &variants::Dilithium2,
};

#[allow(non_snake_case)]
pub(crate) const DILITHIUM3: DilithiumParams = DilithiumParams {
    k: 6,
    l: 5,
    max_attempts: 406,

    ETA: dilithium3::ETA as i32,
    TAU: dilithium3::TAU as u8,
    BETA: dilithium3::BETA as i32,
    GAMMA1: dilithium3::GAMMA1 as i32,
    GAMMA2: dilithium3::GAMMA2 as i32,
    OMEGA: dilithium3::OMEGA,
    POLYT1_PACKEDBYTES: dilithium3::POLYT1_PACKEDBYTES as usize,
    POLYT0_PACKEDBYTES: dilithium3::POLYT0_PACKEDBYTES as usize,
    POLYVECH_PACKEDBYTES: dilithium3::POLYVECH_PACKEDBYTES as usize,
    POLYZ_PACKEDBYTES: dilithium3::POLYZ_PACKEDBYTES as usize,
    POLYW1_PACKEDBYTES: dilithium3::POLYW1_PACKEDBYTES as usize,
    POLYETA_PACKEDBYTES: dilithium3::POLYETA_PACKEDBYTES as usize,
    CRYPTO_PUBLICKEYBYTES: dilithium3::CRYPTO_PUBLICKEYBYTES as usize,
    CRYPTO_SECRETKEYBYTES: dilithium3::CRYPTO_SECRETKEYBYTES as usize,
    CRYPTO_BYTES: dilithium3::CRYPTO_BYTES as usize,

    variant: &variants::Dilithium3,
};

#[allow(non_snake_case)]
pub(crate) const DILITHIUM5: DilithiumParams = DilithiumParams {
    k: 8,
    l: 7,
    max_attempts: 295,

    ETA: dilithium5::ETA as i32,
    TAU: dilithium5::TAU as u8,
    BETA: dilithium5::BETA as i32,
    GAMMA1: dilithium5::GAMMA1 as i32,
    GAMMA2: dilithium5::GAMMA2 as i32,
    OMEGA: dilithium5::OMEGA,
    POLYT1_PACKEDBYTES: dilithium5::POLYT1_PACKEDBYTES as usize,
    POLYT0_PACKEDBYTES: dilithium5::POLYT0_PACKEDBYTES as usize,
    POLYVECH_PACKEDBYTES: dilithium5::POLYVECH_PACKEDBYTES as usize,
    POLYZ_PACKEDBYTES: dilithium5::POLYZ_PACKEDBYTES as usize,
    POLYW1_PACKEDBYTES: dilithium5::POLYW1_PACKEDBYTES as usize,
    POLYETA_PACKEDBYTES: dilithium5::POLYETA_PACKEDBYTES as usize,
    CRYPTO_PUBLICKEYBYTES: dilithium5::CRYPTO_PUBLICKEYBYTES as usize,
    CRYPTO_SECRETKEYBYTES: dilithium5::CRYPTO_SECRETKEYBYTES as usize,
    CRYPTO_BYTES: dilithium5::CRYPTO_BYTES as usize,

    variant: &variants::Dilithium5,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crystals_dilithium_sys as refimpl;

    #[test]
    #[ignore = "still rapidly developing impl"]
    fn test_vtable_size() {
        assert_eq!(core::mem::size_of::<DilithiumParams>(), 0);
    }

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
