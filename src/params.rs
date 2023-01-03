use core::{marker::PhantomData, mem::transmute};

use crate::{api::DilithiumVariant, variants};
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

pub(crate) struct DilithiumParams {
    // Basic parameters
    pub(crate) k: u16,
    pub(crate) l: u16,
    pub(crate) max_attempts: u16,

    pub(crate) K: u32,
    pub(crate) L: u32,
    pub(crate) ETA: u32,
    pub(crate) TAU: u32,
    pub(crate) BETA: u32,
    pub(crate) GAMMA1: u32,
    pub(crate) GAMMA2: u32,
    pub(crate) OMEGA: u32,
    pub(crate) POLYT1_PACKEDBYTES: u32,
    pub(crate) POLYT0_PACKEDBYTES: u32,
    pub(crate) POLYVECH_PACKEDBYTES: u32,
    pub(crate) POLYZ_PACKEDBYTES: u32,
    pub(crate) POLYW1_PACKEDBYTES: u32,
    pub(crate) POLYETA_PACKEDBYTES: u32,
    pub(crate) CRYPTO_PUBLICKEYBYTES: u32,
    pub(crate) CRYPTO_SECRETKEYBYTES: u32,
    pub(crate) CRYPTO_BYTES: u32,

    pub(crate) variant: &'static dyn variants::DilithiumVariant,

}

#[allow(non_snake_case)]
pub(crate) const DILITHIUM2: DilithiumParams = DilithiumParams {
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

    variant: &variants::Dilithium2,
};

#[allow(non_snake_case)]
pub(crate) const DILITHIUM3: DilithiumParams = DilithiumParams {
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

    variant: &variants::Dilithium3,
};


#[allow(non_snake_case)]
pub(crate) const DILITHIUM5: DilithiumParams = DilithiumParams {
    k: 8,
    l: 7,
    max_attempts: 295,
    
    K: dilithium5::K,
    L: dilithium5::L,
    ETA: dilithium5::ETA,
    TAU: dilithium5::TAU,
    BETA: dilithium5::BETA,
    GAMMA1: dilithium5::GAMMA1,
    GAMMA2: dilithium5::GAMMA2,
    OMEGA: dilithium5::OMEGA,
    POLYT1_PACKEDBYTES: dilithium5::POLYT1_PACKEDBYTES,
    POLYT0_PACKEDBYTES: dilithium5::POLYT0_PACKEDBYTES,
    POLYVECH_PACKEDBYTES: dilithium5::POLYVECH_PACKEDBYTES,
    POLYZ_PACKEDBYTES: dilithium5::POLYZ_PACKEDBYTES,
    POLYW1_PACKEDBYTES: dilithium5::POLYW1_PACKEDBYTES,
    POLYETA_PACKEDBYTES: dilithium5::POLYETA_PACKEDBYTES,
    CRYPTO_PUBLICKEYBYTES: dilithium5::CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES: dilithium5::CRYPTO_SECRETKEYBYTES,
    CRYPTO_BYTES: dilithium5::CRYPTO_BYTES,

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
