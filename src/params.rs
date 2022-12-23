use core::marker::PhantomData;

use crate::variants::DilithiumVariant;

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
    // Impl-dependent functions
    // expand_mask: fn(rho_prime: &[u8], kappa: u16) -> TY::Poly,
}

pub(crate) const DILITHIUM2: DilithiumImpl = DilithiumImpl {
    k: 4,
    l: 4,
    max_attempts: 331,
    // expand_mask,
};

pub(crate) const DILITHIUM3: DilithiumImpl = DilithiumImpl {
    k: 6,
    l: 5,
    max_attempts: 406,
    // expand_mask,
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
