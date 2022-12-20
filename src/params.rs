const N: usize = 256;

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
    k: u8,
    l: u8,
    max_attempts: u16,

    // Impl-dependent functions
    // expand_mask: fn(rho_prime: &[u8], kappa: u16) -> TY::Poly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtable_size() {
        assert_eq!(core::mem::size_of::<DilithiumImpl>(), 40);
    }
}

// const DILTIHIUM2: DilithiumImpl<GenericTypes> = DilithiumImpl {
//     k: 4,
//     l: 4,
//     max_attempts: 331,

//     expand_mask,
// };

const DILTIHIUM3: DilithiumImpl = DilithiumImpl {
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
