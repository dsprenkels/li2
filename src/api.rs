//! # TODO
//!
//! At this point, the lifetimes of the keys may outlast the lifetimes of
//! the slices from which they were decoded.  This will prevent us from doing
//! a very-low memory implementation of Dilithium, because either we have to
//! copy the keys to a buffer somewhere, or we have to decode the key
//! immediately; both of which will take up a lot of space.
//!
//! We will have to add a generic lifetime to the type signature s.t. we can
//! have keys that are outlived by the buffer on which they are based.

pub use signature;

use crate::dilithium;

/// `DilithiumVariant` specifies the variant of Dilithium.  The variant
/// specifies which algorithm is executed from a high level.  For example:
/// 'Randomized NIST-round-3 Dilithium2'.
///
/// This trait does not indicate anything about the inner workings of the
/// implementation.  The same `DilithiumVariant` is used, regardless of
/// the platform is it compiled for.
pub trait DilithiumVariant: core::fmt::Debug {
    /// Size of the seed that generates a secret key.
    const SEED_SIZE: usize = 32;
    const SECKEY_SIZE: usize;
    const PUBKEY_SIZE: usize;
    const SIG_SIZE: usize;

    type SecretKeyBytes: AsMut<[u8]> + AsRef<[u8]> + core::fmt::Debug;
    type PublicKeyBytes: AsMut<[u8]> + AsRef<[u8]> + core::fmt::Debug;
    type SignatureBytes: AsMut<[u8]> + AsRef<[u8]> + core::fmt::Debug;

    type SecretKey: signature::Signer<Self::Signature>;
    type PublicKey: signature::Verifier<Self::Signature>;
    type Signature: signature::Signature;

    fn new_secretkey_bytes() -> Self::SecretKeyBytes;
    fn new_publickey_bytes() -> Self::PublicKeyBytes;
    fn new_signature_bytes() -> Self::SignatureBytes;

    fn keygen_from_seed(seed: &[u8]) -> Result<(Self::SecretKey, Self::PublicKey), crate::Error>;
}

#[derive(Debug)]
pub struct SecretKey<V: DilithiumVariant> {
    pub(crate) bytes: V::SecretKeyBytes,
}

impl<V: DilithiumVariant> AsRef<[u8]> for SecretKey<V> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes.as_ref()
    }
}

// TODO: Move this declaration to lib.rs
#[derive(Debug)]
pub struct PublicKey<V: DilithiumVariant> {
    pub(crate) bytes: V::PublicKeyBytes,
}

impl<V: DilithiumVariant> AsRef<[u8]> for PublicKey<V> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes.as_ref()
    }
}

// TODO: Move this declaration to lib.rs
#[derive(Debug)]
pub struct Signature<V: DilithiumVariant> {
    // TODO: This should not be a bag of bytes; decode the signature when
    // Signature::from_bytes() is called.
    pub(crate) bytes: V::SignatureBytes,
}

impl<V: DilithiumVariant> AsRef<[u8]> for Signature<V> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes.as_ref()
    }
}

impl<V: DilithiumVariant> signature::Signature for Signature<V> {
    #[inline]
    fn from_bytes(src: &[u8]) -> Result<Self, signature::Error> {
        if src.len() == V::SIG_SIZE {
            let mut bytes = V::new_signature_bytes();
            bytes.as_mut().copy_from_slice(src);
            Ok(Signature { bytes })
        } else {
            Err(Default::default())
        }
    }
}

#[derive(Debug)]
pub struct Dilithium2;
#[derive(Debug)]
pub struct Dilithium3;
#[derive(Debug)]
pub struct Dilithium5;

macro_rules! DilithiumVariant_impl {
    () => {
        type SecretKeyBytes = [u8; Self::SECKEY_SIZE];
        type PublicKeyBytes = [u8; Self::PUBKEY_SIZE];
        type SignatureBytes = [u8; Self::SIG_SIZE];

        type SecretKey = SecretKey<Self>;
        type PublicKey = PublicKey<Self>;
        type Signature = Signature<Self>;

        fn new_secretkey_bytes() -> Self::SecretKeyBytes {
            [0; Self::SECKEY_SIZE]
        }
        fn new_publickey_bytes() -> Self::PublicKeyBytes {
            [0; Self::PUBKEY_SIZE]
        }
        fn new_signature_bytes() -> Self::SignatureBytes {
            [0; Self::SIG_SIZE]
        }
    };
}

impl DilithiumVariant for Dilithium2 {
    const SECKEY_SIZE: usize = 2528;
    const PUBKEY_SIZE: usize = 1312;
    const SIG_SIZE: usize = 2420;

    DilithiumVariant_impl! {}

    fn keygen_from_seed(seed: &[u8]) -> Result<(Self::SecretKey, Self::PublicKey), crate::Error> {
        dilithium::dilithium2_keygen_from_seed(seed)
    }
}

impl signature::Signer<Signature<Dilithium2>> for SecretKey<Dilithium2> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<Dilithium2>, signature::Error> {
        dilithium::dilithium2_signature(self, msg).map_err(|_| Default::default())
    }
}

impl signature::Verifier<Signature<Dilithium2>> for PublicKey<Dilithium2> {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature<Dilithium2>,
    ) -> Result<(), signature::Error> {
        dilithium::dilithium2_verify(self, msg, signature).map_err(|_| Default::default())
    }
}

impl DilithiumVariant for Dilithium3 {
    const SECKEY_SIZE: usize = 4000;
    const PUBKEY_SIZE: usize = 1952;
    const SIG_SIZE: usize = 3293;

    DilithiumVariant_impl! {}

    fn keygen_from_seed(seed: &[u8]) -> Result<(Self::SecretKey, Self::PublicKey), crate::Error> {
        dilithium::dilithium3_keygen_from_seed(seed)
    }
}

impl signature::Signer<Signature<Dilithium3>> for SecretKey<Dilithium3> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<Dilithium3>, signature::Error> {
        dilithium::dilithium3_signature(self, msg).map_err(|_| Default::default())
    }
}

impl signature::Verifier<Signature<Dilithium3>> for PublicKey<Dilithium3> {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature<Dilithium3>,
    ) -> Result<(), signature::Error> {
        dilithium::dilithium3_verify(self, msg, signature).map_err(|_| Default::default())
    }
}

impl DilithiumVariant for Dilithium5 {
    const SECKEY_SIZE: usize = 4864;
    const PUBKEY_SIZE: usize = 2592;
    const SIG_SIZE: usize = 4595;

    DilithiumVariant_impl! {}

    fn keygen_from_seed(seed: &[u8]) -> Result<(Self::SecretKey, Self::PublicKey), crate::Error> {
        dilithium::dilithium5_keygen_from_seed(seed)
    }
}

impl signature::Signer<Signature<Dilithium5>> for SecretKey<Dilithium5> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<Dilithium5>, signature::Error> {
        dilithium::dilithium5_signature(self, msg).map_err(|_| Default::default())
    }
}

impl signature::Verifier<Signature<Dilithium5>> for PublicKey<Dilithium5> {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature<Dilithium5>,
    ) -> Result<(), signature::Error> {
        dilithium::dilithium5_verify(self, msg, signature).map_err(|_| Default::default())
    }
}
