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

pub use crypto::signature;

/// `DilithiumVariant` specifies the variant of Dilithium.  The variant
/// specifies which algorithm is executed from a high level.  For example:
/// 'Randomized NIST-round-3 Dilithium2'.
/// 
/// This trait does not indicate anything about the inner workings of the
/// implementation.  The same `DilithiumVariant` is used, regardless of
/// the platform is it compiled for.
pub trait DilithiumVariant {
    type SecretKey: signature::Signer<Self::Signature>;
    type PublicKey: signature::Verifier<Self::Signature>;
    type Signature: signature::Signature;

    const SECKEY_SIZE: usize;
    const PUBKEY_SIZE: usize;
    const SIG_SIZE: usize;
}

struct SecretKey<const SIZE: usize> {
    bytes: [u8; SIZE],
}

impl<const SIZE: usize> AsRef<[u8]> for SecretKey<SIZE> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const SECKEY_SIZE: usize, const SIG_SIZE: usize> signature::Signer<Signature<SIG_SIZE>> for SecretKey<SECKEY_SIZE> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<SIG_SIZE>, signature::Error> {
        todo!()
    }
}

struct PublicKey<const SIZE: usize> {
    bytes: [u8; SIZE],
}

impl<const SIZE: usize> AsRef<[u8]> for PublicKey<SIZE> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const PUBKEY_SIZE: usize, const SIG_SIZE: usize> signature::Verifier<Signature<SIG_SIZE>>
    for PublicKey<PUBKEY_SIZE>
{
    fn verify(&self, msg: &[u8], signature: &Signature<SIG_SIZE>) -> Result<(), signature::Error> {
        todo!()
    }
}

#[derive(Debug)]
struct Signature<const SIZE: usize> {
    // TODO: This should not be a bag of bytes; decode the signature when
    // Signature::from_bytes() is called.
    bytes: [u8; SIZE],
}

impl<const SIZE: usize> AsRef<[u8]> for Signature<SIZE> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const SIG_SIZE: usize> signature::Signature for Signature<SIG_SIZE> {
    fn from_bytes(src: &[u8]) -> Result<Self, signature::Error> {
        if src.len() == SIG_SIZE {
            let mut bytes = [0; SIG_SIZE];
            bytes.copy_from_slice(src);
            Ok(Signature { bytes })
        } else {
            Err(Default::default())
        }
    }
}

#[derive(Debug)]
struct Dilithium2;

impl DilithiumVariant for Dilithium2 {
    const SECKEY_SIZE: usize = 32;
    const PUBKEY_SIZE: usize = 1312;
    const SIG_SIZE: usize = 2420;

    type SecretKey = SecretKey<{ Self::SECKEY_SIZE }>;
    type PublicKey = PublicKey<{ Self::PUBKEY_SIZE }>;
    type Signature = Signature<{ Self::SIG_SIZE }>;
}
