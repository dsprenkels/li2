pub const SEED_LENGTH: usize = 32;

trait KeyGen {
    fn generate_from_seed(seed: &[u8]) -> Self;
}

#[cold]
fn secret_key_debug_fmt(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("SecretKey")
        .field("bytes", b"[hidden]")
        .finish()
}

macro_rules! dilithium_variant {
    () => {
        #[derive(Clone)]
        pub struct SecretKey {
            pub(crate) bytes: [u8; SECRET_KEY_LENGTH],
        }

        impl core::fmt::Debug for SecretKey {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                super::secret_key_debug_fmt(f)
            }
        }

        impl AsRef<[u8]> for SecretKey {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl<'a> TryFrom<&'a [u8]> for SecretKey {
            type Error = signature::Error;

            fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
                if bytes.len() != SECRET_KEY_LENGTH {
                    return Err(Default::default());
                }
                let mut arr = [0; SECRET_KEY_LENGTH];
                arr.copy_from_slice(bytes);
                Ok(Self { bytes: arr })
            }
        }

        #[derive(Clone, Debug)]
        pub struct PublicKey {
            pub(crate) bytes: [u8; PUBLIC_KEY_LENGTH],
        }

        impl AsRef<[u8]> for PublicKey {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl<'a> TryFrom<&'a [u8]> for PublicKey {
            type Error = signature::Error;

            fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
                if bytes.len() != PUBLIC_KEY_LENGTH {
                    return Err(Default::default());
                }
                let mut arr = [0; PUBLIC_KEY_LENGTH];
                arr.copy_from_slice(bytes);
                Ok(Self { bytes: arr })
            }
        }

        #[derive(Clone, Debug)]
        pub struct Keypair {
            pub secret: SecretKey,
            pub public: PublicKey,
        }

        #[derive(Clone, Debug)]
        pub struct Signature {
            pub bytes: [u8; SIGNATURE_LENGTH],
        }

        impl AsRef<[u8]> for Signature {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl<'a> TryFrom<&'a [u8]> for Signature {
            type Error = signature::Error;

            fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
                if bytes.len() != SIGNATURE_LENGTH {
                    return Err(Default::default());
                }
                let mut arr = [0; SIGNATURE_LENGTH];
                arr.copy_from_slice(bytes);
                Ok(Self { bytes: arr })
            }
        }

        impl signature::Signature for Signature {
            fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
                bytes.try_into()
            }
        }
    };
}

pub mod dilithium2 {
    use crate::dilithium;

    pub use super::SEED_LENGTH;

    pub const SECRET_KEY_LENGTH: usize = 2528;
    pub const PUBLIC_KEY_LENGTH: usize = 1312;
    pub const SIGNATURE_LENGTH: usize = 2420;

    dilithium_variant! {}

    impl SecretKey {
        fn new() -> Self {
            Self {
                bytes: [0; SECRET_KEY_LENGTH],
            }
        }
    }
    impl PublicKey {
        fn new() -> Self {
            Self {
                bytes: [0; PUBLIC_KEY_LENGTH],
            }
        }
    }

    impl Keypair {
        fn new() -> Self {
            Self {
                secret: SecretKey::new(),
                public: PublicKey::new(),
            }
        }

        pub fn generate_from_seed(seed: &[u8]) -> Result<Self, crate::Error> {
            let mut keypair = Self::new();
            dilithium::dilithium2_keygen_from_seed(&mut keypair, seed)?;
            Ok(keypair)
        }
    }

    impl signature::Signer<Signature> for SecretKey {
        fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
            dilithium::dilithium2_signature(self, msg)
        }
    }

    impl signature::Verifier<Signature> for PublicKey {
        fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
            dilithium::dilithium2_verify(self, msg, signature)
        }
    }
}

pub mod dilithium3 {
    use crate::dilithium;

    pub use super::SEED_LENGTH;

    pub const SECRET_KEY_LENGTH: usize = 4000;
    pub const PUBLIC_KEY_LENGTH: usize = 1952;
    pub const SIGNATURE_LENGTH: usize = 3293;

    dilithium_variant! {}

    impl SecretKey {
        fn new() -> Self {
            Self {
                bytes: [0; SECRET_KEY_LENGTH],
            }
        }
    }
    impl PublicKey {
        fn new() -> Self {
            Self {
                bytes: [0; PUBLIC_KEY_LENGTH],
            }
        }
    }

    impl Keypair {
        fn new() -> Self {
            Self {
                secret: SecretKey::new(),
                public: PublicKey::new(),
            }
        }

        pub fn generate_from_seed(seed: &[u8]) -> Result<Self, crate::Error> {
            let mut keypair = Self::new();
            dilithium::dilithium3_keygen_from_seed(&mut keypair, seed)?;
            Ok(keypair)
        }
    }

    impl signature::Signer<Signature> for SecretKey {
        fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
            dilithium::dilithium3_signature(self, msg)
        }
    }

    impl signature::Verifier<Signature> for PublicKey {
        fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
            dilithium::dilithium3_verify(self, msg, signature)
        }
    }
}

pub mod dilithium5 {
    use crate::dilithium;

    pub use super::SEED_LENGTH;

    pub const SECRET_KEY_LENGTH: usize = 4864;
    pub const PUBLIC_KEY_LENGTH: usize = 2592;
    pub const SIGNATURE_LENGTH: usize = 4595;

    dilithium_variant! {}

    impl SecretKey {
        fn new() -> Self {
            Self {
                bytes: [0; SECRET_KEY_LENGTH],
            }
        }
    }
    impl PublicKey {
        fn new() -> Self {
            Self {
                bytes: [0; PUBLIC_KEY_LENGTH],
            }
        }
    }

    impl Keypair {
        fn new() -> Self {
            Self {
                secret: SecretKey::new(),
                public: PublicKey::new(),
            }
        }

        pub fn generate_from_seed(seed: &[u8]) -> Result<Self, crate::Error> {
            let mut keypair = Self::new();
            dilithium::dilithium5_keygen_from_seed(&mut keypair, seed)?;
            Ok(keypair)
        }
    }

    impl signature::Signer<Signature> for SecretKey {
        fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
            dilithium::dilithium5_signature(self, msg)
        }
    }

    impl signature::Verifier<Signature> for PublicKey {
        fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
            dilithium::dilithium5_verify(self, msg, signature)
        }
    }
}
