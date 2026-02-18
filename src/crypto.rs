use std::fmt;

use ed25519_dalek::ed25519::signature::Verifier as _;
use sha2::{Digest, Sha256};

pub(crate) const HASH_SIZE: usize = 32;
pub(crate) const PUBKEY_SIZE: usize = 32;
pub(crate) const SIGNATURE_SIZE: usize = 64;

/// An Ed25519 public key.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct PublicKey {
    bytes: [u8; PUBKEY_SIZE],
}

impl PublicKey {
    /// Verify that `sig` is a valid signature on `data` from this key.
    pub fn verify_signature(&self, data: impl AsRef<[u8]>, sig: &Signature) -> bool {
        let Ok(verifier) = ed25519_dalek::VerifyingKey::from_bytes(&self.bytes) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from(&sig.bytes);
        verifier.verify(data.as_ref(), &signature).is_ok()
    }
}

/// An Ed25519 signature.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Signature {
    bytes: [u8; SIGNATURE_SIZE],
}

/// A SHA256 digest.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Hash {
    bytes: [u8; HASH_SIZE],
}

impl Hash {
    /// Create a new Hash value by hashing the input data.
    pub fn new(data: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: Sha256::digest(data).into(),
        }
    }
}

macro_rules! boilerplate {
    ( $type:ident, $size:literal ) => {
        impl fmt::LowerHex for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for b in self.bytes {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }

        impl From<[u8; $size]> for $type {
            fn from(bytes: [u8; $size]) -> Self {
                Self { bytes }
            }
        }

        impl From<$type> for [u8; $size] {
            fn from(v: $type) -> Self {
                v.bytes
            }
        }

        impl AsRef<[u8]> for $type {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, stringify!($type))?;
                write!(f, "({:x})", self)
            }
        }
    };
}

boilerplate!(Hash, 32);
boilerplate!(PublicKey, 32);
boilerplate!(Signature, 64);

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn hash_new() {
        assert_eq!(
            Hash {
                bytes: hex!("5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953")
            },
            Hash::new([0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn hash_lowerhex() {
        assert_eq!(
            "abababababababababababababababababababababababababababababababab",
            format!("{:x}", Hash { bytes: [0xAB; 32] })
        );
    }

    #[test]
    fn publickey_lowerhex() {
        assert_eq!(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            format!("{:x}", PublicKey { bytes: [0xCD; 32] })
        );
    }

    #[test]
    fn signature_lowerhex() {
        assert_eq!(
            "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
            format!("{:x}", Signature{bytes:[0xEF; 64]})
        );
    }

    #[test]
    fn hash_debug() {
        assert_eq!(
            "Hash(abababababababababababababababababababababababababababababababab)",
            format!("{:?}", Hash { bytes: [0xAB; 32] })
        );
    }

    #[test]
    fn publickey_debug() {
        assert_eq!(
            "PublicKey(cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd)",
            format!("{:?}", PublicKey { bytes: [0xCD; 32] })
        );
    }

    #[test]
    fn signature_debug() {
        assert_eq!(
            "Signature(efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef)",
            format!("{:?}", Signature{bytes:[0xEF; 64]})
        );
    }

    #[test]
    fn publickey_verify_signature_ok() {
        let data = b"Time is an illusion. Lunchtime doubly so.";
        let signature :Signature= hex!("b115534da664b0d98e307f6562cf2304921e74d82a25b0a8c034fc46560257716f62d09eab1e8dcac09ffb675285d10bff5f0d650899d5236b51291d6f674607").into();
        let pubkey: PublicKey =
            hex!("ed9cdbc8d80d93ec12581be61413b5fdba1cda57f1cde986ef9e83f0558e7e67").into();
        assert!(pubkey.verify_signature(data, &signature));
    }

    #[test]
    fn publickey_verify_signature_nok() {
        let data = b"Time is an illusion. Lunchtime doubly so.";
        let signature :Signature= hex!("0115534da664b0d98e307f6562cf2304921e74d82a25b0a8c034fc46560257716f62d09eab1e8dcac09ffb675285d10bff5f0d650899d5236b51291d6f674607").into();
        let pubkey: PublicKey =
            hex!("ed9cdbc8d80d93ec12581be61413b5fdba1cda57f1cde986ef9e83f0558e7e67").into();
        assert!(!pubkey.verify_signature(data, &signature));
    }

    /// This test checks that with a key that does not pass the
    /// ed25519_dalek::VerifyingKey::from_bytes verification,
    /// returns false and does not panic or return true.
    #[test]
    fn publickey_verify_signature_invalid_key() {
        let data = b"Time is an illusion. Lunchtime doubly so.";
        let signature :Signature= hex!("b115534da664b0d98e307f6562cf2304921e74d82a25b0a8c034fc46560257716f62d09eab1e8dcac09ffb675285d10bff5f0d650899d5236b51291d6f674607").into();
        // This public key does not pass the dalek key verification
        let pubkey: PublicKey =
            hex!("95fbfdc65f4a1c92469440b3fb23cefefe9f26d86057b805243c607ec7eb4f7b").into();
        assert!(!pubkey.verify_signature(data, &signature));
    }
}
