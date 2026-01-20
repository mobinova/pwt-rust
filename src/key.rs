use ed25519_dalek::{SigningKey, VerifyingKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// Key holds supported signing key material.
#[derive(Debug, Clone)]
pub enum Key {
    Bytes(Vec<u8>),
    RsaPrivate(RsaPrivateKey),
    RsaPublic(RsaPublicKey),
    Ed25519Private(SigningKey),
    Ed25519Public(VerifyingKey),
}

impl Key {
    /// from_bytes creates a raw key payload (HMAC secret, DER bytes, etc.).
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self::Bytes(bytes.as_ref().to_vec())
    }

    /// rsa_private wraps an RSA private key.
    pub fn rsa_private(key: RsaPrivateKey) -> Self {
        Self::RsaPrivate(key)
    }

    /// rsa_public wraps an RSA public key.
    pub fn rsa_public(key: RsaPublicKey) -> Self {
        Self::RsaPublic(key)
    }

    /// ed25519_private wraps an Ed25519 signing key.
    pub fn ed25519_private(key: SigningKey) -> Self {
        Self::Ed25519Private(key)
    }

    /// ed25519_public wraps an Ed25519 verifying key.
    pub fn ed25519_public(key: VerifyingKey) -> Self {
        Self::Ed25519Public(key)
    }
}
