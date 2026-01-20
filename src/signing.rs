use crate::errors::SigningMethodError;
use crate::key::Key;
use ed25519_dalek::{Signer as EdSigner, Verifier as EdVerifier};
use hmac::{Hmac, Mac};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::SignatureEncoding;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

/// SigningMethod signs and verifies PWT payloads.
pub trait SigningMethod: Send + Sync {
    fn alg(&self) -> &'static str;
    fn sign(&self, data: &[u8], key: &Key) -> Result<Vec<u8>, SigningMethodError>;
    fn verify(&self, data: &[u8], signature: &[u8], key: &Key) -> Result<(), SigningMethodError>;
}

/// SigningMethodHS256 implements HMAC-SHA256 signing.
#[derive(Debug, Default)]
pub struct SigningMethodHS256;

impl SigningMethodHS256 {
    pub fn new() -> Self {
        Self
    }
}

impl SigningMethod for SigningMethodHS256 {
    fn alg(&self) -> &'static str {
        "HS256"
    }

    fn sign(&self, data: &[u8], key: &Key) -> Result<Vec<u8>, SigningMethodError> {
        let secret = match key {
            Key::Bytes(bytes) => bytes.as_slice(),
            _ => return Err(SigningMethodError::InvalidKeyType),
        };

        let mut mac = Hmac::<Sha256>::new_from_slice(secret)
            .map_err(|err| SigningMethodError::CryptoError(err.to_string()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], key: &Key) -> Result<(), SigningMethodError> {
        let expected = self.sign(data, key)?;
        if expected.as_slice() == signature {
            Ok(())
        } else {
            Err(SigningMethodError::InvalidSignature)
        }
    }
}

/// SigningMethodEdDSA implements Ed25519 signing.
#[derive(Debug, Default)]
pub struct SigningMethodEdDSA;

impl SigningMethodEdDSA {
    pub fn new() -> Self {
        Self
    }
}

impl SigningMethod for SigningMethodEdDSA {
    fn alg(&self) -> &'static str {
        "EdDSA"
    }

    fn sign(&self, data: &[u8], key: &Key) -> Result<Vec<u8>, SigningMethodError> {
        let signing_key = match key {
            Key::Ed25519Private(key) => key.clone(),
            Key::Bytes(bytes) => parse_ed25519_private(bytes)?,
            _ => return Err(SigningMethodError::InvalidKeyType),
        };

        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], key: &Key) -> Result<(), SigningMethodError> {
        let verifying_key = match key {
            Key::Ed25519Public(key) => key.clone(),
            Key::Bytes(bytes) => parse_ed25519_public(bytes)?,
            _ => return Err(SigningMethodError::InvalidKeyType),
        };

        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|err| SigningMethodError::CryptoError(err.to_string()))?;
        verifying_key
            .verify(data, &signature)
            .map_err(|_| SigningMethodError::InvalidSignature)
    }
}

/// SigningMethodRS256 implements RSA SHA-256 signing.
#[derive(Debug, Default)]
pub struct SigningMethodRS256;

impl SigningMethodRS256 {
    pub fn new() -> Self {
        Self
    }
}

impl SigningMethod for SigningMethodRS256 {
    fn alg(&self) -> &'static str {
        "RS256"
    }

    fn sign(&self, data: &[u8], key: &Key) -> Result<Vec<u8>, SigningMethodError> {
        let private_key = match key {
            Key::RsaPrivate(key) => key.clone(),
            Key::Bytes(bytes) => parse_rsa_private(bytes)?,
            _ => return Err(SigningMethodError::InvalidKeyType),
        };

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign(data);
        Ok(signature.to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], key: &Key) -> Result<(), SigningMethodError> {
        let public_key = match key {
            Key::RsaPublic(key) => key.clone(),
            Key::Bytes(bytes) => parse_rsa_public(bytes)?,
            _ => return Err(SigningMethodError::InvalidKeyType),
        };

        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let signature = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|err| SigningMethodError::CryptoError(err.to_string()))?;

        verifying_key
            .verify(data, &signature)
            .map_err(|_| SigningMethodError::InvalidSignature)
    }
}

/// SigningMethodRegistry stores available signing methods.
#[derive(Debug)]
pub struct SigningMethodRegistry;

impl SigningMethodRegistry {
    pub fn register(method: Arc<dyn SigningMethod>) {
        let store = registry();
        let mut guard = store.write().expect("signing method registry lock");
        guard.insert(method.alg().to_string(), method);
    }

    pub fn method(alg: &str) -> Option<Arc<dyn SigningMethod>> {
        let store = registry();
        let guard = store.read().expect("signing method registry lock");
        guard.get(alg).cloned()
    }
}

fn registry() -> &'static RwLock<HashMap<String, Arc<dyn SigningMethod>>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, Arc<dyn SigningMethod>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut methods: HashMap<String, Arc<dyn SigningMethod>> = HashMap::new();
        methods.insert("HS256".to_string(), Arc::new(SigningMethodHS256::new()));
        methods.insert("EdDSA".to_string(), Arc::new(SigningMethodEdDSA::new()));
        methods.insert("RS256".to_string(), Arc::new(SigningMethodRS256::new()));
        RwLock::new(methods)
    })
}

fn parse_ed25519_private(bytes: &[u8]) -> Result<ed25519_dalek::SigningKey, SigningMethodError> {
    match bytes.len() {
        32 => {
            let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                SigningMethodError::KeyParseError("invalid ed25519 key".to_string())
            })?;
            Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
        }
        64 => {
            let key_bytes: [u8; 64] = bytes.try_into().map_err(|_| {
                SigningMethodError::KeyParseError("invalid ed25519 key".to_string())
            })?;
            ed25519_dalek::SigningKey::from_keypair_bytes(&key_bytes)
                .map_err(|err| SigningMethodError::KeyParseError(err.to_string()))
        }
        _ => Err(SigningMethodError::KeyParseError(
            "ed25519 private key must be 32 or 64 bytes".to_string(),
        )),
    }
}

fn parse_ed25519_public(bytes: &[u8]) -> Result<ed25519_dalek::VerifyingKey, SigningMethodError> {
    match bytes.len() {
        32 => {
            let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                SigningMethodError::KeyParseError("invalid ed25519 key".to_string())
            })?;
            ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
                .map_err(|err| SigningMethodError::KeyParseError(err.to_string()))
        }
        64 => {
            let key_bytes: [u8; 64] = bytes.try_into().map_err(|_| {
                SigningMethodError::KeyParseError("invalid ed25519 key".to_string())
            })?;
            let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&key_bytes)
                .map_err(|err| SigningMethodError::KeyParseError(err.to_string()))?;
            Ok(signing_key.verifying_key())
        }
        _ => Err(SigningMethodError::KeyParseError(
            "ed25519 public key must be 32 or 64 bytes".to_string(),
        )),
    }
}

fn parse_rsa_private(bytes: &[u8]) -> Result<RsaPrivateKey, SigningMethodError> {
    if let Ok(key) = RsaPrivateKey::from_pkcs1_der(bytes) {
        return Ok(key);
    }

    if let Ok(key) = RsaPrivateKey::from_pkcs8_der(bytes) {
        return Ok(key);
    }

    Err(SigningMethodError::KeyParseError(
        "failed to parse rsa private key".to_string(),
    ))
}

fn parse_rsa_public(bytes: &[u8]) -> Result<RsaPublicKey, SigningMethodError> {
    if let Ok(key) = RsaPublicKey::from_pkcs1_der(bytes) {
        return Ok(key);
    }

    if let Ok(key) = RsaPublicKey::from_public_key_der(bytes) {
        return Ok(key);
    }

    Err(SigningMethodError::KeyParseError(
        "failed to parse rsa public key".to_string(),
    ))
}
