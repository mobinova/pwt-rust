mod errors;
mod key;
mod signing;

pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/pwt.rs"));
}

pub use errors::{PwtError, SigningMethodError, TokenValidationError};
pub use key::Key;
pub use signing::{
    SigningMethod, SigningMethodEdDSA, SigningMethodHS256, SigningMethodRS256,
    SigningMethodRegistry,
};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use prost::Message;
use std::sync::Arc;

pub use pb::{TokenBody, TokenHeader};

/// KeyFunc resolves the signing key for the provided token during parsing.
pub type KeyFunc =
    dyn Fn(&Token) -> Result<Key, Box<dyn std::error::Error + Send + Sync>> + Send + Sync;

/// Token is a Protobuf Web Token consisting of a header, body, and signing method.
#[derive(Clone)]
pub struct Token {
    pub header: TokenHeader,
    pub body: TokenBody,
    pub method: Arc<dyn SigningMethod>,
}

impl Token {
    /// new creates a token using version "1.0" with the provided signing method.
    pub fn new<M: SigningMethod + 'static>(method: M, body: TokenBody) -> Self {
        Self::new_with_method(Arc::new(method), body, Some("1.0"))
    }

    /// new_versioned creates a token with the supplied version string.
    pub fn new_versioned<M: SigningMethod + 'static>(
        method: M,
        body: TokenBody,
        version: &str,
    ) -> Self {
        Self::new_with_method(Arc::new(method), body, Some(version))
    }

    /// new_with_claims mirrors jwt.NewWithClaims for compatibility.
    pub fn new_with_claims<M: SigningMethod + 'static>(method: M, body: TokenBody) -> Self {
        Self::new_with_method(Arc::new(method), body, None)
    }

    /// new_with_method creates a token using the provided signing method instance.
    pub fn new_with_method(
        method: Arc<dyn SigningMethod>,
        body: TokenBody,
        version: Option<&str>,
    ) -> Self {
        let mut header = TokenHeader::default();
        if let Some(version) = version {
            header.version = version.to_string();
        }
        header.alg = method.alg().to_string();

        Token {
            header,
            body,
            method,
        }
    }

    /// signed_string marshals the token and returns a signed compact string.
    pub fn signed_string(&self, key: &Key) -> Result<String, PwtError> {
        let header_bytes = encode_proto(&self.header).map_err(PwtError::HeaderEncodingFailed)?;
        let payload_bytes = encode_proto(&self.body).map_err(PwtError::PayloadEncodingFailed)?;
        let signing_data = [header_bytes.as_slice(), payload_bytes.as_slice()].concat();

        let signature = self
            .method
            .sign(&signing_data, key)
            .map_err(PwtError::SigningFailed)?;

        Ok(format!(
            "{}.{}.{}",
            base64_url_encode(&header_bytes),
            base64_url_encode(&payload_bytes),
            base64_url_encode(&signature)
        ))
    }

    /// parse decodes token_string and verifies the signature using key_func.
    pub fn parse(token_string: &str, key_func: Option<&KeyFunc>) -> Result<Self, PwtError> {
        let segments: Vec<&str> = token_string.split('.').collect();
        if segments.len() != 3 {
            return Err(PwtError::InvalidSegmentCount(segments.len()));
        }

        let header_bytes =
            base64_url_decode(segments[0]).map_err(|_| PwtError::Base64DecodingFailed("header"))?;
        let header =
            TokenHeader::decode(header_bytes.as_slice()).map_err(PwtError::HeaderDecodingFailed)?;

        let method = SigningMethodRegistry::method(&header.alg)
            .ok_or_else(|| PwtError::UnsupportedAlgorithm(header.alg.clone()))?;

        let payload_bytes = base64_url_decode(segments[1])
            .map_err(|_| PwtError::Base64DecodingFailed("payload"))?;
        let body =
            TokenBody::decode(payload_bytes.as_slice()).map_err(PwtError::PayloadDecodingFailed)?;

        let key_func = key_func.ok_or(PwtError::KeyFuncNil)?;
        let token = Token {
            header,
            body,
            method: method.clone(),
        };
        let key = key_func(&token).map_err(PwtError::KeyFuncError)?;

        let signature = base64_url_decode(segments[2])
            .map_err(|err| PwtError::SignatureDecodingFailed(Box::new(err)))?;

        let signing_data = [header_bytes.as_slice(), payload_bytes.as_slice()].concat();
        method
            .verify(&signing_data, &signature, &key)
            .map_err(PwtError::SignatureVerificationFailed)?;

        token
            .body
            .valid()
            .map_err(PwtError::TokenValidationFailed)?;

        Ok(token)
    }
}

impl TokenBody {
    /// valid validates time-based claims with no leeway.
    pub fn valid(&self) -> Result<(), TokenValidationError> {
        self.valid_with_leeway(0)
    }

    /// valid_with_leeway validates time-based claims with an allowed clock skew.
    pub fn valid_with_leeway(&self, leeway_seconds: i64) -> Result<(), TokenValidationError> {
        let leeway = leeway_seconds.abs();
        let now = unix_timestamp();

        if self.exp != 0 && now >= self.exp + leeway {
            return Err(TokenValidationError::TokenExpired);
        }

        if self.nbf != 0 && now < self.nbf - leeway {
            return Err(TokenValidationError::TokenNotValidYet);
        }

        Ok(())
    }
}

fn encode_proto<M: Message>(message: &M) -> Result<Vec<u8>, prost::EncodeError> {
    let mut buf = Vec::new();
    message.encode(&mut buf)?;
    Ok(buf)
}

fn unix_timestamp() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_secs() as i64
}

fn base64_url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(value.as_bytes())
}
