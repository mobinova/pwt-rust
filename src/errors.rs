use thiserror::Error;

/// TokenValidationError describes claim validation failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TokenValidationError {
    #[error("token is expired")]
    TokenExpired,
    #[error("token is not yet valid (nbf)")]
    TokenNotValidYet,
}

/// SigningMethodError reports signing or verification failures.
#[derive(Debug, Error)]
pub enum SigningMethodError {
    #[error("invalid key type")]
    InvalidKeyType,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("key parse error: {0}")]
    KeyParseError(String),
    #[error("crypto error: {0}")]
    CryptoError(String),
}

/// PwtError reports token parsing and signing failures.
#[derive(Debug, Error)]
pub enum PwtError {
    #[error("invalid token segment count: {0}")]
    InvalidSegmentCount(usize),
    #[error("failed to decode {0}")]
    Base64DecodingFailed(&'static str),
    #[error("failed to unmarshal header: {0}")]
    HeaderDecodingFailed(#[source] prost::DecodeError),
    #[error("failed to unmarshal payload: {0}")]
    PayloadDecodingFailed(#[source] prost::DecodeError),
    #[error("failed to decode signature: {0}")]
    SignatureDecodingFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("unsupported signing method: {0}")]
    UnsupportedAlgorithm(String),
    #[error("keyFunc is nil")]
    KeyFuncNil,
    #[error("keyFunc returned error: {0}")]
    KeyFuncError(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("failed to verify signature: {0}")]
    SignatureVerificationFailed(#[source] SigningMethodError),
    #[error("token validation failed: {0}")]
    TokenValidationFailed(#[source] TokenValidationError),
    #[error("failed to marshal header: {0}")]
    HeaderEncodingFailed(#[source] prost::EncodeError),
    #[error("failed to marshal payload: {0}")]
    PayloadEncodingFailed(#[source] prost::EncodeError),
    #[error("signing failed: {0}")]
    SigningFailed(#[source] SigningMethodError),
}
