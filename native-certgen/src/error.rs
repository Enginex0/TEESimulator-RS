use std::fmt;

#[derive(Debug)]
pub enum CertGenError {
    Jni(String),
    NullParam(&'static str),
    UnsupportedAlgorithm(i32),
    UnsupportedEcCurve(i32),
    KeyGenFailed(String),
    CertBuildFailed(String),
    KeyboxParseFailed(String),
    AttestationBuildFailed(String),
    DerError(der::Error),
    EmptyKeyboxChain,
    ChallengeTooLong(usize),
    InvalidParameter(String),
    SigningFailed(String),
    SerializationFailed(String),
}

impl fmt::Display for CertGenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jni(msg) => write!(f, "JNI error: {}", msg),
            Self::NullParam(name) => write!(f, "null required parameter: {}", name),
            Self::UnsupportedAlgorithm(v) => write!(f, "unsupported algorithm: {}", v),
            Self::UnsupportedEcCurve(v) => write!(f, "unsupported EC curve: {}", v),
            Self::KeyGenFailed(msg) => write!(f, "key generation failed: {}", msg),
            Self::CertBuildFailed(msg) => write!(f, "certificate build failed: {}", msg),
            Self::KeyboxParseFailed(msg) => write!(f, "keybox parse failed: {}", msg),
            Self::AttestationBuildFailed(msg) => write!(f, "attestation build failed: {}", msg),
            Self::DerError(e) => write!(f, "DER error: {}", e),
            Self::EmptyKeyboxChain => write!(f, "keybox certificate chain is empty"),
            Self::ChallengeTooLong(len) => write!(f, "attestation challenge too long: {} bytes (max 128)", len),
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {}", msg),
            Self::SigningFailed(msg) => write!(f, "signing failed: {}", msg),
            Self::SerializationFailed(msg) => write!(f, "serialization failed: {}", msg),
        }
    }
}

impl std::error::Error for CertGenError {}

impl From<jni::errors::Error> for CertGenError {
    fn from(e: jni::errors::Error) -> Self {
        Self::Jni(e.to_string())
    }
}

impl From<der::Error> for CertGenError {
    fn from(e: der::Error) -> Self {
        Self::DerError(e)
    }
}

impl From<ring::error::Unspecified> for CertGenError {
    fn from(e: ring::error::Unspecified) -> Self {
        Self::KeyGenFailed(e.to_string())
    }
}

impl From<ring::error::KeyRejected> for CertGenError {
    fn from(e: ring::error::KeyRejected) -> Self {
        Self::KeyGenFailed(e.to_string())
    }
}

impl From<rsa::Error> for CertGenError {
    fn from(e: rsa::Error) -> Self {
        Self::KeyGenFailed(e.to_string())
    }
}


pub type Result<T> = std::result::Result<T, CertGenError>;
