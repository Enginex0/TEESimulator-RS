use std::fmt;

#[derive(Debug)]
pub enum CertGenError {
    KeyGenFailed(String),
    CertBuildFailed(String),
    AttestationEncodeFailed(String),
    KeyboxParseFailed(String),
    JniError(String),
    InvalidParameter(String),
    UnsupportedAlgorithm(i32),
    UnsupportedCurve(i32),
    SigningFailed(String),
    SerializationFailed(String),
    InternalError(String),
}

impl fmt::Display for CertGenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyGenFailed(msg) => write!(f, "key generation failed: {}", msg),
            Self::CertBuildFailed(msg) => write!(f, "certificate build failed: {}", msg),
            Self::AttestationEncodeFailed(msg) => write!(f, "attestation encode failed: {}", msg),
            Self::KeyboxParseFailed(msg) => write!(f, "keybox parse failed: {}", msg),
            Self::JniError(msg) => write!(f, "JNI error: {}", msg),
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {}", msg),
            Self::UnsupportedAlgorithm(v) => write!(f, "unsupported algorithm: {}", v),
            Self::UnsupportedCurve(v) => write!(f, "unsupported EC curve: {}", v),
            Self::SigningFailed(msg) => write!(f, "signing failed: {}", msg),
            Self::SerializationFailed(msg) => write!(f, "serialization failed: {}", msg),
            Self::InternalError(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for CertGenError {}

impl From<jni::errors::Error> for CertGenError {
    fn from(e: jni::errors::Error) -> Self {
        Self::JniError(e.to_string())
    }
}

impl From<der::Error> for CertGenError {
    fn from(e: der::Error) -> Self {
        Self::SerializationFailed(e.to_string())
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

impl From<rcgen::Error> for CertGenError {
    fn from(e: rcgen::Error) -> Self {
        Self::CertBuildFailed(e.to_string())
    }
}

impl From<anyhow::Error> for CertGenError {
    fn from(e: anyhow::Error) -> Self {
        Self::InternalError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CertGenError>;
