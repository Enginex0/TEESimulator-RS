use crate::error::CertGenError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Algorithm {
    Rsa = 1,
    Ec = 3,
}

impl TryFrom<i32> for Algorithm {
    type Error = CertGenError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Rsa),
            3 => Ok(Self::Ec),
            _ => Err(CertGenError::UnsupportedAlgorithm(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum EcCurve {
    P224 = 0,
    P256 = 1,
    P384 = 2,
    P521 = 3,
    Curve25519 = 4,
}

impl TryFrom<i32> for EcCurve {
    type Error = CertGenError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::P224),
            1 => Ok(Self::P256),
            2 => Ok(Self::P384),
            3 => Ok(Self::P521),
            4 => Ok(Self::Curve25519),
            _ => Err(CertGenError::UnsupportedCurve(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum KeyPurpose {
    Encrypt = 0,
    Decrypt = 1,
    Sign = 2,
    Verify = 3,
    WrapKey = 5,
    AgreeKey = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

pub struct CertGenParams {
    pub algorithm: Algorithm,
    pub key_size: u32,
    pub ec_curve: Option<EcCurve>,
    pub rsa_public_exponent: u64,

    pub attestation_challenge: Option<Vec<u8>>,
    pub purposes: Vec<i32>,
    pub digests: Vec<i32>,

    pub cert_serial: Option<Vec<u8>>,
    pub cert_subject: Option<Vec<u8>>,
    pub cert_not_before: i64,
    pub cert_not_after: i64,

    pub keybox_private_key: Vec<u8>,
    pub keybox_cert_chain: Vec<u8>,

    pub security_level: i32,
    pub attest_version: i32,
    pub keymaster_version: i32,

    pub os_version: i32,
    pub os_patch_level: i32,
    pub vendor_patch_level: i32,
    pub boot_patch_level: i32,

    pub boot_key: Vec<u8>,
    pub boot_hash: Vec<u8>,

    pub creation_datetime: i64,
    pub attestation_application_id: Vec<u8>,
    pub module_hash: Option<Vec<u8>>,

    pub id_brand: Option<Vec<u8>>,
    pub id_device: Option<Vec<u8>>,
    pub id_product: Option<Vec<u8>>,
    pub id_serial: Option<Vec<u8>>,
    pub id_imei: Option<Vec<u8>>,
    pub id_meid: Option<Vec<u8>>,
    pub id_manufacturer: Option<Vec<u8>>,
    pub id_model: Option<Vec<u8>>,
    pub id_second_imei: Option<Vec<u8>>,
}

pub struct GeneratedKeyPair {
    pub private_key_pkcs8: Vec<u8>,
    pub public_key_spki: Vec<u8>,
}
