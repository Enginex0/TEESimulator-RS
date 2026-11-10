use crate::error::{CertGenError, Result};
use crate::types::{Algorithm, EcCurve, GeneratedKeyPair};

pub fn generate_key_pair(
    algorithm: Algorithm,
    key_size: u32,
    ec_curve: Option<EcCurve>,
    rsa_public_exponent: u64,
) -> Result<GeneratedKeyPair> {
    match algorithm {
        Algorithm::Ec => {
            let curve = ec_curve.ok_or_else(|| CertGenError::InvalidParameter("ec_curve required for EC".into()))?;
            generate_ec_key_pair(curve)
        }
        Algorithm::Rsa => generate_rsa_key_pair(key_size, rsa_public_exponent),
    }
}

fn generate_ec_key_pair(curve: EcCurve) -> Result<GeneratedKeyPair> {
    let alg = match curve {
        EcCurve::P256 => &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        EcCurve::P384 => &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        _ => return Err(CertGenError::UnsupportedEcCurve(curve as i32)),
    };

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng)?;

    Ok(GeneratedKeyPair {
        private_key_pkcs8: pkcs8_doc.as_ref().to_vec(),
    })
}

fn generate_rsa_key_pair(key_size: u32, rsa_public_exponent: u64) -> Result<GeneratedKeyPair> {
    use pkcs8::EncodePrivateKey;

    if !matches!(key_size, 2048 | 3072 | 4096) {
        return Err(CertGenError::InvalidParameter(
            format!("RSA key size must be 2048, 3072, or 4096; got {key_size}")
        ));
    }

    let exp = if rsa_public_exponent == 0 {
        rsa::BigUint::from(65537u64)
    } else {
        rsa::BigUint::from(rsa_public_exponent)
    };

    let mut rng = rand::thread_rng();
    let private_key = rsa::RsaPrivateKey::new_with_exp(&mut rng, key_size as usize, &exp)
        .map_err(|e| CertGenError::KeyGenFailed(e.to_string()))?;

    let pkcs8_der = private_key.to_pkcs8_der()
        .map_err(|e| CertGenError::SerializationFailed(e.to_string()))?;

    Ok(GeneratedKeyPair {
        private_key_pkcs8: pkcs8_der.as_bytes().to_vec(),
    })
}
