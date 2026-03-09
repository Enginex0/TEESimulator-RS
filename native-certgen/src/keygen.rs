use crate::error::{CertGenError, Result};
use crate::types::{Algorithm, EcCurve, GeneratedKeyPair};

pub fn generate_key_pair(algorithm: Algorithm, key_size: u32, ec_curve: Option<EcCurve>) -> Result<GeneratedKeyPair> {
    match algorithm {
        Algorithm::Ec => {
            let curve = ec_curve.ok_or_else(|| CertGenError::InvalidParameter("ec_curve required for EC".into()))?;
            generate_ec_key_pair(curve)
        }
        Algorithm::Rsa => generate_rsa_key_pair(key_size),
    }
}

fn generate_ec_key_pair(curve: EcCurve) -> Result<GeneratedKeyPair> {
    use ring::signature::KeyPair;

    let alg = match curve {
        EcCurve::P256 => &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        EcCurve::P384 => &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        _ => return Err(CertGenError::UnsupportedCurve(curve as i32)),
    };

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng)?;
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8_doc.as_ref(), &rng)?;

    Ok(GeneratedKeyPair {
        private_key_pkcs8: pkcs8_doc.as_ref().to_vec(),
        public_key_spki: key_pair.public_key().as_ref().to_vec(),
    })
}

fn generate_rsa_key_pair(key_size: u32) -> Result<GeneratedKeyPair> {
    use pkcs8::EncodePrivateKey;
    use rsa::pkcs8::EncodePublicKey;

    let mut rng = rand::thread_rng();
    let private_key = rsa::RsaPrivateKey::new(&mut rng, key_size as usize)
        .map_err(|e| CertGenError::KeyGenFailed(e.to_string()))?;

    let pkcs8_der = private_key.to_pkcs8_der()
        .map_err(|e| CertGenError::SerializationFailed(e.to_string()))?;

    let public_key = private_key.to_public_key();
    let pub_der = public_key.to_public_key_der()
        .map_err(|e| CertGenError::SerializationFailed(e.to_string()))?;

    Ok(GeneratedKeyPair {
        private_key_pkcs8: pkcs8_der.as_bytes().to_vec(),
        public_key_spki: pub_der.as_ref().to_vec(),
    })
}
