use crate::error::{CertGenError, Result};
use der::{Decode, Encode};
use x509_cert::Certificate;

pub struct ParsedKeybox {
    pub signing_key_der: Vec<u8>,
    pub issuer_dn_der: Vec<u8>,
    pub cert_chain_ders: Vec<Vec<u8>>,
    pub leaf_not_after: i64,
}

pub fn parse_keybox(cert_chain_bytes: &[u8], private_key_bytes: &[u8]) -> Result<ParsedKeybox> {
    let certs = split_der_certificates(cert_chain_bytes)?;
    if certs.is_empty() {
        return Err(CertGenError::KeyboxParseFailed("no certificates found".into()));
    }

    let leaf = Certificate::from_der(&certs[0])
        .map_err(|e| CertGenError::KeyboxParseFailed(format!("leaf cert parse: {e}")))?;

    let issuer_dn_der = leaf.tbs_certificate.issuer.to_der()
        .map_err(|e| CertGenError::KeyboxParseFailed(format!("issuer DN encode: {e}")))?;

    let not_after = leaf.tbs_certificate.validity.not_after;
    let leaf_not_after = not_after.to_unix_duration().as_secs() as i64;

    Ok(ParsedKeybox {
        signing_key_der: private_key_bytes.to_vec(),
        issuer_dn_der,
        cert_chain_ders: certs,
        leaf_not_after,
    })
}

fn split_der_certificates(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        if data[offset] != 0x30 {
            return Err(CertGenError::KeyboxParseFailed(
                format!("expected SEQUENCE tag 0x30 at offset {offset}, got 0x{:02x}", data[offset])
            ));
        }

        let (content_len, header_len) = parse_der_length(&data[offset + 1..])?;
        let total_len = 1 + header_len + content_len;

        if offset + total_len > data.len() {
            return Err(CertGenError::KeyboxParseFailed(
                format!("cert at offset {offset} extends beyond buffer: need {total_len}, have {}", data.len() - offset)
            ));
        }

        certs.push(data[offset..offset + total_len].to_vec());
        offset += total_len;
    }

    if certs.is_empty() {
        return Err(CertGenError::KeyboxParseFailed("no certificates in chain".into()));
    }

    Ok(certs)
}

// Returns (content_length, number_of_length_bytes_consumed)
fn parse_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(CertGenError::KeyboxParseFailed("truncated DER length".into()));
    }

    let first = data[0];

    if first < 0x80 {
        // Short form: length is the byte itself
        return Ok((first as usize, 1));
    }

    // Long form: low 7 bits = number of subsequent length bytes
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 {
        return Err(CertGenError::KeyboxParseFailed(
            format!("unsupported DER length encoding: 0x{first:02x}")
        ));
    }
    if 1 + num_bytes > data.len() {
        return Err(CertGenError::KeyboxParseFailed("truncated multi-byte DER length".into()));
    }

    let mut len: usize = 0;
    for i in 0..num_bytes {
        len = (len << 8) | (data[1 + i] as usize);
    }

    Ok((len, 1 + num_bytes))
}
