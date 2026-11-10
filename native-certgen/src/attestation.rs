use crate::error::Result;
use crate::types::CertGenParams;

const DO_NOT_REPORT: i32 = -1;

pub fn build_attestation_extension(params: &CertGenParams) -> Result<Vec<u8>> {
    let sw = build_software_enforced(params)?;
    let tee = build_tee_enforced(params)?;

    let mut inner = Vec::new();
    // attestationVersion — INTEGER
    inner.extend_from_slice(&enc_integer(params.attest_version as i64));
    // attestationSecurityLevel — ENUMERATED, not INTEGER
    inner.extend_from_slice(&enc_enumerated(params.security_level));
    // keymintVersion — INTEGER
    inner.extend_from_slice(&enc_integer(params.keymaster_version as i64));
    // keymintSecurityLevel — ENUMERATED, not INTEGER
    inner.extend_from_slice(&enc_enumerated(params.security_level));
    // attestationChallenge — OCTET STRING
    inner.extend_from_slice(&enc_octet_string(
        params.attestation_challenge.as_deref().unwrap_or(&[]),
    ));
    // uniqueId — OCTET STRING (always empty)
    inner.extend_from_slice(&enc_octet_string(&[]));
    // softwareEnforced
    inner.extend_from_slice(&sw);
    // teeEnforced
    inner.extend_from_slice(&tee);

    Ok(enc_sequence(&inner))
}

fn build_software_enforced(params: &CertGenParams) -> Result<Vec<u8>> {
    let mut fields: Vec<(u32, Vec<u8>)> = Vec::new();

    // Tag 303: CALLER_NONCE — NULL (presence = true)
    if params.caller_nonce {
        fields.push((303, enc_null()));
    }

    // Tag 400: ACTIVE_DATETIME — INTEGER (milliseconds)
    if params.active_datetime >= 0 {
        fields.push((400, enc_integer(params.active_datetime)));
    }

    // Tag 401: ORIGINATION_EXPIRE_DATETIME — INTEGER (milliseconds)
    if params.origination_expire_datetime >= 0 {
        fields.push((401, enc_integer(params.origination_expire_datetime)));
    }

    // Tag 402: USAGE_EXPIRE_DATETIME — INTEGER (milliseconds)
    if params.usage_expire_datetime >= 0 {
        fields.push((402, enc_integer(params.usage_expire_datetime)));
    }

    // Tag 405: USAGE_COUNT_LIMIT — INTEGER
    if params.usage_count_limit >= 0 {
        fields.push((405, enc_integer(params.usage_count_limit as i64)));
    }

    // Tag 509: UNLOCKED_DEVICE_REQUIRED — NULL
    if params.unlocked_device_required {
        fields.push((509, enc_null()));
    }

    // Tag 701: CREATION_DATETIME — INTEGER (milliseconds)
    fields.push((701, enc_integer(params.creation_datetime)));

    // Tag 709: ATTESTATION_APPLICATION_ID — OCTET STRING
    // The bytes are already the DER-encoded AttestationApplicationId wrapped in OCTET STRING
    // by the Kotlin layer. We wrap them in an EXPLICIT tag.
    if !params.attestation_application_id.is_empty() {
        fields.push((709, enc_octet_string(&params.attestation_application_id)));
    }

    // Tag 724: MODULE_HASH — OCTET STRING (only if attestVersion >= 400)
    if params.attest_version >= 400 {
        if let Some(ref hash) = params.module_hash {
            fields.push((724, enc_octet_string(hash)));
        }
    }

    Ok(build_authorization_list(&mut fields))
}

fn build_tee_enforced(params: &CertGenParams) -> Result<Vec<u8>> {
    let mut fields: Vec<(u32, Vec<u8>)> = Vec::new();

    // Tag 1: PURPOSE — SET OF INTEGER
    if !params.purposes.is_empty() {
        fields.push((1, build_set_of_integer(&params.purposes)));
    }

    // Tag 2: ALGORITHM — INTEGER
    fields.push((2, enc_integer(params.algorithm as i32 as i64)));

    // Tag 3: KEY_SIZE — INTEGER
    fields.push((3, enc_integer(params.key_size as i64)));

    // Tag 5: DIGEST — SET OF INTEGER
    if !params.digests.is_empty() {
        fields.push((5, build_set_of_integer(&params.digests)));
    }

    // Tag 10: EC_CURVE — INTEGER (only for EC keys)
    if let Some(curve) = params.ec_curve {
        fields.push((10, enc_integer(curve as i32 as i64)));
    }

    // Tag 503: NO_AUTH_REQUIRED — NULL (conditional)
    if params.no_auth_required {
        fields.push((503, enc_null()));
    }

    // Tag 702: ORIGIN — INTEGER 0 (GENERATED)
    fields.push((702, enc_integer(0)));

    // Tag 704: ROOT_OF_TRUST — SEQUENCE
    fields.push((704, build_root_of_trust(params)));

    // Tag 705: OS_VERSION — INTEGER
    if params.os_version != DO_NOT_REPORT {
        fields.push((705, enc_integer(params.os_version as i64)));
    }

    // Tag 706: OS_PATCHLEVEL — INTEGER
    if params.os_patch_level != DO_NOT_REPORT {
        fields.push((706, enc_integer(params.os_patch_level as i64)));
    }

    // Tags 710-717: ATTESTATION_ID_* — OCTET STRING (optional)
    if let Some(ref v) = params.id_brand {
        fields.push((710, enc_octet_string(v)));
    }
    if let Some(ref v) = params.id_device {
        fields.push((711, enc_octet_string(v)));
    }
    if let Some(ref v) = params.id_product {
        fields.push((712, enc_octet_string(v)));
    }
    if let Some(ref v) = params.id_serial {
        fields.push((713, enc_octet_string(v)));
    }
    if let Some(ref v) = params.id_imei {
        fields.push((714, enc_octet_string(v)));
    }
    if let Some(ref v) = params.id_meid {
        fields.push((715, enc_octet_string(v)));
    }
    if let Some(ref v) = params.id_manufacturer {
        fields.push((716, enc_octet_string(v)));
    }
    if let Some(ref v) = params.id_model {
        fields.push((717, enc_octet_string(v)));
    }

    // Tag 718: VENDOR_PATCHLEVEL — INTEGER
    if params.vendor_patch_level != DO_NOT_REPORT {
        fields.push((718, enc_integer(params.vendor_patch_level as i64)));
    }

    // Tag 719: BOOT_PATCHLEVEL — INTEGER
    if params.boot_patch_level != DO_NOT_REPORT {
        fields.push((719, enc_integer(params.boot_patch_level as i64)));
    }

    // Tag 723: ATTESTATION_ID_SECOND_IMEI — OCTET STRING (only if attestVersion >= 300)
    if params.attest_version >= 300 {
        if let Some(ref v) = params.id_second_imei {
            fields.push((723, enc_octet_string(v)));
        }
    }

    Ok(build_authorization_list(&mut fields))
}

fn build_root_of_trust(params: &CertGenParams) -> Vec<u8> {
    let mut inner = Vec::new();
    // verifiedBootKey — OCTET STRING (32 bytes)
    inner.extend_from_slice(&enc_octet_string(&params.boot_key));
    // deviceLocked — BOOLEAN TRUE (0xFF, not 0x01)
    inner.extend_from_slice(&enc_boolean(true));
    // verifiedBootState — ENUMERATED 0 (Verified), not INTEGER
    inner.extend_from_slice(&enc_enumerated(0));
    // verifiedBootHash — OCTET STRING (32 bytes)
    inner.extend_from_slice(&enc_octet_string(&params.boot_hash));
    enc_sequence(&inner)
}

fn build_authorization_list(fields: &mut Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    fields.sort_by_key(|(tag, _)| *tag);
    let mut inner = Vec::new();
    for (tag, value) in fields.iter() {
        inner.extend_from_slice(&enc_explicit_tag(*tag, value));
    }
    enc_sequence(&inner)
}

fn build_set_of_integer(values: &[i32]) -> Vec<u8> {
    // DER SET OF: elements sorted by encoded byte value
    let mut encoded: Vec<Vec<u8>> = values.iter().map(|v| enc_integer(*v as i64)).collect();
    encoded.sort();
    let mut inner = Vec::new();
    for e in &encoded {
        inner.extend_from_slice(e);
    }
    enc_set(&inner)
}

// --- DER primitives ---

fn enc_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len <= 0xFF_FFFF {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        vec![
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

fn enc_integer(value: i64) -> Vec<u8> {
    // DER INTEGER: tag 0x02, minimal two's complement big-endian
    let bytes = integer_bytes(value);
    let mut out = vec![0x02];
    out.extend_from_slice(&enc_length(bytes.len()));
    out.extend_from_slice(&bytes);
    out
}

fn integer_bytes(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let raw = value.to_be_bytes();
    // Find first significant byte
    let mut start = 0;
    if value > 0 {
        while start < 7 && raw[start] == 0x00 {
            start += 1;
        }
        // If high bit set, need leading 0x00 to keep positive
        if raw[start] & 0x80 != 0 {
            let mut out = vec![0x00];
            out.extend_from_slice(&raw[start..]);
            return out;
        }
    } else {
        while start < 7 && raw[start] == 0xFF {
            start += 1;
        }
        // If high bit clear, need leading 0xFF to keep negative
        if raw[start] & 0x80 == 0 {
            let mut out = vec![0xFF];
            out.extend_from_slice(&raw[start..]);
            return out;
        }
    }
    raw[start..].to_vec()
}

fn enc_enumerated(value: i32) -> Vec<u8> {
    // DER ENUMERATED: tag 0x0A, same value encoding as INTEGER
    let bytes = integer_bytes(value as i64);
    let mut out = vec![0x0A];
    out.extend_from_slice(&enc_length(bytes.len()));
    out.extend_from_slice(&bytes);
    out
}

fn enc_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    out.extend_from_slice(&enc_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn enc_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn enc_boolean(value: bool) -> Vec<u8> {
    // DER BOOLEAN: TRUE = 0xFF, FALSE = 0x00
    vec![0x01, 0x01, if value { 0xFF } else { 0x00 }]
}

fn enc_sequence(contents: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&enc_length(contents.len()));
    out.extend_from_slice(contents);
    out
}

fn enc_set(contents: &[u8]) -> Vec<u8> {
    let mut out = vec![0x31];
    out.extend_from_slice(&enc_length(contents.len()));
    out.extend_from_slice(contents);
    out
}

fn enc_explicit_tag(tag_number: u32, inner: &[u8]) -> Vec<u8> {
    // EXPLICIT context-specific constructed tag
    let mut out = Vec::new();
    if tag_number < 31 {
        // Short form: single byte 0xA0 | tag_number
        out.push(0xA0 | tag_number as u8);
    } else {
        // Long form: 0xBF followed by base-128 encoding of tag number
        out.push(0xBF);
        enc_base128_tag(&mut out, tag_number);
    }
    out.extend_from_slice(&enc_length(inner.len()));
    out.extend_from_slice(inner);
    out
}

fn enc_base128_tag(out: &mut Vec<u8>, tag: u32) {
    // Base-128 with continuation bits: MSB first, bit 7 set on all but last byte
    let mut digits = Vec::new();
    let mut val = tag;
    digits.push((val & 0x7F) as u8);
    val >>= 7;
    while val > 0 {
        digits.push((val & 0x7F) as u8 | 0x80);
        val >>= 7;
    }
    // Written MSB first
    for b in digits.iter().rev() {
        out.push(*b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Algorithm, EcCurve};

    #[test]
    fn test_enc_integer_zero() {
        assert_eq!(enc_integer(0), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_enc_integer_small_positive() {
        assert_eq!(enc_integer(3), vec![0x02, 0x01, 0x03]);
        assert_eq!(enc_integer(127), vec![0x02, 0x01, 0x7F]);
    }

    #[test]
    fn test_enc_integer_needs_leading_zero() {
        // 128 = 0x80, high bit set so needs 0x00 prefix
        assert_eq!(enc_integer(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(enc_integer(256), vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_enc_integer_multi_byte() {
        // 140000 = 0x02_22_E0
        assert_eq!(enc_integer(140000), vec![0x02, 0x03, 0x02, 0x22, 0xE0]);
    }

    #[test]
    fn test_enc_integer_large() {
        // 20250301 = 0x01_34_FE_BD
        assert_eq!(
            enc_integer(20250301),
            vec![0x02, 0x04, 0x01, 0x34, 0xFE, 0xBD]
        );
    }

    #[test]
    fn test_enc_enumerated() {
        // SecurityLevel TEE = 1
        assert_eq!(enc_enumerated(1), vec![0x0A, 0x01, 0x01]);
        // VerifiedBootState Verified = 0
        assert_eq!(enc_enumerated(0), vec![0x0A, 0x01, 0x00]);
    }

    #[test]
    fn test_enc_boolean_true() {
        // DER: TRUE = 0xFF
        assert_eq!(enc_boolean(true), vec![0x01, 0x01, 0xFF]);
    }

    #[test]
    fn test_enc_null() {
        assert_eq!(enc_null(), vec![0x05, 0x00]);
    }

    #[test]
    fn test_enc_octet_string_empty() {
        assert_eq!(enc_octet_string(&[]), vec![0x04, 0x00]);
    }

    #[test]
    fn test_enc_explicit_tag_short() {
        // Tag 1 wrapping INTEGER 2: A1 03 02 01 02
        let inner = enc_integer(2);
        let tagged = enc_explicit_tag(1, &inner);
        assert_eq!(tagged, vec![0xA1, 0x03, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn test_enc_explicit_tag_10() {
        // Tag 10: 0xAA
        let inner = enc_integer(1);
        let tagged = enc_explicit_tag(10, &inner);
        assert_eq!(tagged[0], 0xAA);
    }

    #[test]
    fn test_enc_explicit_tag_503() {
        // Tag 503: 0xBF 0x83 0x77
        // 503 = 3*128 + 119 => 0x83 0x77
        let inner = enc_null();
        let tagged = enc_explicit_tag(503, &inner);
        assert_eq!(&tagged[..3], &[0xBF, 0x83, 0x77]);
    }

    #[test]
    fn test_enc_explicit_tag_704() {
        // Tag 704: 0xBF 0x85 0x40
        // 704 = 5*128 + 64 => 0x85 0x40
        let inner = enc_sequence(&[]);
        let tagged = enc_explicit_tag(704, &inner);
        assert_eq!(&tagged[..3], &[0xBF, 0x85, 0x40]);
    }

    #[test]
    fn test_enc_explicit_tag_718() {
        // Tag 718: 0xBF 0x85 0x4E
        let inner = enc_integer(20250301);
        let tagged = enc_explicit_tag(718, &inner);
        assert_eq!(&tagged[..3], &[0xBF, 0x85, 0x4E]);
    }

    #[test]
    fn test_enc_explicit_tag_719() {
        // Tag 719: 0xBF 0x85 0x4F
        let inner = enc_integer(20250301);
        let tagged = enc_explicit_tag(719, &inner);
        assert_eq!(&tagged[..3], &[0xBF, 0x85, 0x4F]);
    }

    #[test]
    fn test_enc_explicit_tag_701() {
        // Tag 701: 0xBF 0x85 0x3D
        let inner = enc_integer(1000);
        let tagged = enc_explicit_tag(701, &inner);
        assert_eq!(&tagged[..3], &[0xBF, 0x85, 0x3D]);
    }

    #[test]
    fn test_enc_explicit_tag_709() {
        // Tag 709: 0xBF 0x85 0x45
        let inner = enc_octet_string(&[0x01]);
        let tagged = enc_explicit_tag(709, &inner);
        assert_eq!(&tagged[..3], &[0xBF, 0x85, 0x45]);
    }

    #[test]
    fn test_build_set_of_integer_sorted() {
        // SET OF INTEGER must sort by encoded bytes
        let result = build_set_of_integer(&[3, 2]);
        // Expect sorted: INTEGER 2 before INTEGER 3
        let expected = enc_set(&[0x02, 0x01, 0x02, 0x02, 0x01, 0x03]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_root_of_trust_structure() {
        let params = make_test_params();
        let rot = build_root_of_trust(&params);
        // Should be a SEQUENCE (0x30)
        assert_eq!(rot[0], 0x30);
        // Find BOOLEAN TRUE inside
        let rot_inner = &rot[2..]; // skip tag+length
        // First: OCTET STRING (32 bytes boot key)
        assert_eq!(rot_inner[0], 0x04);
        assert_eq!(rot_inner[1], 0x20); // 32 bytes
        // After boot key (34 bytes): BOOLEAN TRUE
        assert_eq!(rot_inner[34], 0x01); // BOOLEAN tag
        assert_eq!(rot_inner[35], 0x01); // length 1
        assert_eq!(rot_inner[36], 0xFF); // TRUE = 0xFF
        // Then ENUMERATED 0 (verifiedBootState)
        assert_eq!(rot_inner[37], 0x0A); // ENUMERATED tag, not 0x02
        assert_eq!(rot_inner[38], 0x01);
        assert_eq!(rot_inner[39], 0x00);
    }

    #[test]
    fn test_do_not_report_omits_fields() {
        let mut params = make_test_params();
        params.os_patch_level = DO_NOT_REPORT;
        params.vendor_patch_level = DO_NOT_REPORT;
        params.boot_patch_level = DO_NOT_REPORT;
        let tee = build_tee_enforced(&params).unwrap();
        let hex = hex_string(&tee);
        // Tags 706, 718, 719 should not appear
        // Tag 706 = BF 85 42, 718 = BF 85 4E, 719 = BF 85 4F
        assert!(!hex.contains("bf8542"), "os_patch_level should be omitted");
        assert!(
            !hex.contains("bf854e"),
            "vendor_patch_level should be omitted"
        );
        assert!(
            !hex.contains("bf854f"),
            "boot_patch_level should be omitted"
        );
    }

    #[test]
    fn test_key_description_security_level_is_enumerated() {
        let params = make_test_params();
        let ext = build_attestation_extension(&params).unwrap();
        // KeyDescription is a SEQUENCE: 0x30 ...
        assert_eq!(ext[0], 0x30);
        // Skip SEQUENCE tag + length to get to inner fields
        let inner = skip_tlv_header(&ext);
        // Field 0: attestationVersion — INTEGER (0x02)
        assert_eq!(inner[0], 0x02);
        let (_, rest) = skip_one_tlv(inner);
        // Field 1: attestationSecurityLevel — ENUMERATED (0x0A)
        assert_eq!(rest[0], 0x0A, "attestationSecurityLevel must be ENUMERATED");
        let (_, rest) = skip_one_tlv(rest);
        // Field 2: keymintVersion — INTEGER (0x02)
        assert_eq!(rest[0], 0x02);
        let (_, rest) = skip_one_tlv(rest);
        // Field 3: keymintSecurityLevel — ENUMERATED (0x0A)
        assert_eq!(rest[0], 0x0A, "keymintSecurityLevel must be ENUMERATED");
    }

    #[test]
    fn test_authorization_list_sorted_by_tag() {
        let params = make_test_params();
        let tee = build_tee_enforced(&params).unwrap();
        let inner = skip_tlv_header(&tee);
        let tags = extract_tag_numbers(inner);
        let mut sorted = tags.clone();
        sorted.sort();
        assert_eq!(tags, sorted, "AuthorizationList fields must be sorted by tag number");
    }

    #[test]
    fn test_enforcement_tags_in_software_enforced() {
        let mut params = make_test_params();
        params.usage_count_limit = 3;
        params.unlocked_device_required = true;
        params.caller_nonce = true;
        params.active_datetime = 1709913600000;
        let sw = build_software_enforced(&params).unwrap();
        let inner = skip_tlv_header(&sw);
        let tags = extract_tag_numbers(inner);
        assert!(tags.contains(&303), "CALLER_NONCE (303) must be in softwareEnforced");
        assert!(tags.contains(&400), "ACTIVE_DATETIME (400) must be in softwareEnforced");
        assert!(tags.contains(&405), "USAGE_COUNT_LIMIT (405) must be in softwareEnforced");
        assert!(tags.contains(&509), "UNLOCKED_DEVICE_REQUIRED (509) must be in softwareEnforced");
    }

    #[test]
    fn test_no_auth_required_conditional() {
        let mut params = make_test_params();
        params.no_auth_required = false;
        let tee = build_tee_enforced(&params).unwrap();
        let inner = skip_tlv_header(&tee);
        let tags = extract_tag_numbers(inner);
        assert!(!tags.contains(&503), "NO_AUTH_REQUIRED (503) must be absent when false");
    }

    #[test]
    fn test_enforcement_tags_omitted_when_unset() {
        let params = make_test_params();
        let sw = build_software_enforced(&params).unwrap();
        let inner = skip_tlv_header(&sw);
        let tags = extract_tag_numbers(inner);
        assert!(!tags.contains(&303), "CALLER_NONCE should be absent when false");
        assert!(!tags.contains(&400), "ACTIVE_DATETIME should be absent when -1");
        assert!(!tags.contains(&405), "USAGE_COUNT_LIMIT should be absent when -1");
        assert!(!tags.contains(&509), "UNLOCKED_DEVICE_REQUIRED should be absent when false");
    }

    #[test]
    fn test_full_extension_roundtrip() {
        let params = make_test_params();
        let ext = build_attestation_extension(&params).unwrap();
        // Must be valid DER: starts with SEQUENCE tag
        assert_eq!(ext[0], 0x30);
        // Length must account for all inner bytes
        let (header_len, total_content_len) = parse_tlv_lengths(&ext);
        assert_eq!(ext.len(), header_len + total_content_len);
    }

    // --- test helpers ---

    fn make_test_params() -> CertGenParams {
        CertGenParams {
            algorithm: Algorithm::Ec,
            key_size: 256,
            ec_curve: Some(EcCurve::P256),
            rsa_public_exponent: 0,
            attestation_challenge: Some(vec![0xAB; 32]),
            purposes: vec![2, 3],
            digests: vec![4],
            cert_serial: None,
            cert_subject: None,
            cert_not_before: -1,
            cert_not_after: -1,
            keybox_private_key: vec![],
            keybox_cert_chain: vec![],
            security_level: 1,
            attest_version: 200,
            keymaster_version: 200,
            os_version: 140000,
            os_patch_level: 202503,
            vendor_patch_level: 20250301,
            boot_patch_level: 20250301,
            boot_key: vec![0x01; 32],
            boot_hash: vec![0x02; 32],
            creation_datetime: 1709913600000,
            attestation_application_id: vec![0xDE, 0xAD],
            module_hash: None,
            id_brand: None,
            id_device: None,
            id_product: None,
            id_serial: None,
            id_imei: None,
            id_meid: None,
            id_manufacturer: None,
            id_model: None,
            id_second_imei: None,
            active_datetime: -1,
            origination_expire_datetime: -1,
            usage_expire_datetime: -1,
            usage_count_limit: -1,
            caller_nonce: false,
            unlocked_device_required: false,
            no_auth_required: true,
        }
    }

    fn hex_string(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn skip_tlv_header(data: &[u8]) -> &[u8] {
        let (header_len, _) = parse_tlv_lengths(data);
        &data[header_len..]
    }

    fn skip_one_tlv(data: &[u8]) -> (usize, &[u8]) {
        let (header_len, content_len) = parse_tlv_lengths(data);
        let total = header_len + content_len;
        (total, &data[total..])
    }

    fn parse_tlv_lengths(data: &[u8]) -> (usize, usize) {
        // Returns (header_bytes, content_bytes)
        let tag_len = tag_byte_len(data);
        let len_start = tag_len;
        if data[len_start] < 0x80 {
            (len_start + 1, data[len_start] as usize)
        } else {
            let num_len_bytes = (data[len_start] & 0x7F) as usize;
            let mut content_len = 0usize;
            for i in 0..num_len_bytes {
                content_len = (content_len << 8) | data[len_start + 1 + i] as usize;
            }
            (len_start + 1 + num_len_bytes, content_len)
        }
    }

    fn tag_byte_len(data: &[u8]) -> usize {
        if data[0] & 0x1F != 0x1F {
            1
        } else {
            let mut i = 1;
            while data[i] & 0x80 != 0 {
                i += 1;
            }
            i + 1
        }
    }

    fn extract_tag_numbers(mut data: &[u8]) -> Vec<u32> {
        let mut tags = Vec::new();
        while !data.is_empty() {
            let tag = read_tag_number(data);
            tags.push(tag);
            let (_, rest) = skip_one_tlv(data);
            data = rest;
        }
        tags
    }

    fn read_tag_number(data: &[u8]) -> u32 {
        if data[0] & 0x1F != 0x1F {
            (data[0] & 0x1F) as u32
        } else {
            let mut val = 0u32;
            let mut i = 1;
            loop {
                val = (val << 7) | (data[i] & 0x7F) as u32;
                if data[i] & 0x80 == 0 {
                    break;
                }
                i += 1;
            }
            val
        }
    }
}
