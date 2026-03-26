#![deny(clippy::unwrap_used, clippy::expect_used)]

mod error;
mod types;
mod keygen;
pub mod keybox;
pub mod attestation;
pub mod certbuilder;
pub mod logging;

use jni::objects::{JByteArray, JClass, JIntArray, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jstring};
use jni::JNIEnv;

use crate::error::{CertGenError, Result};
use crate::types::{Algorithm, CertGenParams, EcCurve};

// ---------------------------------------------------------------------------
// JNI entry: generateAttestedKeyPair
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_org_matrix_TEESimulator_pki_NativeCertGen_generateAttestedKeyPair(
    mut env: JNIEnv,
    _class: JClass,
    config: JObject,
) -> jbyteArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_attested_inner(&mut env, &config)
    }));

    match result {
        Ok(Ok(raw)) => raw,
        Ok(Err(e)) => {
            tracing::error!(%e, "generateAttestedKeyPair failed");
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("NativeCertGen: {e}"),
            );
            std::ptr::null_mut()
        }
        Err(_) => {
            tracing::error!("generateAttestedKeyPair panicked");
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                "NativeCertGen: internal panic",
            );
            std::ptr::null_mut()
        }
    }
}

fn generate_attested_inner(env: &mut JNIEnv, config: &JObject) -> Result<jbyteArray> {
    let params = extract_config(env, config)?;

    let key_pair = keygen::generate_key_pair(
        params.algorithm,
        params.key_size,
        params.ec_curve,
        params.rsa_public_exponent,
    )?;

    let keybox = keybox::parse_keybox(&params.keybox_cert_chain, &params.keybox_private_key)?;

    let attest_ext = match params.attestation_challenge {
        Some(_) => Some(attestation::build_attestation_extension(&params)?),
        None => None,
    };

    let cert_chain = certbuilder::build_certificate_chain(
        &key_pair,
        attest_ext.as_deref(),
        &keybox,
        &params,
    )?;

    let blob = assemble_result(&key_pair.private_key_pkcs8, &cert_chain);

    let out = env.byte_array_from_slice(&blob)?;
    Ok(out.into_raw())
}

// ---------------------------------------------------------------------------
// JNI entry: initLogging
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_org_matrix_TEESimulator_pki_NativeCertGen_initLogging(
    mut env: JNIEnv,
    _class: JClass,
    verbose: jboolean,
    log_dir: JString,
) -> jboolean {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        init_logging_inner(&mut env, verbose, &log_dir)
    }));

    match result {
        Ok(Ok(())) => 1,
        Ok(Err(e)) => {
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("NativeCertGen initLogging: {e}"),
            );
            0
        }
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                "NativeCertGen initLogging: internal panic",
            );
            0
        }
    }
}

fn init_logging_inner(env: &mut JNIEnv, verbose: jboolean, log_dir: &JString) -> Result<()> {
    let dir: String = env.get_string(log_dir)?.into();
    logging::init(verbose != 0, &dir, 2, 3)
        .map_err(|e| CertGenError::Jni(format!("logging init failed: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// JNI entry: dumpLogs
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_org_matrix_TEESimulator_pki_NativeCertGen_dumpLogs(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dump_logs_inner(&mut env)
    }));

    match result {
        Ok(Ok(raw)) => raw,
        Ok(Err(e)) => {
            tracing::error!(%e, "dumpLogs failed");
            std::ptr::null_mut()
        }
        Err(_) => {
            tracing::error!("dumpLogs panicked");
            std::ptr::null_mut()
        }
    }
}

fn dump_logs_inner(env: &mut JNIEnv) -> Result<jstring> {
    logging::dump::execute_dump()
        .map_err(|e| CertGenError::Jni(format!("dump failed: {e}")))?;

    // Read the dump path written by execute_dump
    let path = std::fs::read_to_string("/data/adb/tricky_store/.dump_path")
        .map_err(|e| CertGenError::Jni(format!("read dump path: {e}")))?;

    let jpath = env.new_string(&path)?;
    Ok(jpath.into_raw())
}

// ---------------------------------------------------------------------------
// Config extraction from Java CertGenConfig object
// ---------------------------------------------------------------------------

fn extract_config(env: &mut JNIEnv, config: &JObject) -> Result<CertGenParams> {
    let algorithm = get_int(env, config, "algorithm")?;
    let key_size = get_int(env, config, "keySize")?;
    let ec_curve_raw = get_int(env, config, "ecCurve")?;
    let rsa_pub_exp = get_long(env, config, "rsaPublicExponent")?;

    let cert_not_before = get_long(env, config, "certNotBefore")?;
    let cert_not_after = get_long(env, config, "certNotAfter")?;
    let security_level = get_int(env, config, "securityLevel")?;
    let attest_version = get_int(env, config, "attestVersion")?;
    let keymaster_version = get_int(env, config, "keymasterVersion")?;
    let os_version = get_int(env, config, "osVersion")?;
    let os_patch_level = get_int(env, config, "osPatchLevel")?;
    let vendor_patch_level = get_int(env, config, "vendorPatchLevel")?;
    let boot_patch_level = get_int(env, config, "bootPatchLevel")?;
    let creation_datetime = get_long(env, config, "creationDatetime")?;

    let attestation_challenge = get_nullable_byte_array(env, config, "attestationChallenge")?;
    let purposes = get_int_array(env, config, "purposes")?;
    let digests = get_int_array(env, config, "digests")?;
    let cert_serial = get_nullable_byte_array(env, config, "certSerial")?;
    let cert_subject = get_nullable_byte_array(env, config, "certSubject")?;
    let keybox_private_key = get_byte_array(env, config, "keyboxPrivateKey")?;
    let keybox_cert_chain = get_byte_array(env, config, "keyboxCertChain")?;
    let boot_key = get_byte_array(env, config, "bootKey")?;
    let boot_hash = get_byte_array(env, config, "bootHash")?;
    let attestation_app_id = get_byte_array(env, config, "attestationApplicationId")?;
    let module_hash = get_nullable_byte_array(env, config, "moduleHash")?;

    let id_brand = get_nullable_byte_array(env, config, "idBrand")?;
    let id_device = get_nullable_byte_array(env, config, "idDevice")?;
    let id_product = get_nullable_byte_array(env, config, "idProduct")?;
    let id_serial = get_nullable_byte_array(env, config, "idSerial")?;
    let id_imei = get_nullable_byte_array(env, config, "idImei")?;
    let id_meid = get_nullable_byte_array(env, config, "idMeid")?;
    let id_manufacturer = get_nullable_byte_array(env, config, "idManufacturer")?;
    let id_model = get_nullable_byte_array(env, config, "idModel")?;
    let id_second_imei = get_nullable_byte_array(env, config, "idSecondImei")?;

    let active_datetime = get_long(env, config, "activeDatetime")?;
    let origination_expire_datetime = get_long(env, config, "originationExpireDatetime")?;
    let usage_expire_datetime = get_long(env, config, "usageExpireDatetime")?;
    let usage_count_limit = get_int(env, config, "usageCountLimit")?;
    let caller_nonce = get_boolean(env, config, "callerNonce")?;
    let unlocked_device_required = get_boolean(env, config, "unlockedDeviceRequired")?;
    let no_auth_required = get_boolean(env, config, "noAuthRequired")?;

    Ok(CertGenParams {
        algorithm: Algorithm::try_from(algorithm)?,
        key_size: key_size as u32,
        ec_curve: if algorithm == 3 {
            Some(EcCurve::try_from(ec_curve_raw)?)
        } else {
            None
        },
        rsa_public_exponent: rsa_pub_exp as u64,
        attestation_challenge,
        purposes,
        digests,
        cert_serial,
        cert_subject,
        cert_not_before,
        cert_not_after,
        keybox_private_key,
        keybox_cert_chain,
        security_level,
        attest_version,
        keymaster_version,
        os_version,
        os_patch_level,
        vendor_patch_level,
        boot_patch_level,
        boot_key,
        boot_hash,
        creation_datetime,
        attestation_application_id: attestation_app_id,
        module_hash,
        id_brand,
        id_device,
        id_product,
        id_serial,
        id_imei,
        id_meid,
        id_manufacturer,
        id_model,
        id_second_imei,
        active_datetime,
        origination_expire_datetime,
        usage_expire_datetime,
        usage_count_limit,
        caller_nonce,
        unlocked_device_required,
        no_auth_required,
    })
}

// ---------------------------------------------------------------------------
// JNI field accessor helpers — called 35+ times, justifies the abstraction
// ---------------------------------------------------------------------------

fn get_int(env: &mut JNIEnv, obj: &JObject, name: &str) -> Result<i32> {
    Ok(env.get_field(obj, name, "I")?.i()?)
}

fn get_long(env: &mut JNIEnv, obj: &JObject, name: &str) -> Result<i64> {
    Ok(env.get_field(obj, name, "J")?.j()?)
}

fn get_boolean(env: &mut JNIEnv, obj: &JObject, name: &str) -> Result<bool> {
    Ok(env.get_field(obj, name, "Z")?.z()?)
}

fn get_byte_array(env: &mut JNIEnv, obj: &JObject, name: &'static str) -> Result<Vec<u8>> {
    let field = env.get_field(obj, name, "[B")?.l()?;
    if field.is_null() {
        return Err(CertGenError::NullParam(name));
    }
    let arr: JByteArray = field.into();
    let len = env.get_array_length(&arr)?;
    let mut buf = vec![0i8; len as usize];
    env.get_byte_array_region(&arr, 0, &mut buf)?;
    env.delete_local_ref(arr)?;
    Ok(buf.into_iter().map(|b| b as u8).collect())
}

fn get_nullable_byte_array(
    env: &mut JNIEnv,
    obj: &JObject,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    let field = env.get_field(obj, name, "[B")?.l()?;
    if field.is_null() {
        return Ok(None);
    }
    let arr: JByteArray = field.into();
    let len = env.get_array_length(&arr)?;
    let mut buf = vec![0i8; len as usize];
    env.get_byte_array_region(&arr, 0, &mut buf)?;
    env.delete_local_ref(arr)?;
    Ok(Some(buf.into_iter().map(|b| b as u8).collect()))
}

fn get_int_array(env: &mut JNIEnv, obj: &JObject, name: &str) -> Result<Vec<i32>> {
    let field = env.get_field(obj, name, "[I")?.l()?;
    if field.is_null() {
        return Ok(vec![]);
    }
    let arr: JIntArray = field.into();
    let len = env.get_array_length(&arr)?;
    let mut buf = vec![0i32; len as usize];
    env.get_int_array_region(&arr, 0, &mut buf)?;
    env.delete_local_ref(arr)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Binary result assembly (doc 09 section 4.1)
// ---------------------------------------------------------------------------

fn assemble_result(private_key: &[u8], cert_chain: &[Vec<u8>]) -> Vec<u8> {
    let total = 4 + private_key.len()
        + 4
        + cert_chain.iter().map(|c| 4 + c.len()).sum::<usize>();

    let mut buf = Vec::with_capacity(total);

    // Private key segment
    buf.extend_from_slice(&(private_key.len() as u32).to_be_bytes());
    buf.extend_from_slice(private_key);

    // Cert count
    buf.extend_from_slice(&(cert_chain.len() as u32).to_be_bytes());

    // Each cert: length-prefixed DER
    for cert in cert_chain {
        buf.extend_from_slice(&(cert.len() as u32).to_be_bytes());
        buf.extend_from_slice(cert);
    }

    buf
}
