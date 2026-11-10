package org.matrix.TEESimulator.attestation

/**
 * Defines constants for KeyMint attestation, mainly the tags of properties and authorizations of a
 * cryptographic key, as specified in the Android hardware security HAL.
 */
object AttestationConstants {
    // https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyCreationResult.aidl

    // These constants represent the fixed positions of fields within the top-level
    // KeyDescription ASN.1 SEQUENCE in a key attestation. Using these constants
    // prevents hardcoding fragile index numbers throughout the parsing code.
    const val KEY_DESCRIPTION_ATTESTATION_VERSION_INDEX = 0
    const val KEY_DESCRIPTION_ATTESTATION_SECURITY_LEVEL_INDEX = 1
    const val KEY_DESCRIPTION_KEYMINT_VERSION_INDEX = 2
    const val KEY_DESCRIPTION_KEYMINT_SECURITY_LEVEL_INDEX = 3
    const val KEY_DESCRIPTION_ATTESTATION_CHALLENGE_INDEX = 4
    const val KEY_DESCRIPTION_UNIQUE_ID_INDEX = 5
    const val KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX = 6
    const val KEY_DESCRIPTION_TEE_ENFORCED_INDEX = 7

    // --- RootOfTrust Sequence Indices ---
    // These constants represent the fixed positions of fields within the
    // RootOfTrust ASN.1 SEQUENCE.
    const val ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX = 0
    const val ROOT_OF_TRUST_DEVICE_LOCKED_INDEX = 1
    const val ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX = 2
    const val ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX = 3

    // https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl

    // --- Key Properties ---
    const val TAG_PURPOSE = 1
    const val TAG_ALGORITHM = 2
    const val TAG_KEY_SIZE = 3
    const val TAG_BLOCK_MODE = 4
    const val TAG_DIGEST = 5
    const val TAG_PADDING = 6
    const val TAG_CALLER_NONCE = 7
    const val TAG_MIN_MAC_LENGTH = 8
    const val TAG_EC_CURVE = 10
    const val TAG_RSA_PUBLIC_EXPONENT = 200
    const val TAG_RSA_OAEP_MGF_DIGEST = 203

    // --- Key Lifetime and Usage Control ---
    const val TAG_ROLLBACK_RESISTANCE = 303
    const val TAG_EARLY_BOOT_ONLY = 305
    const val TAG_ACTIVE_DATETIME = 400
    const val TAG_ORIGINATION_EXPIRE_DATETIME = 401
    const val TAG_USAGE_EXPIRE_DATETIME = 402
    const val TAG_MAX_BOOT_LEVEL = 403
    const val TAG_MAX_USES_PER_BOOT = 404
    const val TAG_USAGE_COUNT_LIMIT = 405

    // --- User Authentication ---
    const val TAG_USER_ID = 501
    const val TAG_USER_SECURE_ID = 502
    const val TAG_NO_AUTH_REQUIRED = 503
    const val TAG_USER_AUTH_TYPE = 504
    const val TAG_AUTH_TIMEOUT = 505
    const val TAG_ALLOW_WHILE_ON_BODY = 506
    const val TAG_TRUSTED_USER_PRESENCE_REQUIRED = 507
    const val TAG_TRUSTED_CONFIRMATION_REQUIRED = 508
    const val TAG_UNLOCKED_DEVICE_REQUIRED = 509

    // --- Attestation and Application Info ---
    const val TAG_APPLICATION_ID = 601
    const val TAG_CREATION_DATETIME = 701
    const val TAG_ORIGIN = 702
    const val TAG_ROOT_OF_TRUST = 704
    const val TAG_OS_VERSION = 705
    const val TAG_OS_PATCHLEVEL = 706
    const val TAG_UNIQUE_ID = 707
    const val TAG_ATTESTATION_CHALLENGE = 708
    const val TAG_ATTESTATION_APPLICATION_ID = 709
    const val TAG_ATTESTATION_ID_BRAND = 710
    const val TAG_ATTESTATION_ID_DEVICE = 711
    const val TAG_ATTESTATION_ID_PRODUCT = 712
    const val TAG_ATTESTATION_ID_SERIAL = 713
    const val TAG_ATTESTATION_ID_IMEI = 714
    const val TAG_ATTESTATION_ID_MEID = 715
    const val TAG_ATTESTATION_ID_MANUFACTURER = 716
    const val TAG_ATTESTATION_ID_MODEL = 717
    const val TAG_VENDOR_PATCHLEVEL = 718
    const val TAG_BOOT_PATCHLEVEL = 719
    const val TAG_DEVICE_UNIQUE_ATTESTATION = 720
    const val TAG_ATTESTATION_ID_SECOND_IMEI = 723
    const val TAG_MODULE_HASH = 724

    // --- Certificate Properties ---
    const val TAG_CERTIFICATE_SERIAL = 1006
    const val TAG_CERTIFICATE_SUBJECT = 1007
    const val TAG_CERTIFICATE_NOT_BEFORE = 1008
    const val TAG_CERTIFICATE_NOT_AFTER = 1009

    // --- Other Constants ---
    // https://cs.android.com/android/platform/superproject/main/+/main:system/keymaster/km_openssl/attestation_record.cpp
    const val CHALLENGE_LENGTH_LIMIT = 128
}
