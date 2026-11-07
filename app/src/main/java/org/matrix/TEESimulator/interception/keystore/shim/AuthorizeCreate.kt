package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import org.matrix.TEESimulator.attestation.KeyMintAttestation

object AuthorizeCreate {

    fun check(
        keyParams: KeyMintAttestation?,
        opParams: KeyMintAttestation,
        rawOpParams: Array<KeyParameter>? = null,
    ): Int? {
        if (keyParams == null) return null
        val purpose = opParams.purpose.firstOrNull() ?: return null
        // Algorithm-level rejection runs before purpose-list check (AOSP HAL behavior)
        return checkAlgorithmPurpose(keyParams, purpose)
            ?: checkPurpose(keyParams, purpose)
            ?: checkOperationAuthorizations(keyParams, opParams)
            ?: checkTemporalValidity(keyParams, purpose)
            ?: checkCallerNonce(keyParams, purpose, rawOpParams)
    }

    private fun checkAlgorithmPurpose(keyParams: KeyMintAttestation, purpose: Int): Int? {
        val algo = keyParams.algorithm
        if (
            (algo == Algorithm.EC || algo == Algorithm.RSA) &&
                (purpose == KeyPurpose.VERIFY || purpose == KeyPurpose.ENCRYPT)
        ) {
            return KeystoreErrorCodes.unsupportedPurpose
        }
        if (algo == Algorithm.RSA && purpose == KeyPurpose.AGREE_KEY)
            return KeystoreErrorCodes.unsupportedPurpose
        return null
    }

    private fun checkPurpose(keyParams: KeyMintAttestation, purpose: Int): Int? {
        if (purpose == KeyPurpose.WRAP_KEY) return KeystoreErrorCodes.incompatiblePurpose
        if (purpose !in keyParams.purpose) return KeystoreErrorCodes.incompatiblePurpose
        return null
    }

    /**
     * Validates operation parameters against key authorizations for block mode, padding,
     * primary digest, and RSA-OAEP MGF1 digests per KeyMint AIDL specifications.
     *
     * @param keyParams Authorized key characteristics bound to the key blob.
     * @param opParams Cryptographic operation parameters requested by caller.
     * @return Service-specific error code if authorization fails, or null on success.
     */
    private fun checkOperationAuthorizations(
        keyParams: KeyMintAttestation,
        opParams: KeyMintAttestation,
    ): Int? {
        if (opParams.blockMode.any { it !in keyParams.blockMode }) {
            return KeystoreErrorCodes.incompatibleBlockMode
        }
        if (opParams.padding.any { it !in keyParams.padding }) {
            return KeystoreErrorCodes.incompatiblePaddingMode
        }
        if (opParams.digest.any { it !in keyParams.digest }) {
            return KeystoreErrorCodes.incompatibleDigest
        }
        val effectiveMgfDigests =
            if (opParams.padding.contains(PaddingMode.RSA_OAEP)) {
                if (opParams.rsaOaepMgfDigest.isEmpty()) {
                    if (keyParams.rsaOaepMgfDigest.isNotEmpty()) {
                        listOf(Digest.SHA1)
                    } else {
                        emptyList()
                    }
                } else {
                    opParams.rsaOaepMgfDigest
                }
            } else {
                opParams.rsaOaepMgfDigest
            }

        val supportedMgfDigests: Set<Int> =
            setOf(
                Digest.MD5,
                Digest.SHA1,
                Digest.SHA_2_224,
                Digest.SHA_2_256,
                Digest.SHA_2_384,
                Digest.SHA_2_512,
            )
        if (effectiveMgfDigests.any { it !in supportedMgfDigests }) {
            return KeystoreErrorCodes.unsupportedMgfDigest
        }
        if (effectiveMgfDigests.any { it !in keyParams.rsaOaepMgfDigest }) {
            return KeystoreErrorCodes.incompatibleMgfDigest
        }

        if (keyParams.algorithm == Algorithm.AES && opParams.blockMode.contains(BlockMode.GCM)) {
            val requestedMacLength = opParams.minMacLength
            val keyMinMacLength = keyParams.minMacLength
            if (
                requestedMacLength != null &&
                    keyMinMacLength != null &&
                    requestedMacLength < keyMinMacLength
            ) {
                return KeystoreErrorCodes.invalidMacLength
            }
        }

        if (
            keyParams.algorithm == Algorithm.RSA &&
                opParams.padding.contains(PaddingMode.RSA_OAEP) &&
                opParams.digest.isEmpty()
        ) {
            return KeystoreErrorCodes.incompatibleDigest
        }

        return null
    }

    private fun checkTemporalValidity(keyParams: KeyMintAttestation, purpose: Int): Int? {
        val now = System.currentTimeMillis()

        keyParams.activeDateTime?.let { activeDate ->
            if (now < activeDate.time) return KeystoreErrorCodes.keyNotYetValid
        }

        keyParams.originationExpireDateTime?.let { expireDate ->
            if (purpose == KeyPurpose.SIGN || purpose == KeyPurpose.ENCRYPT) {
                if (now > expireDate.time) return KeystoreErrorCodes.keyExpired
            }
        }

        keyParams.usageExpireDateTime?.let { expireDate ->
            if (purpose == KeyPurpose.VERIFY || purpose == KeyPurpose.DECRYPT) {
                if (now > expireDate.time) return KeystoreErrorCodes.keyExpired
            }
        }

        return null
    }

    private fun checkCallerNonce(
        keyParams: KeyMintAttestation,
        purpose: Int,
        rawOpParams: Array<KeyParameter>?,
    ): Int? {
        if (purpose != KeyPurpose.SIGN && purpose != KeyPurpose.ENCRYPT) return null
        if (keyParams.callerNonce == true) return null
        if (rawOpParams?.any { it.tag == Tag.NONCE } == true)
            return KeystoreErrorCodes.callerNonceProhibited
        return null
    }
}
