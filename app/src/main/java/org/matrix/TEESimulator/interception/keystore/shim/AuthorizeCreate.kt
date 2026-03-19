package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.KeyParameter
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
            ?: checkTemporalValidity(keyParams, purpose)
            ?: checkCallerNonce(keyParams, purpose, rawOpParams)
    }

    private fun checkAlgorithmPurpose(keyParams: KeyMintAttestation, purpose: Int): Int? {
        val algo = keyParams.algorithm
        if ((algo == Algorithm.EC || algo == Algorithm.RSA) &&
            (purpose == KeyPurpose.VERIFY || purpose == KeyPurpose.ENCRYPT)
        ) {
            return KeystoreErrorCodes.unsupportedPurpose
        }
        if (algo == Algorithm.EC && purpose == KeyPurpose.DECRYPT)
            return KeystoreErrorCodes.unsupportedPurpose
        if (algo == Algorithm.RSA && purpose == KeyPurpose.AGREE_KEY)
            return KeystoreErrorCodes.unsupportedPurpose
        return null
    }

    private fun checkPurpose(keyParams: KeyMintAttestation, purpose: Int): Int? {
        if (purpose == KeyPurpose.WRAP_KEY)
            return KeystoreErrorCodes.incompatiblePurpose
        if (purpose !in keyParams.purpose)
            return KeystoreErrorCodes.incompatiblePurpose
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

    private fun checkCallerNonce(keyParams: KeyMintAttestation, purpose: Int, rawOpParams: Array<KeyParameter>?): Int? {
        if (purpose != KeyPurpose.SIGN && purpose != KeyPurpose.ENCRYPT) return null
        if (keyParams.callerNonce == true) return null
        if (rawOpParams?.any { it.tag == Tag.NONCE } == true)
            return KeystoreErrorCodes.callerNonceProhibited
        return null
    }
}
