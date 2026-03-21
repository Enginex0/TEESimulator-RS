package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import android.os.RemoteException
import android.os.ServiceSpecificException
import android.system.keystore2.IKeystoreOperation
import android.system.keystore2.KeyParameters
import java.security.KeyPair
import java.security.Signature
import java.security.SignatureException
import java.util.concurrent.locks.LockSupport
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger

internal object KeystoreErrorCode {
    val INVALID_OPERATION_HANDLE: Int by lazy { resolve("ErrorCode", "INVALID_OPERATION_HANDLE", -28) }
    val VERIFICATION_FAILED: Int by lazy { resolve("ErrorCode", "VERIFICATION_FAILED", -30) }
    val UNSUPPORTED_PURPOSE: Int by lazy { resolve("ErrorCode", "UNSUPPORTED_PURPOSE", -2) }
    val INCOMPATIBLE_PURPOSE: Int by lazy { resolve("ErrorCode", "INCOMPATIBLE_PURPOSE", -3) }
    val INVALID_ARGUMENT: Int by lazy { resolve("ErrorCode", "INVALID_ARGUMENT", -38) }
    val INVALID_TAG: Int by lazy { resolve("ErrorCode", "INVALID_TAG", -40) }
    val INVALID_INPUT_LENGTH: Int by lazy { resolve("ErrorCode", "INVALID_INPUT_LENGTH", -21) }
    val INCOMPATIBLE_KEY: Int by lazy { resolve("ErrorCode", "INCOMPATIBLE_KEY", -31) }
    val INCOMPATIBLE_ALGORITHM: Int by lazy { resolve("ErrorCode", "INCOMPATIBLE_ALGORITHM", -18) }
    val KEY_EXPIRED: Int by lazy { resolve("ErrorCode", "KEY_EXPIRED", -25) }
    val KEY_NOT_YET_VALID: Int by lazy { resolve("ErrorCode", "KEY_NOT_YET_VALID", -24) }
    val CALLER_NONCE_PROHIBITED: Int by lazy { resolve("ErrorCode", "CALLER_NONCE_PROHIBITED", -55) }
    val UNKNOWN_ERROR: Int by lazy { resolve("ErrorCode", "UNKNOWN_ERROR", -1000) }
    val SYSTEM_ERROR: Int by lazy { resolve("ResponseCode", "SYSTEM_ERROR", 4, keystore = true) }
    val TOO_MUCH_DATA: Int by lazy { resolve("ResponseCode", "TOO_MUCH_DATA", 21, keystore = true) }
    val PERMISSION_DENIED: Int by lazy { resolve("ResponseCode", "PERMISSION_DENIED", 6, keystore = true) }
    val KEY_NOT_FOUND: Int by lazy { resolve("ResponseCode", "KEY_NOT_FOUND", 7, keystore = true) }

    private fun resolve(enumName: String, field: String, fallback: Int, keystore: Boolean = false): Int {
        val pkg = if (keystore) "android.system.keystore2" else "android.hardware.security.keymint"
        return runCatching { Class.forName("$pkg.$enumName").getField(field).getInt(null) }
            .getOrDefault(fallback)
    }
}

// A sealed interface to represent the different cryptographic operations we can perform.
private sealed interface CryptoPrimitive {
    fun updateAad(data: ByteArray?)

    fun update(data: ByteArray?): ByteArray?

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?

    fun abort()

    /** Returns parameters from the begin phase (e.g. GCM nonce), or null if none. */
    fun getBeginParameters(): Array<KeyParameter>? = null
}

// Helper object to map KeyMint constants to JCA algorithm strings.
private object JcaAlgorithmMapper {
    fun mapSignatureAlgorithm(params: KeyMintAttestation): String {
        val digest =
            when (params.digest.firstOrNull()) {
                Digest.SHA_2_256 -> "SHA256"
                Digest.SHA_2_384 -> "SHA384"
                Digest.SHA_2_512 -> "SHA512"
                else -> "NONE"
            }
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.EC -> "ECDSA"
                Algorithm.RSA -> "RSA"
                else ->
                    throw ServiceSpecificException(
                        KeystoreErrorCode.SYSTEM_ERROR,
                        "Unsupported signature algorithm: ${params.algorithm}",
                    )
            }
        return "${digest}with${keyAlgo}"
    }

    fun mapCipherAlgorithm(params: KeyMintAttestation): String {
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.RSA -> "RSA"
                Algorithm.AES -> "AES"
                else ->
                    throw ServiceSpecificException(
                        KeystoreErrorCode.SYSTEM_ERROR,
                        "Unsupported cipher algorithm: ${params.algorithm}",
                    )
            }
        val blockMode =
            when (params.blockMode.firstOrNull()) {
                BlockMode.ECB -> "ECB"
                BlockMode.CBC -> "CBC"
                BlockMode.CTR -> "CTR"
                BlockMode.GCM -> "GCM"
                else -> "ECB"
            }
        val padding =
            when (params.padding.firstOrNull()) {
                PaddingMode.NONE -> "NoPadding"
                PaddingMode.PKCS7 -> "PKCS7Padding"
                PaddingMode.RSA_PKCS1_1_5_ENCRYPT -> "PKCS1Padding"
                PaddingMode.RSA_OAEP -> "OAEPPadding"
                else -> "NoPadding" // Default for GCM
            }
        return "$keyAlgo/$blockMode/$padding"
    }
}

// Concrete implementation for Signing.
private class Signer(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initSign(keyPair.private)
        }

    override fun updateAad(data: ByteArray?) {
        throw ServiceSpecificException(KeystoreErrorCode.INVALID_TAG)
    }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
        if (data != null) update(data)
        return this.signature.sign()
    }

    override fun abort() {}
}

// Concrete implementation for Verification.
private class Verifier(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initVerify(keyPair.public)
        }

    override fun updateAad(data: ByteArray?) {
        throw ServiceSpecificException(KeystoreErrorCode.INVALID_TAG)
    }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) update(data)
        if (signature == null)
            throw ServiceSpecificException(
                KeystoreErrorCode.VERIFICATION_FAILED,
                "Signature to verify is null",
            )
        if (!this.signature.verify(signature)) {
            throw ServiceSpecificException(
                KeystoreErrorCode.VERIFICATION_FAILED,
                "Signature/MAC verification failed",
            )
        }
        return null
    }

    override fun abort() {}
}

// Concrete implementation for Encryption/Decryption.
private class CipherPrimitive(
    cryptoKey: java.security.Key,
    params: KeyMintAttestation,
    private val opMode: Int,
) : CryptoPrimitive {
    private val cipher: Cipher =
        Cipher.getInstance(JcaAlgorithmMapper.mapCipherAlgorithm(params)).apply {
            init(opMode, cryptoKey)
        }
    private val isAead = params.blockMode.firstOrNull() == BlockMode.GCM

    override fun updateAad(data: ByteArray?) {
        if (!isAead) throw ServiceSpecificException(KeystoreErrorCode.INVALID_TAG)
        if (data != null) cipher.updateAAD(data)
    }

    override fun update(data: ByteArray?): ByteArray? =
        if (data != null) cipher.update(data) else null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        if (data != null) cipher.doFinal(data) else cipher.doFinal()

    override fun abort() {}

    /** Returns the cipher IV as a NONCE parameter for GCM operations. */
    override fun getBeginParameters(): Array<KeyParameter>? {
        val iv = cipher.iv ?: return null
        return arrayOf(
            KeyParameter().apply {
                tag = Tag.NONCE
                value = KeyParameterValue.blob(iv)
            }
        )
    }
}

// Concrete implementation for ECDH Key Agreement.
private class KeyAgreementPrimitive(keyPair: KeyPair) : CryptoPrimitive {
    private val agreement: javax.crypto.KeyAgreement =
        javax.crypto.KeyAgreement.getInstance("ECDH").apply { init(keyPair.private) }

    override fun updateAad(data: ByteArray?) {
        throw ServiceSpecificException(KeystoreErrorCode.INVALID_TAG)
    }

    override fun update(data: ByteArray?): ByteArray? = null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data == null)
            throw ServiceSpecificException(
                KeystoreErrorCode.INVALID_ARGUMENT,
                "Peer public key required for key agreement",
            )
        val peerKey =
            java.security.KeyFactory.getInstance("EC")
                .generatePublic(java.security.spec.X509EncodedKeySpec(data))
        agreement.doPhase(peerKey, true)
        return agreement.generateSecret()
    }

    override fun abort() {}
}

/**
 * A software-only implementation of a cryptographic operation. This class acts as a controller,
 * delegating to a specific cryptographic primitive based on the operation's purpose.
 *
 * Tracks operation lifecycle: once [finish] or [abort] is called, subsequent calls throw
 * [ServiceSpecificException] with [KeystoreErrorCode.INVALID_OPERATION_HANDLE].
 */
class SoftwareOperation(
    private val txId: Long,
    keyPair: KeyPair?,
    secretKey: javax.crypto.SecretKey?,
    params: KeyMintAttestation,
    private val latencyFloorMs: Long = 0L,
    var onFinishCallback: (() -> Unit)? = null,
) {
    private val primitive: CryptoPrimitive

    @Volatile private var finalized = false

    init {
        val purpose = params.purpose.firstOrNull()
        val purposeName = KeyMintParameterLogger.purposeNames[purpose] ?: "UNKNOWN"
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Initializing for purpose: $purposeName.")

        primitive =
            when (purpose) {
                KeyPurpose.SIGN -> Signer(keyPair!!, params)
                KeyPurpose.VERIFY -> Verifier(keyPair!!, params)
                KeyPurpose.ENCRYPT -> {
                    val key: java.security.Key = secretKey ?: keyPair!!.public
                    CipherPrimitive(key, params, Cipher.ENCRYPT_MODE)
                }
                KeyPurpose.DECRYPT -> {
                    val key: java.security.Key = secretKey ?: keyPair!!.private
                    CipherPrimitive(key, params, Cipher.DECRYPT_MODE)
                }
                KeyPurpose.AGREE_KEY -> KeyAgreementPrimitive(keyPair!!)
                else ->
                    throw ServiceSpecificException(
                        KeystoreErrorCode.UNSUPPORTED_PURPOSE,
                        "Unsupported operation purpose: $purpose",
                    )
            }
    }

    /** Parameters produced during begin (e.g. GCM nonce), to populate CreateOperationResponse. */
    val beginParameters: KeyParameters?
        get() {
            val params = primitive.getBeginParameters() ?: return null
            if (params.isEmpty()) return null
            return KeyParameters().apply { keyParameter = params }
        }

    private fun checkActive() {
        if (finalized)
            throw ServiceSpecificException(
                KeystoreErrorCode.INVALID_OPERATION_HANDLE,
                "Operation already finalized.",
            )
    }

    fun updateAad(data: ByteArray?) {
        checkActive()
        try {
            primitive.updateAad(data)
        } catch (e: ServiceSpecificException) {
            finalized = true
            throw e
        } catch (e: Exception) {
            finalized = true
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to updateAad.", e)
            throw ServiceSpecificException(KeystoreErrorCode.SYSTEM_ERROR, e.message)
        }
    }

    fun update(data: ByteArray?): ByteArray? {
        checkActive()
        try {
            return primitive.update(data)
        } catch (e: ServiceSpecificException) {
            finalized = true
            throw e
        } catch (e: Exception) {
            finalized = true
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to update operation.", e)
            throw mapToServiceSpecificException(e)
        }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        checkActive()
        val startNs = if (latencyFloorMs > 0) System.nanoTime() else 0L
        try {
            val result = primitive.finish(data, signature)
            SystemLogger.info("[SoftwareOp TX_ID: $txId] Finished operation successfully.")
            if (latencyFloorMs > 0) {
                val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
                val delayMs = latencyFloorMs - elapsedMs
                if (delayMs > 0) LockSupport.parkNanos(delayMs * 1_000_000)
            }
            onFinishCallback?.invoke()
            return result
        } catch (e: ServiceSpecificException) {
            throw e
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to finish operation.", e)
            throw mapToServiceSpecificException(e)
        } finally {
            finalized = true
        }
    }

    private fun mapToServiceSpecificException(e: Exception): ServiceSpecificException = when (e) {
        is ServiceSpecificException -> e
        is SignatureException -> ServiceSpecificException(KeystoreErrorCode.VERIFICATION_FAILED, e.message)
        is BadPaddingException -> ServiceSpecificException(KeystoreErrorCode.INVALID_ARGUMENT, e.message)
        is IllegalBlockSizeException -> ServiceSpecificException(KeystoreErrorCode.INVALID_INPUT_LENGTH, e.message)
        is java.security.InvalidKeyException -> ServiceSpecificException(KeystoreErrorCode.INCOMPATIBLE_KEY, e.message)
        else -> ServiceSpecificException(KeystoreErrorCode.UNKNOWN_ERROR, e.message)
    }

    fun abort() {
        checkActive()
        finalized = true
        primitive.abort()
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Operation aborted.")
    }
}

/** Binder interface for [SoftwareOperation]. Synchronized and input-length validated. */
class SoftwareOperationBinder(private val operation: SoftwareOperation) :
    IKeystoreOperation.Stub() {

    private fun checkInputLength(data: ByteArray?) {
        if (data != null && data.size > MAX_RECEIVE_DATA)
            throw ServiceSpecificException(KeystoreErrorCode.TOO_MUCH_DATA)
    }

    @Throws(RemoteException::class)
    override fun updateAad(aadInput: ByteArray?) {
        synchronized(this) {
            checkInputLength(aadInput)
            operation.updateAad(aadInput)
        }
    }

    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? {
        synchronized(this) {
            checkInputLength(input)
            return operation.update(input)
        }
    }

    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? {
        synchronized(this) {
            checkInputLength(input)
            checkInputLength(signature)
            return operation.finish(input, signature)
        }
    }

    @Throws(RemoteException::class)
    override fun abort() {
        synchronized(this) { operation.abort() }
    }

    companion object {
        private const val MAX_RECEIVE_DATA = 0x8000
    }
}
