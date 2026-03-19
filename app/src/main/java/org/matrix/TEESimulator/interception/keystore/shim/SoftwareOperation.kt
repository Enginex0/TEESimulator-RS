package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import android.os.ServiceSpecificException
import android.system.keystore2.IKeystoreOperation
import android.system.keystore2.KeyParameters
import java.security.KeyPair
import java.security.Signature
import java.security.SignatureException
import javax.crypto.Cipher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger

private sealed interface CryptoPrimitive {
    fun updateAad(aadInput: ByteArray?) {
        throw ServiceSpecificException(KeystoreErrorCodes.invalidTag)
    }
    fun update(data: ByteArray?): ByteArray?
    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?
    fun abort()
    fun getBeginParameters(): Array<KeyParameter>? = null
}

private object JcaAlgorithmMapper {
    fun mapSignatureAlgorithm(params: KeyMintAttestation): String {
        val digest =
            when (params.digest.firstOrNull()) {
                Digest.SHA_2_256 -> "SHA256"
                Digest.SHA_2_384 -> "SHA384"
                Digest.SHA_2_512 -> "SHA512"
                else -> "NONE"
            }
        return when (params.algorithm) {
            Algorithm.EC -> "${digest}withECDSA"
            Algorithm.RSA -> {
                val isPss = params.padding.firstOrNull() == PaddingMode.RSA_PSS
                if (isPss) "${digest}withRSA/PSS" else "${digest}withRSA"
            }
            else ->
                throw ServiceSpecificException(
                    KeystoreErrorCodes.incompatibleAlgorithm,
                    "Unsupported signature algorithm: ${params.algorithm}",
                )
        }
    }

    fun mapCipherAlgorithm(params: KeyMintAttestation): String {
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.RSA -> "RSA"
                Algorithm.AES -> "AES"
                else ->
                    throw ServiceSpecificException(
                        KeystoreErrorCodes.incompatibleAlgorithm,
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
                PaddingMode.RSA_PKCS1_1_5_SIGN -> "PKCS1Padding"
                PaddingMode.RSA_OAEP -> "OAEPPadding"
                else -> "NoPadding"
            }
        return "$keyAlgo/$blockMode/$padding"
    }
}

private class Signer(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initSign(keyPair.private)
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

private class Verifier(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initVerify(keyPair.public)
        }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) update(data)
        if (signature == null) {
            throw ServiceSpecificException(KeystoreErrorCodes.verificationFailed, "Signature to verify is null")
        }
        if (!this.signature.verify(signature)) {
            throw ServiceSpecificException(KeystoreErrorCodes.verificationFailed, "Signature verification failed")
        }
        return null
    }

    override fun abort() {}
}

private class CipherPrimitive(
    cryptoKey: java.security.Key,
    params: KeyMintAttestation,
    private val opMode: Int,
) : CryptoPrimitive {
    private val isAead = params.blockMode.firstOrNull() == BlockMode.GCM
    private val cipher: Cipher =
        Cipher.getInstance(JcaAlgorithmMapper.mapCipherAlgorithm(params)).apply {
            init(opMode, cryptoKey)
        }

    override fun updateAad(aadInput: ByteArray?) {
        if (!isAead) throw ServiceSpecificException(KeystoreErrorCodes.invalidTag)
        if (aadInput != null) cipher.updateAAD(aadInput)
    }

    override fun update(data: ByteArray?): ByteArray? =
        if (data != null) cipher.update(data) else null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        if (data != null) cipher.doFinal(data) else cipher.doFinal()

    override fun getBeginParameters(): Array<KeyParameter>? {
        val iv = cipher.iv ?: return null
        return arrayOf(
            KeyParameter().apply {
                tag = Tag.NONCE
                value = KeyParameterValue.blob(iv)
            }
        )
    }

    override fun abort() {}
}

private class KeyAgreementPrimitive(keyPair: KeyPair) : CryptoPrimitive {
    private val agreement: javax.crypto.KeyAgreement =
        javax.crypto.KeyAgreement.getInstance("ECDH").apply { init(keyPair.private) }

    override fun update(data: ByteArray?): ByteArray? = null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data == null)
            throw ServiceSpecificException(
                KeystoreErrorCodes.invalidArgument,
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

class SoftwareOperation(
    private val txId: Long,
    keyPair: KeyPair?,
    secretKey: javax.crypto.SecretKey?,
    params: KeyMintAttestation,
    private val latencyFloorMs: Long = 0L,
) {
    private val primitive: CryptoPrimitive
    @Volatile var finalized = false
        private set

    var onFinishCallback: (() -> Unit)? = null

    val beginParameters: KeyParameters?
        get() {
            val params = primitive.getBeginParameters() ?: return null
            if (params.isEmpty()) return null
            return KeyParameters().apply { keyParameter = params }
        }

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
                        KeystoreErrorCodes.unsupportedPurpose,
                        "Unsupported operation purpose: $purpose",
                    )
            }
    }

    private fun checkActive() {
        if (finalized) {
            SystemLogger.debug("[SoftwareOp TX_ID: $txId] Rejected: operation already finalized (pruned or completed)")
            throw ServiceSpecificException(KeystoreErrorCodes.invalidOperationHandle)
        }
    }

    private fun checkInputLength(data: ByteArray?) {
        if (data != null && data.size > MAX_RECEIVE_DATA) {
            SystemLogger.info("[SoftwareOp TX_ID: $txId] Input too large: ${data.size} > $MAX_RECEIVE_DATA, throwing TOO_MUCH_DATA(${KeystoreErrorCodes.tooMuchData})")
            throw ServiceSpecificException(KeystoreErrorCodes.tooMuchData)
        }
    }

    fun updateAad(aadInput: ByteArray?) {
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] updateAad() inputSize=${aadInput?.size ?: 0}")
        checkActive()
        checkInputLength(aadInput)
        primitive.updateAad(aadInput)
    }

    fun update(data: ByteArray?): ByteArray? {
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] update() inputSize=${data?.size ?: 0}")
        checkActive()
        checkInputLength(data)
        try {
            return primitive.update(data)
        } catch (e: ServiceSpecificException) {
            throw e
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to update operation.", e)
            throw mapToServiceSpecificException(e)
        }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        checkActive()
        checkInputLength(data)
        try {
            val startNs = if (latencyFloorMs > 0) System.nanoTime() else 0L
            val result = primitive.finish(data, signature)
            if (latencyFloorMs > 0) {
                val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
                val delayMs = latencyFloorMs - elapsedMs
                if (delayMs > 0) Thread.sleep(delayMs)
            }
            finalized = true
            onFinishCallback?.invoke()
            SystemLogger.info("[SoftwareOp TX_ID: $txId] Finished operation successfully.")
            return result
        } catch (e: ServiceSpecificException) {
            throw e
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to finish operation.", e)
            throw mapToServiceSpecificException(e)
        }
    }

    fun abort() {
        finalized = true
        primitive.abort()
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Operation aborted.")
    }

    private fun mapToServiceSpecificException(e: Exception): ServiceSpecificException = when (e) {
        is SignatureException -> ServiceSpecificException(KeystoreErrorCodes.verificationFailed, e.message)
        is javax.crypto.BadPaddingException -> ServiceSpecificException(KeystoreErrorCodes.invalidArgument, e.message)
        is javax.crypto.IllegalBlockSizeException -> ServiceSpecificException(KeystoreErrorCodes.invalidInputLength, e.message)
        is java.security.InvalidKeyException -> ServiceSpecificException(KeystoreErrorCodes.incompatibleKey, e.message)
        else -> ServiceSpecificException(KeystoreErrorCodes.unknownError, e.message)
    }

    companion object {
        private const val MAX_RECEIVE_DATA = 0x8000
    }
}

internal object KeystoreErrorCodes {
    val tooMuchData: Int by lazy {
        resolveField("android.system.keystore2.ResponseCode", "TOO_MUCH_DATA", 21)
    }

    val invalidOperationHandle: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INVALID_OPERATION_HANDLE", -28)
    }

    val invalidTag: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INVALID_TAG", -76)
    }

    val verificationFailed: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "VERIFICATION_FAILED", -30)
    }

    val invalidArgument: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INVALID_ARGUMENT", -38)
    }

    val invalidInputLength: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INVALID_INPUT_LENGTH", -21)
    }

    val incompatibleKey: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_KEY", -31)
    }

    val incompatiblePurpose: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_PURPOSE", -13)
    }

    val unsupportedPurpose: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "UNSUPPORTED_PURPOSE", -14)
    }

    val incompatibleAlgorithm: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "INCOMPATIBLE_ALGORITHM", -18)
    }

    val keyNotYetValid: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "KEY_NOT_YET_VALID", -39)
    }

    val keyExpired: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "KEY_EXPIRED", -40)
    }

    val callerNonceProhibited: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "CALLER_NONCE_PROHIBITED", -55)
    }

    val unknownError: Int by lazy {
        resolveField("android.hardware.security.keymint.ErrorCode", "UNKNOWN_ERROR", -1000)
    }

    fun resolveField(className: String, fieldName: String, fallback: Int): Int =
        runCatching {
            Class.forName(className).getField(fieldName).getInt(null)
        }.getOrElse {
            SystemLogger.debug("Resolved $className.$fieldName via fallback: $fallback")
            fallback
        }
}

class SoftwareOperationBinder(private val operation: SoftwareOperation) :
    IKeystoreOperation.Stub() {

    @Synchronized
    override fun updateAad(aadInput: ByteArray?) {
        operation.updateAad(aadInput)
    }

    @Synchronized
    override fun update(input: ByteArray?): ByteArray? {
        return operation.update(input)
    }

    @Synchronized
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? {
        return operation.finish(input, signature)
    }

    @Synchronized
    override fun abort() {
        operation.abort()
    }
}
