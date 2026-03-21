package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.*
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.Certificate
import java.util.concurrent.CompletableFuture
import android.util.Pair as AndroidPair
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.LockSupport
import org.matrix.TEESimulator.attestation.AttestationBuilder
import org.matrix.TEESimulator.attestation.AttestationConstants
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertGenConfig
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper
import org.matrix.TEESimulator.pki.KeyBoxManager
import org.matrix.TEESimulator.pki.NativeCertGen
import org.matrix.TEESimulator.util.AndroidDeviceUtils
import org.matrix.TEESimulator.util.TeeLatencySimulator

/**
 * Intercepts calls to an `IKeystoreSecurityLevel` service (e.g., TEE or StrongBox). This is where
 * the core logic for key generation and import handling for modern Android resides.
 */
class KeyMintSecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val securityLevel: Int,
) : BinderInterceptor() {

    private val recentOps = ConcurrentHashMap<Int, ConcurrentLinkedDeque<Long>>()
    private val activeOps = ConcurrentHashMap<Int, ConcurrentLinkedDeque<SoftwareOperation>>()

    data class GeneratedKeyInfo(
        val keyPair: KeyPair?,
        val secretKey: javax.crypto.SecretKey?,
        val nspace: Long,
        val response: KeyEntryResponse,
        val keyParams: KeyMintAttestation,
    )

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        val shouldSkip = ConfigurationManager.shouldSkipUid(callingUid)

        when (code) {
            GENERATE_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                if (!shouldSkip) return handleGenerateKey(txId, callingUid, callingPid, data)
            }
            CREATE_OPERATION_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                if (!shouldSkip) return handleCreateOperation(txId, callingUid, data)
            }
            IMPORT_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost
                SystemLogger.info(
                    "[TX_ID: $txId] Forward to post-importKey hook for ${keyDescriptor.alias}[${keyDescriptor.nspace}]"
                )
                return TransactionResult.Continue
            }
        }

        logTransaction(
            txId,
            transactionNames[code] ?: "unknown code=$code",
            callingUid,
            callingPid,
            true,
        )

        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        // We only care about successful transactions.
        if (resultCode != 0 || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        if (code == IMPORT_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
            cleanupKeyData(keyId)
            importedKeys.add(keyId)

            // Patch imported key certificates the same way as generated keys.
            if (!ConfigurationManager.shouldSkipUid(callingUid)) {
                val metadata: KeyMetadata =
                    reply.readTypedObject(KeyMetadata.CREATOR)
                        ?: return TransactionResult.SkipTransaction
                val originalChain = CertificateHelper.getCertificateChain(metadata)
                if (originalChain != null && originalChain.size > 1) {
                    val newChain =
                        AttestationPatcher.patchCertificateChain(originalChain, callingUid)
                    CertificateHelper.updateCertificateChain(metadata, newChain).getOrThrow()
                    metadata.authorizations =
                        InterceptorUtils.patchAuthorizations(metadata.authorizations, callingUid)
                    patchedChains[keyId] = newChain
                    teeResponses[keyId] = KeyEntryResponse().apply {
                        this.metadata = metadata
                        iSecurityLevel = original
                    }
                    SystemLogger.debug("Cached patched certificate chain for imported key $keyId.")
                    return InterceptorUtils.createTypedObjectReply(metadata)
                }
            }
        } else if (code == CREATE_OPERATION_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                ?: return TransactionResult.SkipTransaction
            val params = data.createTypedArray(KeyParameter.CREATOR)
                ?: return TransactionResult.SkipTransaction
            val parsedParams = KeyMintAttestation(params)
            val forced = data.readBoolean()
            if (forced)
                SystemLogger.verbose(
                    "[TX_ID: $txId] Current operation has a very high pruning power."
                )
            val response: CreateOperationResponse =
                reply.readTypedObject(CreateOperationResponse.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            SystemLogger.verbose(
                "[TX_ID: $txId] CreateOperationResponse: ${response.iOperation} ${response.operationChallenge}"
            )

            // Intercept the IKeystoreOperation binder
            response.iOperation?.let { operation ->
                val operationBinder = operation.asBinder()
                if (!interceptedOperations.containsKey(operationBinder)) {
                    SystemLogger.info("Found new IKeystoreOperation. Registering interceptor...")
                    val backdoor = getBackdoor(target)
                    if (backdoor != null) {
                        val interceptor = OperationInterceptor(operation, backdoor)
                        register(
                            backdoor,
                            operationBinder,
                            interceptor,
                            OperationInterceptor.INTERCEPTED_CODES,
                        )
                        interceptedOperations[operationBinder] = interceptor
                    } else {
                        SystemLogger.error(
                            "Failed to get backdoor to register OperationInterceptor."
                        )
                    }
                }
            }
        } else if (code == GENERATE_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            val metadata: KeyMetadata =
                reply.readTypedObject(KeyMetadata.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            val originalChain =
                CertificateHelper.getCertificateChain(metadata)
                    ?: return TransactionResult.SkipTransaction
            if (originalChain.size > 1) {
                val newChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)

                // Cache the newly patched chain to ensure consistency across subsequent API calls.
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction
                val key = metadata.key
                    ?: return TransactionResult.SkipTransaction
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                CertificateHelper.updateCertificateChain(metadata, newChain).getOrThrow()
                metadata.authorizations =
                    InterceptorUtils.patchAuthorizations(metadata.authorizations, callingUid)

                cleanupKeyData(keyId)
                patchedChains[keyId] = newChain

                teeResponses[keyId] = KeyEntryResponse().apply {
                    this.metadata = metadata
                    iSecurityLevel = original
                }

                SystemLogger.debug(
                    "Cached patched certificate chain for $keyId. (${key.alias} [${key.domain}, ${key.nspace}])"
                )

                return InterceptorUtils.createTypedObjectReply(metadata)
            }
        }
        return TransactionResult.SkipTransaction
    }

    private fun trackAndEnforceOpLimit(callingUid: Int, securityLevel: Int) {
        if (securityLevel != SecurityLevel.STRONGBOX) return
        val timestamps = recentOps.computeIfAbsent(callingUid) { ConcurrentLinkedDeque() }
        val cutoff = System.nanoTime() - STRONGBOX_OP_WINDOW_NS
        timestamps.removeIf { it < cutoff }
        if (timestamps.size >= STRONGBOX_MAX_CONCURRENT_OPS) {
            throw android.os.ServiceSpecificException(
                KEYMINT_TOO_MANY_OPERATIONS,
                "StrongBox op limit reached for uid=$callingUid"
            )
        }
        timestamps.addLast(System.nanoTime())
    }

    private fun pruneOpsForUid(callingUid: Int, newOp: SoftwareOperation) {
        val ops = activeOps.computeIfAbsent(callingUid) { ConcurrentLinkedDeque() }
        ops.removeIf { it.isFinalized }
        while (ops.size >= MAX_CONCURRENT_OPS_PER_UID) {
            val oldest = ops.pollFirst() ?: break
            oldest.abort()
            SystemLogger.debug("Pruned oldest op for uid=$callingUid (LRU eviction)")
        }
        ops.addLast(newOp)
    }

    private fun handleCreateOperation(
        txId: Long,
        callingUid: Int,
        data: Parcel,
    ): TransactionResult {
        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
        val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            ?: return TransactionResult.ContinueAndSkipPost

        val resolvedEntry: Map.Entry<KeyIdentifier, GeneratedKeyInfo>? =
            when (keyDescriptor.domain) {
                Domain.KEY_ID -> {
                    val nspace = keyDescriptor.nspace
                    if (nspace == 0L) null
                    else
                        generatedKeys.entries
                            .filter { it.key.uid == callingUid }
                            .find { it.value.nspace == nspace }
                }
                Domain.APP ->
                    keyDescriptor.alias?.let { alias ->
                        val key = KeyIdentifier(callingUid, alias)
                        generatedKeys[key]?.let { java.util.AbstractMap.SimpleEntry(key, it) }
                    }
                else -> null
            }
        val generatedKeyInfo = resolvedEntry?.value
        val resolvedKeyId = resolvedEntry?.key

        if (generatedKeyInfo == null) {
            SystemLogger.debug(
                "[TX_ID: $txId] Operation for unknown/hardware key (domain=${keyDescriptor.domain}, " +
                    "alias=${keyDescriptor.alias}, nspace=${keyDescriptor.nspace}). Forwarding."
            )
            return TransactionResult.Continue
        }

        SystemLogger.info(
            "[TX_ID: $txId] Creating SOFTWARE operation for key ${generatedKeyInfo.nspace}."
        )

        trackAndEnforceOpLimit(callingUid, securityLevel)

        val opParams = data.createTypedArray(KeyParameter.CREATOR)!!
        val parsedOpParams = KeyMintAttestation(opParams)
        val forced = data.readBoolean()

        val requestedPurpose = parsedOpParams.purpose.firstOrNull()
        if (requestedPurpose == null) {
            return InterceptorUtils.createServiceSpecificErrorReply(KEYMINT_INVALID_ARGUMENT)
        }

        if (forced) {
            return InterceptorUtils.createServiceSpecificErrorReply(PERMISSION_DENIED)
        }

        val keyParams = generatedKeyInfo.keyParams

        val algorithm = keyParams.algorithm
        val isAsymmetric = algorithm == Algorithm.EC || algorithm == Algorithm.RSA
        val unsupported =
            (isAsymmetric &&
                (requestedPurpose == KeyPurpose.VERIFY ||
                    requestedPurpose == KeyPurpose.ENCRYPT)) ||
                (requestedPurpose == KeyPurpose.AGREE_KEY && algorithm != Algorithm.EC) ||
                (algorithm == Algorithm.EC && requestedPurpose == KeyPurpose.DECRYPT)
        if (unsupported) {
            return InterceptorUtils.createServiceSpecificErrorReply(
                KeystoreErrorCode.UNSUPPORTED_PURPOSE
            )
        }

        if (requestedPurpose == KeyPurpose.WRAP_KEY) {
            return InterceptorUtils.createServiceSpecificErrorReply(
                KeystoreErrorCode.INCOMPATIBLE_PURPOSE
            )
        }

        if (requestedPurpose !in keyParams.purpose) {
            SystemLogger.info(
                "[TX_ID: $txId] Rejecting: purpose $requestedPurpose not in ${keyParams.purpose}"
            )
            return InterceptorUtils.createServiceSpecificErrorReply(
                KeystoreErrorCode.INCOMPATIBLE_PURPOSE
            )
        }

        keyParams.activeDateTime?.let { activeDate ->
            if (System.currentTimeMillis() < activeDate.time) {
                return InterceptorUtils.createServiceSpecificErrorReply(
                    KeystoreErrorCode.KEY_NOT_YET_VALID
                )
            }
        }

        // ORIGINATION_EXPIRE applies to SIGN/ENCRYPT only.
        keyParams.originationExpireDateTime?.let { expireDate ->
            if (
                (requestedPurpose == KeyPurpose.SIGN ||
                    requestedPurpose == KeyPurpose.ENCRYPT) &&
                    System.currentTimeMillis() > expireDate.time
            ) {
                return InterceptorUtils.createServiceSpecificErrorReply(
                    KeystoreErrorCode.KEY_EXPIRED
                )
            }
        }

        // USAGE_EXPIRE applies to DECRYPT/VERIFY only.
        keyParams.usageExpireDateTime?.let { expireDate ->
            if (
                (requestedPurpose == KeyPurpose.DECRYPT ||
                    requestedPurpose == KeyPurpose.VERIFY) &&
                    System.currentTimeMillis() > expireDate.time
            ) {
                return InterceptorUtils.createServiceSpecificErrorReply(
                    KeystoreErrorCode.KEY_EXPIRED
                )
            }
        }

        if (
            (requestedPurpose == KeyPurpose.SIGN || requestedPurpose == KeyPurpose.ENCRYPT) &&
                keyParams.callerNonce != true &&
                opParams.any { it.tag == Tag.NONCE }
        ) {
            return InterceptorUtils.createServiceSpecificErrorReply(
                KeystoreErrorCode.CALLER_NONCE_PROHIBITED
            )
        }

        return runCatching {
                // Use key params for crypto properties (algorithm, digest, etc.) but
                // override purpose from the operation params.
                val effectiveParams =
                    keyParams.copy(purpose = parsedOpParams.purpose, digest = parsedOpParams.digest.ifEmpty { keyParams.digest })
                val opLatency = if (securityLevel == SecurityLevel.STRONGBOX) STRONGBOX_OP_LATENCY_FLOOR_MS else 0L
                val softwareOperation =
                    SoftwareOperation(
                        txId,
                        generatedKeyInfo.keyPair,
                        generatedKeyInfo.secretKey,
                        effectiveParams,
                        opLatency,
                    )
                pruneOpsForUid(callingUid, softwareOperation)

                // Decrement usage counter on finish; delete key when exhausted.
                if (keyParams.usageCountLimit != null && resolvedKeyId != null) {
                    val limit = keyParams.usageCountLimit
                    val remaining =
                        usageCounters.getOrPut(resolvedKeyId) {
                            java.util.concurrent.atomic.AtomicInteger(limit)
                        }
                    if (remaining.get() <= 0) {
                        cleanupKeyData(resolvedKeyId)
                        usageCounters.remove(resolvedKeyId)
                        throw android.os.ServiceSpecificException(KeystoreErrorCode.KEY_NOT_FOUND)
                    }
                    softwareOperation.onFinishCallback = {
                        if (remaining.decrementAndGet() <= 0) {
                            cleanupKeyData(resolvedKeyId)
                            usageCounters.remove(resolvedKeyId)
                        }
                    }
                }

                val operationBinder = SoftwareOperationBinder(softwareOperation)

                val response =
                    CreateOperationResponse().apply {
                        iOperation = operationBinder
                        operationChallenge = null
                        parameters = softwareOperation.beginParameters
                    }

                InterceptorUtils.createTypedObjectReply(response)
            }
            .getOrElse { e ->
                SystemLogger.error("[TX_ID: $txId] Failed to create software operation.", e)
                InterceptorUtils.createServiceSpecificErrorReply(
                    if (e is android.os.ServiceSpecificException) e.errorCode
                    else KeystoreErrorCode.SYSTEM_ERROR
                )
            }
    }

    /**
     * Handles the `generateKey` transaction. Based on the configuration for the calling UID, it
     * either generates a key in software or lets the call pass through to the hardware.
     */
    private fun handleGenerateKey(txId: Long, callingUid: Int, callingPid: Int, data: Parcel): TransactionResult {
        if (data.dataSize() > MAX_ALIAS_LENGTH) {
            SystemLogger.warning("Skipping oversized transaction: ${data.dataSize()} bytes")
            return InterceptorUtils.createErrorReply(KEYMINT_INVALID_INPUT_LENGTH)
        }

        return runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return@runCatching TransactionResult.ContinueAndSkipPost
                val attestationKey = data.readTypedObject(KeyDescriptor.CREATOR)
                SystemLogger.debug(
                    "Handling generateKey ${keyDescriptor.alias}, attestKey=${attestationKey?.alias}"
                )

                val params = data.createTypedArray(KeyParameter.CREATOR)
                    ?: return@runCatching TransactionResult.ContinueAndSkipPost
                val parsedParams = KeyMintAttestation(params)

                val challenge = parsedParams.attestationChallenge
                if (challenge != null && challenge.size > AttestationConstants.CHALLENGE_LENGTH_LIMIT) {
                    SystemLogger.warning("[TX_ID: $txId] Rejecting oversized attestation challenge: ${challenge.size} bytes (max ${AttestationConstants.CHALLENGE_LENGTH_LIMIT})")
                    return InterceptorUtils.createErrorReply(KEYMINT_INVALID_INPUT_LENGTH)
                }

                if (params.any { it.tag == Tag.CREATION_DATETIME }) {
                    SystemLogger.warning("[TX_ID: $txId] Rejecting CREATION_DATETIME in generateKey params")
                    return InterceptorUtils.createErrorReply(INVALID_ARGUMENT)
                }

                val hasDeviceIdTags =
                    params.any {
                        it.tag == Tag.ATTESTATION_ID_SERIAL ||
                            it.tag == Tag.ATTESTATION_ID_IMEI ||
                            it.tag == Tag.ATTESTATION_ID_MEID ||
                            it.tag == Tag.DEVICE_UNIQUE_ATTESTATION ||
                            it.tag == Tag.ATTESTATION_ID_SECOND_IMEI
                    }
                if (
                    hasDeviceIdTags &&
                        !ConfigurationManager.hasPermissionForUid(
                            callingUid,
                            "android.permission.READ_PRIVILEGED_PHONE_STATE",
                        )
                ) {
                    return InterceptorUtils.createErrorReply(CANNOT_ATTEST_IDS)
                }

                if (params.any { it.tag == Tag.INCLUDE_UNIQUE_ID }) {
                    val hasSELinux =
                        ConfigurationManager.checkSELinuxPermission(
                            callingPid,
                            "keystore_key",
                            "gen_unique_id",
                        )
                    val hasAndroid =
                        ConfigurationManager.hasPermissionForUid(
                            callingUid,
                            "android.permission.REQUEST_UNIQUE_ID_ATTESTATION",
                        )
                    if (!hasSELinux && !hasAndroid) {
                        return InterceptorUtils.createServiceSpecificErrorReply(PERMISSION_DENIED)
                    }
                }
                val isAttestKeyRequest = parsedParams.isAttestKey()

                val forceGenerate =
                    ConfigurationManager.shouldGenerate(callingUid) ||
                        (ConfigurationManager.shouldPatch(callingUid) && isAttestKeyRequest) ||
                        (attestationKey != null &&
                            isAttestationKey(KeyIdentifier(callingUid, attestationKey.alias)))

                val isAuto = ConfigurationManager.isAutoMode(callingUid)

                val isStrongBox = securityLevel == SecurityLevel.STRONGBOX

                if (isStrongBox && !isStrongBoxCapable(parsedParams)) {
                    SystemLogger.info("[TX_ID: $txId] StrongBox-unsupported params (algo=${parsedParams.algorithm} size=${parsedParams.keySize}), forwarding to HAL")
                    return TransactionResult.ContinueAndSkipPost
                }

                when {
                    forceGenerate -> doSoftwareGeneration(
                        callingUid, keyDescriptor, attestationKey, parsedParams, isAttestKeyRequest
                    )
                    // StrongBox before TEE-race: broken StrongBox HALs must never reach raceTeePatch
                    isAuto && isStrongBox -> doSoftwareGeneration(
                        callingUid, keyDescriptor, attestationKey, parsedParams, isAttestKeyRequest
                    )
                    isAuto && !teeFunctional -> raceTeePatch(
                        callingUid, keyDescriptor, attestationKey, params, parsedParams, isAttestKeyRequest
                    )
                    parsedParams.attestationChallenge != null -> TransactionResult.Continue
                    else -> TransactionResult.ContinueAndSkipPost
                }
            }
            .getOrElse { e ->
                SystemLogger.error("No key pair generated for UID $callingUid.", e)
                val code =
                    if (e is android.os.ServiceSpecificException) e.errorCode
                    else SECURE_HW_COMMUNICATION_FAILED
                InterceptorUtils.createServiceSpecificErrorReply(code)
            }
    }

    /** Performs software key generation and caches the result. */
    private fun doSoftwareGeneration(
        callingUid: Int,
        keyDescriptor: KeyDescriptor,
        attestationKey: KeyDescriptor?,
        parsedParams: KeyMintAttestation,
        isAttestKeyRequest: Boolean,
    ): TransactionResult {
        val genStartNanos = System.nanoTime()
        keyDescriptor.nspace = secureRandom.nextLong()
        SystemLogger.info(
            "Generating software key for ${keyDescriptor.alias}[${keyDescriptor.nspace}]."
        )

        val isSymmetric =
            parsedParams.algorithm != Algorithm.EC && parsedParams.algorithm != Algorithm.RSA

        val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
        cleanupKeyData(keyId)

        if (isSymmetric) {
            val algoName =
                when (parsedParams.algorithm) {
                    Algorithm.AES -> "AES"
                    Algorithm.HMAC -> "HmacSHA256"
                    else -> throw android.os.ServiceSpecificException(
                        SECURE_HW_COMMUNICATION_FAILED,
                        "Unsupported symmetric algorithm: ${parsedParams.algorithm}",
                    )
                }
            val keyGen = javax.crypto.KeyGenerator.getInstance(algoName)
            keyGen.init(parsedParams.keySize)
            val secretKey = keyGen.generateKey()

            val metadata = KeyMetadata().apply {
                keySecurityLevel = securityLevel
                key = KeyDescriptor().apply {
                    domain = Domain.KEY_ID
                    nspace = keyDescriptor.nspace
                    alias = null
                    blob = null
                }
                certificate = null
                certificateChain = null
                authorizations = parsedParams.toAuthorizations(callingUid, securityLevel)
                modificationTimeMs = System.currentTimeMillis()
            }
            val response = KeyEntryResponse().apply {
                this.metadata = metadata
                iSecurityLevel = original
            }
            generatedKeys[keyId] =
                GeneratedKeyInfo(null, secretKey, keyDescriptor.nspace, response, parsedParams)

            if (securityLevel == SecurityLevel.STRONGBOX) {
                val delayMs = STRONGBOX_KEYGEN_LATENCY_FLOOR_MS - (System.nanoTime() - genStartNanos) / 1_000_000
                if (delayMs > 0) LockSupport.parkNanos(delayMs * 1_000_000)
            } else {
                TeeLatencySimulator.simulateGenerateKeyDelay(
                    parsedParams.algorithm, System.nanoTime() - genStartNanos
                )
            }
            return InterceptorUtils.createTypedObjectReply(metadata)
        }

        val keyData = if (NativeCertGen.isAvailable && attestationKey == null) {
            generateAttestedKeyPairNative(callingUid, parsedParams)
                ?: CertificateGenerator.generateAttestedKeyPair(
                    callingUid, keyDescriptor.alias, attestationKey?.alias,
                    parsedParams, securityLevel,
                )
        } else {
            CertificateGenerator.generateAttestedKeyPair(
                callingUid, keyDescriptor.alias, attestationKey?.alias,
                parsedParams, securityLevel,
            )
        } ?: throw Exception("Certificate generation failed.")

        val response =
            buildKeyEntryResponse(callingUid, keyData.second, parsedParams, keyDescriptor)
        generatedKeys[keyId] =
            GeneratedKeyInfo(keyData.first, null, keyDescriptor.nspace, response, parsedParams)
        if (isAttestKeyRequest) attestationKeys.add(keyId)

        val certChainCopy = keyData.second.toList()
        persistExecutor.execute {
            GeneratedKeyPersistence.save(
                keyId = keyId,
                keyPair = keyData.first,
                nspace = keyDescriptor.nspace,
                securityLevel = securityLevel,
                certChain = certChainCopy,
                algorithm = parsedParams.algorithm,
                keySize = parsedParams.keySize,
                ecCurve = parsedParams.ecCurve ?: 0,
                purposes = parsedParams.purpose,
                digests = parsedParams.digest,
                isAttestationKey = isAttestKeyRequest,
            )
        }

        if (securityLevel == SecurityLevel.STRONGBOX) {
            val delayMs = STRONGBOX_KEYGEN_LATENCY_FLOOR_MS - (System.nanoTime() - genStartNanos) / 1_000_000
            if (delayMs > 0) LockSupport.parkNanos(delayMs * 1_000_000)
        } else {
            TeeLatencySimulator.simulateGenerateKeyDelay(
                parsedParams.algorithm, System.nanoTime() - genStartNanos
            )
        }
        return InterceptorUtils.createTypedObjectReply(response.metadata)
    }

    private fun generateAttestedKeyPairNative(
        callingUid: Int,
        params: KeyMintAttestation,
    ): AndroidPair<KeyPair, List<Certificate>>? {
        return runCatching {
            val algorithmName = when (params.algorithm) {
                Algorithm.EC -> "EC"
                Algorithm.RSA -> "RSA"
                else -> return null
            }
            val keyboxFile = ConfigurationManager.getKeyboxFileForUid(callingUid)
            val keybox = KeyBoxManager.getAttestationKey(keyboxFile, algorithmName) ?: return null

            val keyboxCertChainBytes = keybox.certificates
                .map { it.encoded }
                .fold(ByteArray(0)) { acc, der -> acc + der }

            val attestVersion = AndroidDeviceUtils.getAttestVersion(securityLevel)
            val config = CertGenConfig(
                algorithm = params.algorithm,
                keySize = params.keySize,
                ecCurve = params.ecCurve ?: 0,
                rsaPublicExponent = params.rsaPublicExponent?.toLong() ?: 65537L,
                attestationChallenge = params.attestationChallenge,
                purposes = params.purpose.toIntArray(),
                digests = params.digest.toIntArray(),
                certSerial = params.certificateSerial?.toByteArray(),
                certSubject = params.certificateSubject?.encoded,
                certNotBefore = params.certificateNotBefore?.time ?: -1L,
                certNotAfter = params.certificateNotAfter?.time ?: -1L,
                keyboxPrivateKey = keybox.keyPair.private.encoded,
                keyboxCertChain = keyboxCertChainBytes,
                securityLevel = securityLevel,
                attestVersion = attestVersion,
                keymasterVersion = AndroidDeviceUtils.getKeymasterVersion(securityLevel),
                osVersion = AndroidDeviceUtils.osVersion,
                osPatchLevel = AndroidDeviceUtils.getPatchLevel(callingUid),
                vendorPatchLevel = AndroidDeviceUtils.getVendorPatchLevelLong(callingUid),
                bootPatchLevel = AndroidDeviceUtils.getBootPatchLevelLong(callingUid),
                bootKey = AndroidDeviceUtils.bootKey,
                bootHash = AndroidDeviceUtils.bootHash,
                creationDatetime = System.currentTimeMillis(),
                attestationApplicationId = AttestationBuilder.createApplicationId(callingUid).octets,
                moduleHash = if (attestVersion >= 400) AndroidDeviceUtils.moduleHash else null,
                idBrand = params.brand,
                idDevice = params.device,
                idProduct = params.product,
                idSerial = params.serial,
                idImei = params.imei,
                idMeid = params.meid,
                idManufacturer = params.manufacturer,
                idModel = params.model,
                idSecondImei = if (attestVersion >= 300) params.secondImei else null,
                activeDatetime = params.activeDateTime?.time ?: -1L,
                originationExpireDatetime = params.originationExpireDateTime?.time ?: -1L,
                usageExpireDatetime = params.usageExpireDateTime?.time ?: -1L,
                usageCountLimit = params.usageCountLimit ?: -1,
                callerNonce = params.callerNonce == true,
                unlockedDeviceRequired = params.unlockedDeviceRequired == true,
                noAuthRequired = params.noAuthRequired != false,
            )

            val resultBytes = NativeCertGen.generateAttestedKeyPair(config) ?: return null
            val (keyPair, certs) = NativeCertGen.parseNativeResult(resultBytes)
            SystemLogger.info("NativeCertGen: ${certs.size} certs generated")
            AndroidPair(keyPair, certs)
        }.onFailure {
            SystemLogger.error("NativeCertGen failed, falling back to BouncyCastle", it)
        }.getOrNull()
    }

    fun loadPersistedKeys() {
        val records = GeneratedKeyPersistence.loadAll(securityLevel)
        if (records.isEmpty()) return

        SystemLogger.info("Restoring ${records.size} persisted keys for security level $securityLevel")
        for (record in records) {
            runCatching {
                val keyId = KeyIdentifier(record.uid, record.alias)
                if (generatedKeys.containsKey(keyId)) return@runCatching

                val algorithmName = when (record.algorithm) {
                    Algorithm.EC -> "EC"
                    Algorithm.RSA -> "RSA"
                    else -> throw IllegalArgumentException("Unknown algorithm: ${record.algorithm}")
                }

                val keyFactory = KeyFactory.getInstance(algorithmName)
                val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(record.privateKeyBytes))

                val certFactory = CertificateFactory.getInstance("X.509")
                val certChain = record.certChainBytes.map { bytes ->
                    certFactory.generateCertificate(ByteArrayInputStream(bytes))
                }
                require(certChain.isNotEmpty()) { "Empty certificate chain" }

                val keyPair = KeyPair(certChain[0].publicKey, privateKey)
                val descriptor = KeyDescriptor().apply {
                    domain = Domain.APP
                    nspace = record.nspace
                    alias = record.alias
                    blob = null
                }

                val attestation = KeyMintAttestation(
                    algorithm = record.algorithm,
                    ecCurve = if (record.algorithm == Algorithm.EC) record.ecCurve else null,
                    ecCurveName = "",
                    keySize = record.keySize,
                    origin = null,
                    noAuthRequired = null,
                    blockMode = emptyList(),
                    padding = emptyList(),
                    purpose = record.purposes,
                    digest = record.digests,
                    rsaPublicExponent = null,
                    certificateSerial = null,
                    certificateSubject = null,
                    certificateNotBefore = null,
                    certificateNotAfter = null,
                    attestationChallenge = null,
                    brand = null, device = null, product = null, serial = null,
                    imei = null, meid = null, manufacturer = null, model = null,
                    secondImei = null,
                    activeDateTime = null,
                    originationExpireDateTime = null,
                    usageExpireDateTime = null,
                    usageCountLimit = null,
                    callerNonce = null,
                    unlockedDeviceRequired = null,
                    includeUniqueId = null,
                    rollbackResistance = null,
                    earlyBootOnly = null,
                    allowWhileOnBody = null,
                    trustedUserPresenceRequired = null,
                    trustedConfirmationRequired = null,
                    maxUsesPerBoot = null,
                    maxBootLevel = null,
                    minMacLength = null,
                    rsaOaepMgfDigest = emptyList(),
                )

                val response = buildKeyEntryResponse(record.uid, certChain, attestation, descriptor)
                generatedKeys[keyId] = GeneratedKeyInfo(keyPair, null, record.nspace, response, attestation)
                if (record.isAttestationKey) attestationKeys.add(keyId)
                SystemLogger.debug("Restored persisted key: $keyId")
            }.onFailure {
                SystemLogger.error("Failed to restore key: uid=${record.uid} alias=${record.alias}", it)
            }
        }
        SystemLogger.info("Key restoration complete. Total in memory: ${generatedKeys.size}")
    }

    /**
     * Races TEE hardware generation against software generation concurrently for AUTO mode.
     * If TEE succeeds, the software future is cancelled and TEE is marked functional.
     * If TEE fails, the already-running software result is used without additional delay.
     */
    private fun raceTeePatch(
        callingUid: Int,
        keyDescriptor: KeyDescriptor,
        attestationKey: KeyDescriptor?,
        rawParams: Array<KeyParameter>,
        parsedParams: KeyMintAttestation,
        isAttestKeyRequest: Boolean,
    ): TransactionResult {
        SystemLogger.info("AUTO: racing TEE vs software for ${keyDescriptor.alias}")

        val teeDescriptor = KeyDescriptor().apply {
            domain = keyDescriptor.domain
            nspace = keyDescriptor.nspace
            alias = keyDescriptor.alias
            blob = keyDescriptor.blob
        }
        val teeAttestKey =
            attestationKey?.let {
                KeyDescriptor().apply {
                    domain = it.domain
                    nspace = it.nspace
                    alias = it.alias
                    blob = it.blob
                }
            }

        val threadA = CompletableFuture.supplyAsync {
            original.generateKey(teeDescriptor, teeAttestKey, rawParams, 0, byteArrayOf())
        }

        val swDescriptor = KeyDescriptor().apply {
            domain = keyDescriptor.domain
            nspace = secureRandom.nextLong()
            alias = keyDescriptor.alias
            blob = keyDescriptor.blob
        }

        val threadB = CompletableFuture.supplyAsync {
            doSoftwareGeneration(
                callingUid, swDescriptor, attestationKey, parsedParams, isAttestKeyRequest
            )
        }

        return try {
            val teeMetadata = threadA.join()
            threadB.cancel(true)
            teeFunctional = true
            SystemLogger.info("AUTO: TEE succeeded for ${keyDescriptor.alias}, marked functional.")

            val originalChain = CertificateHelper.getCertificateChain(teeMetadata)
            if (originalChain != null && originalChain.size > 1) {
                val newChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)
                CertificateHelper.updateCertificateChain(teeMetadata, newChain).getOrThrow()
                teeMetadata.authorizations =
                    InterceptorUtils.patchAuthorizations(teeMetadata.authorizations, callingUid)
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                cleanupKeyData(keyId)
                patchedChains[keyId] = newChain
            }

            // Cache the patched response for getKeyEntry. Stored in teeResponses
            // (not generatedKeys) so createOperation forwards to real hardware.
            val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
            val patchedResponse = KeyEntryResponse().apply {
                this.metadata = teeMetadata
                iSecurityLevel = original
            }
            teeResponses[keyId] = patchedResponse

            InterceptorUtils.createTypedObjectReply(teeMetadata)
        } catch (_: Exception) {
            SystemLogger.info("AUTO: TEE failed for ${keyDescriptor.alias}, using software result.")
            try {
                threadB.join()
            } catch (e: Exception) {
                SystemLogger.error("AUTO: both paths failed for ${keyDescriptor.alias}.", e)
                val code =
                    if (e.cause is android.os.ServiceSpecificException)
                        (e.cause as android.os.ServiceSpecificException).errorCode
                    else SECURE_HW_COMMUNICATION_FAILED
                InterceptorUtils.createServiceSpecificErrorReply(code)
            }
        }
    }

    /**
     * Constructs a fake `KeyEntryResponse` that mimics a real response from the Keystore service.
     */
    private fun buildKeyEntryResponse(
        callingUid: Int,
        chain: List<Certificate>,
        params: KeyMintAttestation,
        descriptor: KeyDescriptor,
    ): KeyEntryResponse {
        val normalizedKeyDescriptor =
            KeyDescriptor().apply {
                domain = Domain.KEY_ID
                nspace = descriptor.nspace
                alias = null
                blob = null
            }
        val metadata =
            KeyMetadata().apply {
                keySecurityLevel = securityLevel
                key = normalizedKeyDescriptor
                CertificateHelper.updateCertificateChain(this, chain.toTypedArray()).getOrThrow()
                authorizations = params.toAuthorizations(callingUid, securityLevel)
                modificationTimeMs = System.currentTimeMillis()
            }
        return KeyEntryResponse().apply {
            this.metadata = metadata
            iSecurityLevel = original
        }
    }

    companion object {
        private val secureRandom = SecureRandom()
        private val persistExecutor = Executors.newSingleThreadExecutor()

        @Volatile var teeFunctional = false

        private const val KEYMINT_INVALID_INPUT_LENGTH = -21
        private const val KEYMINT_INVALID_ARGUMENT = -38
        private const val KEYMINT_TOO_MANY_OPERATIONS = -29
        private const val INVALID_ARGUMENT = 20
        private const val PERMISSION_DENIED = 6
        private const val SECURE_HW_COMMUNICATION_FAILED = -49
        private const val CANNOT_ATTEST_IDS = -66

        private const val STRONGBOX_KEYGEN_LATENCY_FLOOR_MS = 250L
        private const val STRONGBOX_OP_LATENCY_FLOOR_MS = 80L
        private const val STRONGBOX_MAX_CONCURRENT_OPS = 4
        private const val STRONGBOX_OP_WINDOW_NS = 10_000_000_000L
        private const val MAX_ALIAS_LENGTH = 256 * 1024
        private const val MAX_CONCURRENT_OPS_PER_UID = 15

        private fun isStrongBoxCapable(params: KeyMintAttestation): Boolean = when (params.algorithm) {
            Algorithm.RSA -> params.keySize <= 2048
            Algorithm.EC -> params.ecCurve == null || params.ecCurve == EcCurve.P_256
            else -> true
        }

        // Transaction codes for IKeystoreSecurityLevel interface.
        private val GENERATE_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val IMPORT_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")
        private val CREATE_OPERATION_TRANSACTION =
            InterceptorUtils.getTransactCode(
                IKeystoreSecurityLevel.Stub::class.java,
                "createOperation",
            )

        /** Only these transaction codes need native-level interception. */
        val INTERCEPTED_CODES =
            intArrayOf(GENERATE_KEY_TRANSACTION, IMPORT_KEY_TRANSACTION, CREATE_OPERATION_TRANSACTION)

        private val transactionNames: Map<Int, String> by lazy {
            IKeystoreSecurityLevel.Stub::class
                .java
                .declaredFields
                .filter {
                    it.isAccessible = true
                    it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
                }
                .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
        }

        // Stores keys generated entirely in software.
        val generatedKeys = ConcurrentHashMap<KeyIdentifier, GeneratedKeyInfo>()
        // A set to quickly identify keys that were generated for attestation purposes.
        val attestationKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()
        // Caches patched certificate chains to prevent re-generation and signature inconsistencies.
        val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()
        // Keys imported via importKey; getKeyEntry must not override these.
        val importedKeys: MutableSet<KeyIdentifier> = ConcurrentHashMap.newKeySet()
        // TEE-generated responses cached for getKeyEntry (not for createOperation).
        val teeResponses = ConcurrentHashMap<KeyIdentifier, KeyEntryResponse>()
        // Tracks remaining usage count per key for USAGE_COUNT_LIMIT enforcement.
        private val usageCounters =
            ConcurrentHashMap<KeyIdentifier, java.util.concurrent.atomic.AtomicInteger>()
        // Stores interceptors for active cryptographic operations.
        private val interceptedOperations = ConcurrentHashMap<IBinder, OperationInterceptor>()

        // --- Public Accessors for Other Interceptors ---
        fun getGeneratedKeyResponse(keyId: KeyIdentifier): KeyEntryResponse? =
            generatedKeys[keyId]?.response ?: teeResponses[keyId]

        /**
         * Finds a software-generated key by first filtering all known keys by the caller's UID, and
         * then matching the specific nspace.
         *
         * @param callingUid The UID of the process that initiated the createOperation call.
         * @param nspace The unique key identifier from the operation's KeyDescriptor.
         * @return The matching GeneratedKeyInfo if found, otherwise null.
         */
        fun findGeneratedKeyByKeyId(callingUid: Int, nspace: Long?): GeneratedKeyInfo? {
            // Iterate through all entries in the map to check both the key (for UID) and value (for
            // nspace).
            if (nspace == null || nspace == 0L) return null
            return generatedKeys.entries
                .filter { (keyIdentifier, _) -> keyIdentifier.uid == callingUid }
                .find { (_, info) -> info.nspace == nspace }
                ?.value
        }

        fun getPatchedChain(keyId: KeyIdentifier): Array<Certificate>? = patchedChains[keyId]

        fun isAttestationKey(keyId: KeyIdentifier): Boolean = attestationKeys.contains(keyId)

        fun cleanupKeyData(keyId: KeyIdentifier) {
            if (generatedKeys.remove(keyId) != null) {
                SystemLogger.debug("Remove generated key ${keyId}")
                GeneratedKeyPersistence.delete(keyId)
            }
            if (patchedChains.remove(keyId) != null) {
                SystemLogger.debug("Remove patched chain for ${keyId}")
            }
            if (attestationKeys.remove(keyId)) {
                SystemLogger.debug("Remove cached attestaion key ${keyId}")
            }
            importedKeys.remove(keyId)
            usageCounters.remove(keyId)
            teeResponses.remove(keyId)
        }

        fun removeOperationInterceptor(operationBinder: IBinder, backdoor: IBinder) {
            // Unregister from the native hook layer first.
            unregister(backdoor, operationBinder)

            if (interceptedOperations.remove(operationBinder) != null) {
                SystemLogger.debug("Removed operation interceptor for binder: $operationBinder")
            }
        }

        fun invalidatePatchedChains(reason: String? = null) {
            val count = patchedChains.size
            if (count == 0) return
            patchedChains.clear()
            SystemLogger.info("Invalidated $count patched cert chains${reason?.let { " due to $it" } ?: ""}.")
        }

        fun clearAllGeneratedKeys(reason: String? = null) {
            val count = generatedKeys.size
            val reasonMessage = reason?.let { " due to $it" } ?: ""
            generatedKeys.clear()
            patchedChains.clear()
            attestationKeys.clear()
            importedKeys.clear()
            usageCounters.clear()
            teeResponses.clear()
            GeneratedKeyPersistence.deleteAll()
            SystemLogger.info("Cleared all cached keys ($count entries)$reasonMessage.")
        }
    }
}

/**
 * Extension function to convert parsed `KeyMintAttestation` parameters back into an array of
 * `Authorization` objects for the fake `KeyMetadata`.
 */
private fun KeyMintAttestation.toAuthorizations(
    callingUid: Int,
    securityLevel: Int,
): Array<Authorization> {
    val authList = mutableListOf<Authorization>()

    /**
     * Helper function to create a fully-formed Authorization object.
     *
     * @param tag The KeyMint tag (e.g., Tag.ALGORITHM).
     * @param value The value for the tag, wrapped in a KeyParameterValue.
     * @return A populated Authorization object.
     */
    fun createAuth(tag: Int, value: KeyParameterValue): Authorization {
        val param =
            KeyParameter().apply {
                this.tag = tag
                this.value = value
            }
        return Authorization().apply {
            this.keyParameter = param
            this.securityLevel = securityLevel
        }
    }

    authList.add(createAuth(Tag.ALGORITHM, KeyParameterValue.algorithm(this.algorithm)))

    if (this.ecCurve != null) {
        authList.add(createAuth(Tag.EC_CURVE, KeyParameterValue.ecCurve(this.ecCurve)))
    }

    this.purpose.forEach { authList.add(createAuth(Tag.PURPOSE, KeyParameterValue.keyPurpose(it))) }
    this.blockMode.forEach {
        authList.add(createAuth(Tag.BLOCK_MODE, KeyParameterValue.blockMode(it)))
    }
    this.digest.forEach { authList.add(createAuth(Tag.DIGEST, KeyParameterValue.digest(it))) }
    this.padding.forEach {
        authList.add(createAuth(Tag.PADDING, KeyParameterValue.paddingMode(it)))
    }

    authList.add(createAuth(Tag.KEY_SIZE, KeyParameterValue.integer(this.keySize)))

    if (this.rsaPublicExponent != null) {
        authList.add(
            createAuth(
                Tag.RSA_PUBLIC_EXPONENT,
                KeyParameterValue.longInteger(this.rsaPublicExponent.toLong()),
            )
        )
    }

    if (this.noAuthRequired != false) {
        authList.add(createAuth(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true)))
    }

    if (this.callerNonce == true) {
        authList.add(createAuth(Tag.CALLER_NONCE, KeyParameterValue.boolValue(true)))
    }
    if (this.minMacLength != null) {
        authList.add(createAuth(Tag.MIN_MAC_LENGTH, KeyParameterValue.integer(this.minMacLength)))
    }
    if (this.rollbackResistance == true) {
        authList.add(createAuth(Tag.ROLLBACK_RESISTANCE, KeyParameterValue.boolValue(true)))
    }
    if (this.earlyBootOnly == true) {
        authList.add(createAuth(Tag.EARLY_BOOT_ONLY, KeyParameterValue.boolValue(true)))
    }
    if (this.allowWhileOnBody == true) {
        authList.add(createAuth(Tag.ALLOW_WHILE_ON_BODY, KeyParameterValue.boolValue(true)))
    }
    if (this.trustedUserPresenceRequired == true) {
        authList.add(
            createAuth(Tag.TRUSTED_USER_PRESENCE_REQUIRED, KeyParameterValue.boolValue(true))
        )
    }
    if (this.trustedConfirmationRequired == true) {
        authList.add(
            createAuth(Tag.TRUSTED_CONFIRMATION_REQUIRED, KeyParameterValue.boolValue(true))
        )
    }
    if (this.maxUsesPerBoot != null) {
        authList.add(
            createAuth(Tag.MAX_USES_PER_BOOT, KeyParameterValue.integer(this.maxUsesPerBoot))
        )
    }
    if (this.maxBootLevel != null) {
        authList.add(
            createAuth(Tag.MAX_BOOT_LEVEL, KeyParameterValue.integer(this.maxBootLevel))
        )
    }

    authList.add(
        createAuth(Tag.ORIGIN, KeyParameterValue.origin(this.origin ?: KeyOrigin.GENERATED))
    )

    authList.add(
        createAuth(Tag.OS_VERSION, KeyParameterValue.integer(AndroidDeviceUtils.osVersion))
    )

    val osPatch = AndroidDeviceUtils.getPatchLevel(callingUid)
    if (osPatch != AndroidDeviceUtils.DO_NOT_REPORT) {
        authList.add(createAuth(Tag.OS_PATCHLEVEL, KeyParameterValue.integer(osPatch)))
    }

    val vendorPatch = AndroidDeviceUtils.getVendorPatchLevelLong(callingUid)
    if (vendorPatch != AndroidDeviceUtils.DO_NOT_REPORT) {
        authList.add(createAuth(Tag.VENDOR_PATCHLEVEL, KeyParameterValue.integer(vendorPatch)))
    }

    val bootPatch = AndroidDeviceUtils.getBootPatchLevelLong(callingUid)
    if (bootPatch != AndroidDeviceUtils.DO_NOT_REPORT) {
        authList.add(createAuth(Tag.BOOT_PATCHLEVEL, KeyParameterValue.integer(bootPatch)))
    }

    // Software-enforced tags: CREATION_DATETIME, enforcement dates, USER_ID.
    fun createSwAuth(tag: Int, value: KeyParameterValue): Authorization {
        val param =
            KeyParameter().apply {
                this.tag = tag
                this.value = value
            }
        return Authorization().apply {
            this.keyParameter = param
            this.securityLevel = SecurityLevel.SOFTWARE
        }
    }

    authList.add(
        createSwAuth(Tag.CREATION_DATETIME, KeyParameterValue.dateTime(System.currentTimeMillis()))
    )

    this.activeDateTime?.let {
        authList.add(createSwAuth(Tag.ACTIVE_DATETIME, KeyParameterValue.dateTime(it.time)))
    }
    this.originationExpireDateTime?.let {
        authList.add(
            createSwAuth(Tag.ORIGINATION_EXPIRE_DATETIME, KeyParameterValue.dateTime(it.time))
        )
    }
    this.usageExpireDateTime?.let {
        authList.add(
            createSwAuth(Tag.USAGE_EXPIRE_DATETIME, KeyParameterValue.dateTime(it.time))
        )
    }
    this.usageCountLimit?.let {
        authList.add(createSwAuth(Tag.USAGE_COUNT_LIMIT, KeyParameterValue.integer(it)))
    }
    if (this.unlockedDeviceRequired == true) {
        authList.add(
            createSwAuth(Tag.UNLOCKED_DEVICE_REQUIRED, KeyParameterValue.boolValue(true))
        )
    }

    authList.add(
        createSwAuth(Tag.USER_ID, KeyParameterValue.integer(callingUid / 100000))
    )

    return authList.toTypedArray()
}
