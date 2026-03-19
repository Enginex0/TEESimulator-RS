package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.*
import android.util.Pair as AndroidPair
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicInteger
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
import org.matrix.TEESimulator.util.AndroidPermissionUtils

class KeyMintSecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val securityLevel: Int,
) : BinderInterceptor() {

    data class GeneratedKeyInfo(
        val keyPair: KeyPair,
        val nspace: Long,
        val response: KeyEntryResponse,
        val keyParams: KeyMintAttestation? = null,
    )

    private val activeOps = ConcurrentHashMap<Int, ConcurrentLinkedDeque<SoftwareOperation>>()
    private val recentOps = ConcurrentHashMap<Int, ConcurrentLinkedDeque<Long>>()

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
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
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
        if (code == GENERATE_KEY_TRANSACTION && hardwareKeygenTxIds.remove(txId)) {
            val remaining = hardwareKeygenCount(callingUid).decrementAndGet()
            SystemLogger.info("[TX_ID: $txId] PERMIT_RELEASED uid=$callingUid concurrent_remaining=$remaining result=${if (resultCode == 0) "OK" else "ERROR($resultCode)"}")
        }

        // We only care about successful transactions.
        if (resultCode != 0 || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        if (code == IMPORT_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            // Evict generated key data but retain patched chains so detectors
            // can't use importKey to force unpatched getKeyEntry responses.
            val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
            if (generatedKeys.remove(keyId) != null) {
                SystemLogger.debug("Remove generated key on importKey $keyId")
                GeneratedKeyPersistence.delete(keyId)
            }
            attestationKeys.remove(keyId)
            importedKeys.add(keyId)
        } else if (code == CREATE_OPERATION_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
            val params = data.createTypedArray(KeyParameter.CREATOR)!!
            val parsedParams = KeyMintAttestation(params)
            val forced = data.readBoolean()
            if (forced)
                SystemLogger.verbose(
                    "[TX_ID: $txId] Current operation has a very high pruning power."
                )
            val response: CreateOperationResponse =
                reply.readTypedObject(CreateOperationResponse.CREATOR)!!
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
                        register(backdoor, operationBinder, interceptor, OperationInterceptor.INTERCEPTED_CODES)
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
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                val key = metadata.key!!
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                CertificateHelper.updateCertificateChain(metadata, newChain).getOrThrow()

                // We must clean up cached generated keys before storing the patched chain
                cleanupKeyData(keyId)
                patchedChains[keyId] = newChain
                SystemLogger.debug(
                    "Cached patched certificate chain for $keyId. (${key.alias} [${key.domain}, ${key.nspace}])"
                )

                return InterceptorUtils.createTypedObjectReply(metadata)
            }
        }
        return TransactionResult.SkipTransaction
    }

    private fun pruneOpsForUid(uid: Int, newOp: SoftwareOperation, maxOps: Int = MAX_CONCURRENT_OPS_PER_UID) {
        val ops = activeOps.computeIfAbsent(uid) { ConcurrentLinkedDeque() }
        val before = ops.size
        ops.removeIf { it.finalized }
        val afterClean = ops.size
        while (ops.size >= maxOps) {
            val oldest = ops.pollFirst() ?: break
            if (!oldest.finalized) {
                SystemLogger.info("[LRU] Pruning operation for uid=$uid (active=${ops.size}/$maxOps)")
                oldest.abort()
            }
        }
        ops.addLast(newOp)
        SystemLogger.debug("[LRU] uid=$uid ops: before=$before cleaned=${before - afterClean} active=${ops.size}")
    }

    private fun trackAndEnforceOpLimit(callingUid: Int, txId: Long): TransactionResult? {
        if (securityLevel != SecurityLevel.STRONGBOX) return null
        val timestamps = recentOps.computeIfAbsent(callingUid) { ConcurrentLinkedDeque() }
        val cutoff = System.nanoTime() - STRONGBOX_OP_WINDOW_NS
        timestamps.removeIf { it < cutoff }
        val swOps = activeOps[callingUid]?.count { !it.finalized } ?: 0
        if (timestamps.size + swOps >= STRONGBOX_MAX_CONCURRENT_OPS) {
            SystemLogger.info("[TX_ID: $txId] StrongBox op limit reached for uid=$callingUid (hw=${timestamps.size} sw=$swOps max=$STRONGBOX_MAX_CONCURRENT_OPS)")
            return InterceptorUtils.createErrorReply(KEYMINT_TOO_MANY_OPERATIONS)
        }
        timestamps.addLast(System.nanoTime())
        return null
    }

    private fun handleCreateOperation(
        txId: Long,
        callingUid: Int,
        data: Parcel,
    ): TransactionResult {
        SystemLogger.debug("[TX_ID: $txId] createOperation parcel: dataSize=${data.dataSize()} dataAvail=${data.dataAvail()} dataPos=${data.dataPosition()}")
        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
        val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!

        SystemLogger.debug("[TX_ID: $txId] createOperation descriptor: domain=${keyDescriptor.domain} nspace=${keyDescriptor.nspace} alias=${keyDescriptor.alias}")

        // Android framework calls createOperation with domain=APP+alias;
        // keystore2 internally resolves to KEY_ID — but software keys never
        // reach keystore2's database, so we must handle both lookup paths.
        val resolvedEntry: Map.Entry<KeyIdentifier, GeneratedKeyInfo> =
            when (keyDescriptor.domain) {
                Domain.APP -> {
                    val alias = keyDescriptor.alias ?: run {
                        SystemLogger.info("[TX_ID: $txId] createOperation domain=APP with null alias, forwarding to HAL")
                        return TransactionResult.ContinueAndSkipPost
                    }
                    val key = KeyIdentifier(callingUid, alias)
                    generatedKeys[key]?.let { java.util.AbstractMap.SimpleEntry(key, it) } ?: run {
                        SystemLogger.info("[TX_ID: $txId] createOperation alias=$alias not in generatedKeys, forwarding to HAL")
                        return TransactionResult.ContinueAndSkipPost
                    }
                }
                Domain.KEY_ID -> {
                    val nspace = keyDescriptor.nspace
                    val entry = if (nspace == null || nspace == 0L) null
                        else generatedKeys.entries
                            .filter { it.key.uid == callingUid }
                            .find { it.value.nspace == nspace }
                    entry ?: run {
                        trackAndEnforceOpLimit(callingUid, txId)?.let { return it }
                        SystemLogger.info("[TX_ID: $txId] createOperation KeyId(${keyDescriptor.nspace}) NOT FOUND for uid=$callingUid. Forwarding to HAL.")
                        return TransactionResult.Continue
                    }
                }
                else -> {
                    SystemLogger.info("[TX_ID: $txId] createOperation domain=${keyDescriptor.domain}, forwarding to HAL")
                    return TransactionResult.ContinueAndSkipPost
                }
            }
        val generatedKeyInfo = resolvedEntry.value
        val resolvedKeyId = resolvedEntry.key

        trackAndEnforceOpLimit(callingUid, txId)?.let { return it }

        SystemLogger.info("[TX_ID: $txId] Creating SOFTWARE operation for uid=$callingUid.")

        val params = data.createTypedArray(KeyParameter.CREATOR)!!
        val parsedParams = KeyMintAttestation(params).let { p ->
            if (p.algorithm != 0) p
            else p.copy(algorithm = when (generatedKeyInfo.keyPair.private.algorithm) {
                "EC", "ECDSA" -> Algorithm.EC
                "RSA" -> Algorithm.RSA
                else -> p.algorithm
            })
        }
        val forced = data.readBoolean()

        val requestedPurpose = parsedParams.purpose.firstOrNull()
        if (requestedPurpose == null) {
            return InterceptorUtils.createServiceSpecificErrorReply(KEYMINT_INVALID_ARGUMENT)
        }

        if (forced) {
            return InterceptorUtils.createServiceSpecificErrorReply(RESPONSE_PERMISSION_DENIED)
        }

        AuthorizeCreate.check(generatedKeyInfo.keyParams, parsedParams, params)?.let { errorCode ->
            SystemLogger.info("[TX_ID: $txId] authorize_create rejected: errorCode=$errorCode")
            return InterceptorUtils.createServiceSpecificErrorReply(errorCode)
        }

        val keyParams = generatedKeyInfo.keyParams
        val effectiveParams = if (keyParams != null) {
            keyParams.copy(
                purpose = parsedParams.purpose,
                digest = parsedParams.digest.ifEmpty { keyParams.digest },
            )
        } else parsedParams

        val opLatency = if (securityLevel == SecurityLevel.STRONGBOX) STRONGBOX_OP_LATENCY_FLOOR_MS else 0L
        val softwareOperation = SoftwareOperation(txId, generatedKeyInfo.keyPair, effectiveParams, opLatency)

        if (keyParams?.usageCountLimit != null) {
            val limit = keyParams.usageCountLimit
            val remaining = usageCounters.getOrPut(resolvedKeyId) {
                java.util.concurrent.atomic.AtomicInteger(limit)
            }
            if (remaining.get() <= 0) {
                cleanupKeyData(resolvedKeyId)
                usageCounters.remove(resolvedKeyId)
                throw android.os.ServiceSpecificException(RESPONSE_KEY_NOT_FOUND)
            }
            softwareOperation.onFinishCallback = {
                if (remaining.decrementAndGet() <= 0) {
                    cleanupKeyData(resolvedKeyId)
                    usageCounters.remove(resolvedKeyId)
                    SystemLogger.info("Key $resolvedKeyId exhausted (USAGE_COUNT_LIMIT=$limit).")
                }
            }
        }

        val maxOps = if (securityLevel == SecurityLevel.STRONGBOX) STRONGBOX_MAX_CONCURRENT_OPS else MAX_CONCURRENT_OPS_PER_UID
        pruneOpsForUid(callingUid, softwareOperation, maxOps)
        val operationBinder = SoftwareOperationBinder(softwareOperation)

        val response =
            CreateOperationResponse().apply {
                iOperation = operationBinder
                operationChallenge = null
                softwareOperation.iv?.let { iv ->
                    parameters = KeyParameters().apply {
                        keyParameter = arrayOf(
                            KeyParameter().apply {
                                tag = Tag.NONCE
                                value = KeyParameterValue.blob(iv)
                            }
                        )
                    }
                }
            }

        return InterceptorUtils.createTypedObjectReply(response)
    }

    private fun handleGenerateKey(txId: Long, callingUid: Int, callingPid: Int, data: Parcel): TransactionResult {
        if (data.dataSize() > MAX_ALIAS_LENGTH) {
            SystemLogger.warning("Skipping oversized transaction: ${data.dataSize()} bytes")
            return TransactionResult.ContinueAndSkipPost
        }

        return runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                val attestationKey = data.readTypedObject(KeyDescriptor.CREATOR)

                SystemLogger.debug(
                    "Handling generateKey ${keyDescriptor.alias}, attestKey=${attestationKey?.alias}"
                )
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                val parsedParams = KeyMintAttestation(params)

                val challenge = parsedParams.attestationChallenge
                if (challenge != null && challenge.size > AttestationConstants.CHALLENGE_LENGTH_LIMIT) {
                    SystemLogger.warning("[TX_ID: $txId] Rejecting oversized attestation challenge: ${challenge.size} bytes (max ${AttestationConstants.CHALLENGE_LENGTH_LIMIT})")
                    return InterceptorUtils.createErrorReply(KEYMINT_INVALID_INPUT_LENGTH)
                }

                if (params.any { it.tag == Tag.CREATION_DATETIME }) {
                    SystemLogger.warning("[TX_ID: $txId] Rejecting CREATION_DATETIME in generateKey params")
                    return InterceptorUtils.createErrorReply(RESPONSE_INVALID_ARGUMENT)
                }

                if (params.any { it.tag == Tag.DEVICE_UNIQUE_ATTESTATION } && !AndroidPermissionUtils.hasUniqueIdAttestationPermission(callingUid)) {
                    SystemLogger.warning("[TX_ID: $txId] Rejecting DEVICE_UNIQUE_ATTESTATION for uid=$callingUid")
                    return InterceptorUtils.createErrorReply(KEYMINT_CANNOT_ATTEST_IDS)
                }

                val hasDeviceIdAttestation = params.any { 
                    it.tag == Tag.ATTESTATION_ID_IMEI || 
                    it.tag == Tag.ATTESTATION_ID_MEID || 
                    it.tag == Tag.ATTESTATION_ID_SERIAL || 
                    it.tag == Tag.DEVICE_UNIQUE_ATTESTATION || 
                    it.tag == Tag.ATTESTATION_ID_SECOND_IMEI 
                }

                if(hasDeviceIdAttestation && !AndroidPermissionUtils.hasDeviceAttestationPermission(callingUid)) {
                    SystemLogger.warning("[TX_ID: $txId] Rejecting DEVICE_ID_ATTESTATION for uid=$callingUid")
                    return InterceptorUtils.createErrorReply(KEYMINT_CANNOT_ATTEST_IDS)
                }

                // AOSP security_level.rs:478-485: INCLUDE_UNIQUE_ID requires
                // SELinux gen_unique_id OR Android REQUEST_UNIQUE_ID_ATTESTATION
                if (params.any { it.tag == Tag.INCLUDE_UNIQUE_ID }) {
                    val hasSELinux = ConfigurationManager.checkSELinuxPermission(
                        callingPid, "keystore_key", "gen_unique_id",
                    )
                    val hasAndroid = ConfigurationManager.hasPermissionForUid(
                        callingUid, "android.permission.REQUEST_UNIQUE_ID_ATTESTATION",
                    )
                    if (!hasSELinux && !hasAndroid) {
                        SystemLogger.warning("[TX_ID: $txId] Rejecting INCLUDE_UNIQUE_ID for uid=$callingUid pid=$callingPid")
                        return InterceptorUtils.createServiceSpecificErrorReply(RESPONSE_PERMISSION_DENIED)
                    }
                }

                val isSymmetric = parsedParams.algorithm == Algorithm.AES ||
                    parsedParams.algorithm == Algorithm.HMAC ||
                    parsedParams.algorithm == Algorithm.TRIPLE_DES

                if (isSymmetric) {
                    SystemLogger.debug("[TX_ID: $txId] Symmetric algorithm ${parsedParams.algorithm} → forwarding to HAL")
                    return TransactionResult.ContinueAndSkipPost
                }

                if (securityLevel == SecurityLevel.STRONGBOX && !isStrongBoxCapable(parsedParams)) {
                    SystemLogger.info("[TX_ID: $txId] StrongBox-unsupported params (algo=${parsedParams.algorithm} size=${parsedParams.keySize}) → forwarding to HAL for rejection")
                    return TransactionResult.ContinueAndSkipPost
                }

                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                val isAttestKeyRequest = parsedParams.isAttestKey()

                val needsSoftwareGeneration =
                    ConfigurationManager.shouldGenerate(callingUid) ||
                        (ConfigurationManager.shouldPatch(callingUid) && isAttestKeyRequest) ||
                        (attestationKey != null &&
                            isAttestationKey(KeyIdentifier(callingUid, attestationKey.alias)))

                if (needsSoftwareGeneration) {
                    return doSoftwareKeyGen(callingUid, keyDescriptor, attestationKey, parsedParams, keyId, isAttestKeyRequest)
                } else if (parsedParams.attestationChallenge != null) {
                    val windowUsed = hardwareKeygenWindowCount(callingUid)
                    val concurrentUsed = hardwareKeygenCount(callingUid).get()

                    // Sliding window rate limit
                    if (windowUsed >= MAX_HW_KEYGEN_PER_WINDOW) {
                        SystemLogger.info("[TX_ID: $txId] RATE_LIMITED uid=$callingUid window=$windowUsed/$MAX_HW_KEYGEN_PER_WINDOW concurrent=$concurrentUsed → software fallback")
                        return doSoftwareKeyGen(callingUid, keyDescriptor, attestationKey, parsedParams, keyId, isAttestKeyRequest)
                    }
                    // Concurrent cap
                    if (hardwareKeygenCount(callingUid).incrementAndGet() > MAX_CONCURRENT_HW_KEYGEN_PER_UID) {
                        hardwareKeygenCount(callingUid).decrementAndGet()
                        SystemLogger.info("[TX_ID: $txId] CONCURRENT_LIMITED uid=$callingUid window=$windowUsed/$MAX_HW_KEYGEN_PER_WINDOW concurrent=${concurrentUsed + 1}/$MAX_CONCURRENT_HW_KEYGEN_PER_UID → software fallback")
                        return doSoftwareKeyGen(callingUid, keyDescriptor, attestationKey, parsedParams, keyId, isAttestKeyRequest)
                    }
                    // Both checks passed — commit the window permit and forward to hardware TEE
                    recordHardwareKeygen(callingUid)
                    hardwareKeygenTxIds.add(txId)
                    SystemLogger.info("[TX_ID: $txId] HARDWARE_KEYGEN uid=$callingUid window=${windowUsed + 1}/$MAX_HW_KEYGEN_PER_WINDOW concurrent=${concurrentUsed + 1}/$MAX_CONCURRENT_HW_KEYGEN_PER_UID → forwarding to TEE")
                    return TransactionResult.Continue
                }

                cleanupKeyData(keyId)
                TransactionResult.ContinueAndSkipPost
            }
            .getOrElse {
                SystemLogger.error("Error during generateKey handling for UID $callingUid.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    private fun doSoftwareKeyGen(
        callingUid: Int,
        keyDescriptor: KeyDescriptor,
        attestationKey: KeyDescriptor?,
        parsedParams: KeyMintAttestation,
        keyId: KeyIdentifier,
        isAttestKeyRequest: Boolean,
    ): TransactionResult {
        val startNs = System.nanoTime()
        keyDescriptor.nspace = secureRandom.nextLong()
        SystemLogger.info("Generating software key for ${keyDescriptor.alias}[${keyDescriptor.nspace}].")

        val keyData = if (NativeCertGen.isAvailable && attestationKey == null) {
            generateAttestedKeyPairNative(callingUid, parsedParams)
                ?: CertificateGenerator.generateAttestedKeyPair(
                    callingUid, keyDescriptor.alias, attestationKey?.alias, parsedParams, securityLevel,
                )
        } else {
            CertificateGenerator.generateAttestedKeyPair(
                callingUid, keyDescriptor.alias, attestationKey?.alias, parsedParams, securityLevel,
            )
        } ?: throw Exception("Both native and BouncyCastle cert gen failed.")

        cleanupKeyData(keyId)
        val response = buildKeyEntryResponse(callingUid, keyData.second, parsedParams, keyDescriptor)
        generatedKeys[keyId] = GeneratedKeyInfo(keyData.first, keyDescriptor.nspace, response, parsedParams)
        if (isAttestKeyRequest) attestationKeys.add(keyId)

        GeneratedKeyPersistence.save(
            keyId = keyId,
            keyPair = keyData.first,
            nspace = keyDescriptor.nspace,
            securityLevel = securityLevel,
            certChain = keyData.second.toList(),
            algorithm = parsedParams.algorithm,
            keySize = parsedParams.keySize,
            ecCurve = parsedParams.ecCurve ?: 0,
            purposes = parsedParams.purpose,
            digests = parsedParams.digest,
            isAttestationKey = isAttestKeyRequest,
        )

        val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
        val floor = if (securityLevel == SecurityLevel.STRONGBOX) STRONGBOX_KEYGEN_LATENCY_FLOOR_MS else TEE_LATENCY_FLOOR_MS
        val delayMs = floor - elapsedMs
        if (delayMs > 0) Thread.sleep(delayMs)

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

            val keyboxPrivateKeyBytes = keybox.keyPair.private.encoded
            val keyboxCertChainBytes = keybox.certificates
                .map { it.encoded }
                .fold(ByteArray(0)) { acc, der -> acc + der }

            val attestVersion = AndroidDeviceUtils.getAttestVersion(securityLevel)
            val keymasterVersion = AndroidDeviceUtils.getKeymasterVersion(securityLevel)
            val appId = AttestationBuilder.createApplicationId(callingUid)

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
                keyboxPrivateKey = keyboxPrivateKeyBytes,
                keyboxCertChain = keyboxCertChainBytes,
                securityLevel = securityLevel,
                attestVersion = attestVersion,
                keymasterVersion = keymasterVersion,
                osVersion = AndroidDeviceUtils.osVersion,
                osPatchLevel = AndroidDeviceUtils.getPatchLevel(callingUid),
                vendorPatchLevel = AndroidDeviceUtils.getVendorPatchLevelLong(callingUid),
                bootPatchLevel = AndroidDeviceUtils.getBootPatchLevelLong(callingUid),
                bootKey = AndroidDeviceUtils.bootKey,
                bootHash = AndroidDeviceUtils.bootHash,
                creationDatetime = System.currentTimeMillis(),
                attestationApplicationId = appId.octets,
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
            )

            val resultBytes = NativeCertGen.generateAttestedKeyPair(config) ?: return null
            val (keyPair, certs) = NativeCertGen.parseNativeResult(resultBytes)
            SystemLogger.info("NativeCertGen: generated key pair successfully (${certs.size} certs)")
            AndroidPair(keyPair, certs)
        }.onFailure {
            SystemLogger.error("NativeCertGen: generation failed, falling back to BouncyCastle", it)
        }.getOrNull()
    }

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

    fun loadPersistedKeys() {
        val records = GeneratedKeyPersistence.loadAll(securityLevel)
        if (records.isEmpty()) {
            SystemLogger.debug("No persisted keys to restore for security level $securityLevel")
            return
        }

        SystemLogger.info("Restoring ${records.size} persisted keys for security level $securityLevel")

        for (record in records) {
            runCatching {
                val keyId = KeyIdentifier(record.uid, record.alias)
                if (generatedKeys.containsKey(keyId)) {
                    SystemLogger.debug("Skipping already-loaded key: $keyId")
                    return@runCatching
                }

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
                require(certChain.isNotEmpty()) { "Persisted key has empty certificate chain" }

                val publicKey = certChain[0].publicKey
                val keyPair = KeyPair(publicKey, privateKey)

                val descriptor = KeyDescriptor().apply {
                    domain = Domain.APP
                    nspace = record.nspace
                    alias = record.alias
                    blob = null
                }

                val attestation = KeyMintAttestation(
                    keySize = record.keySize,
                    algorithm = record.algorithm,
                    ecCurve = record.ecCurve,
                    ecCurveName = "",
                    origin = null,
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
                    brand = null,
                    device = null,
                    product = null,
                    serial = null,
                    imei = null,
                    meid = null,
                    manufacturer = null,
                    model = null,
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
                    noAuthRequired = null,
                    maxUsesPerBoot = null,
                    maxBootLevel = null,
                    minMacLength = null,
                    rsaOaepMgfDigest = emptyList(),
                )

                val response = buildKeyEntryResponse(record.uid, certChain, attestation, descriptor)
                generatedKeys[keyId] = GeneratedKeyInfo(keyPair, record.nspace, response, attestation)
                if (record.isAttestationKey) attestationKeys.add(keyId)

                SystemLogger.debug("Restored persisted key: $keyId")
            }.onFailure {
                SystemLogger.error("Failed to restore key: uid=${record.uid} alias=${record.alias}", it)
            }
        }

        SystemLogger.info("Key restoration complete. Total in memory: ${generatedKeys.size}")
    }

    companion object {
        private val secureRandom = SecureRandom()

        // Maximum alias length to prevent binder buffer exhaustion (Issue #109)
        // Binder buffer is ~1MB; 256KB provides 4x safety margin for transaction overhead
        private const val MAX_ALIAS_LENGTH = 256 * 1024
        private const val KEYMINT_INVALID_INPUT_LENGTH = -21
        private const val KEYMINT_INVALID_ARGUMENT = -38
        private const val RESPONSE_INVALID_ARGUMENT = 20
        private const val RESPONSE_PERMISSION_DENIED = 6
        private const val RESPONSE_KEY_NOT_FOUND = 7
        private const val TEE_LATENCY_FLOOR_MS = 15L
        private const val STRONGBOX_KEYGEN_LATENCY_FLOOR_MS = 250L
        private const val STRONGBOX_OP_LATENCY_FLOOR_MS = 80L
        private const val KEYMINT_TOO_MANY_OPERATIONS = -29
        private const val KEYMINT_CANNOT_ATTEST_IDS = -66
        private const val MAX_CONCURRENT_OPS_PER_UID = 15
        private const val STRONGBOX_MAX_CONCURRENT_OPS = 4
        private const val STRONGBOX_OP_WINDOW_NS = 10_000_000_000L // 10s
        private const val MAX_CONCURRENT_HW_KEYGEN_PER_UID = 2
        // Sliding window: max hardware keygen permits per UID within the burst window
        private const val MAX_HW_KEYGEN_PER_WINDOW = 2
        private const val BURST_WINDOW_MS = 30_000L
        private val uidHardwareKeygenCount = ConcurrentHashMap<Int, AtomicInteger>()
        private val hardwareKeygenTxIds = ConcurrentHashMap.newKeySet<Long>()
        private val uidKeygenTimestamps = ConcurrentHashMap<Int, MutableList<Long>>()

        private fun isStrongBoxCapable(params: KeyMintAttestation): Boolean = when (params.algorithm) {
            Algorithm.RSA -> params.keySize <= 2048
            Algorithm.EC -> params.ecCurve == null || params.ecCurve == EcCurve.P_256
            else -> true
        }

        private fun hardwareKeygenCount(uid: Int): AtomicInteger =
            uidHardwareKeygenCount.computeIfAbsent(uid) { AtomicInteger(0) }

        private fun hardwareKeygenWindowCount(uid: Int): Int {
            val now = System.currentTimeMillis()
            val timestamps = uidKeygenTimestamps.computeIfAbsent(uid) { mutableListOf() }
            synchronized(timestamps) {
                timestamps.removeAll { now - it > BURST_WINDOW_MS }
                if (timestamps.isEmpty()) {
                    uidKeygenTimestamps.remove(uid, timestamps)
                    uidHardwareKeygenCount.remove(uid)
                }
                return timestamps.size
            }
        }

        private fun recordHardwareKeygen(uid: Int) {
            val timestamps = uidKeygenTimestamps.computeIfAbsent(uid) { mutableListOf() }
            synchronized(timestamps) {
                timestamps.add(System.currentTimeMillis())
            }
        }

        private val GENERATE_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val IMPORT_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")
        private val CREATE_OPERATION_TRANSACTION =
            InterceptorUtils.getTransactCode(
                IKeystoreSecurityLevel.Stub::class.java,
                "createOperation",
            )

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

        val generatedKeys = ConcurrentHashMap<KeyIdentifier, GeneratedKeyInfo>()
        val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()
        val attestationKeys: MutableSet<KeyIdentifier> = ConcurrentHashMap.newKeySet()
        val importedKeys: MutableSet<KeyIdentifier> = ConcurrentHashMap.newKeySet()
        private val usageCounters = ConcurrentHashMap<KeyIdentifier, java.util.concurrent.atomic.AtomicInteger>()
        private val interceptedOperations = ConcurrentHashMap<IBinder, OperationInterceptor>()

        fun getGeneratedKeyResponse(keyId: KeyIdentifier): KeyEntryResponse? =
            generatedKeys[keyId]?.response

        fun findGeneratedKeyByKeyId(callingUid: Int, nspace: Long?): GeneratedKeyInfo? {
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
        }

        fun removeOperationInterceptor(operationBinder: IBinder, backdoor: IBinder) {
            unregister(backdoor, operationBinder)

            if (interceptedOperations.remove(operationBinder) != null) {
                SystemLogger.debug("Removed operation interceptor for binder: $operationBinder")
            }
        }

        fun invalidatePatchedChains(reason: String? = null) {
            val count = patchedChains.size
            if (count == 0) return
            val reasonMessage = reason?.let { " due to $it" } ?: ""
            patchedChains.clear()
            SystemLogger.info("Invalidated $count patched cert chains$reasonMessage.")
        }

        fun clearAllGeneratedKeys(reason: String? = null) {
            val count = generatedKeys.size
            val reasonMessage = reason?.let { " due to $it" } ?: ""
            generatedKeys.clear()
            patchedChains.clear()
            attestationKeys.clear()
            importedKeys.clear()
            usageCounters.clear()
            GeneratedKeyPersistence.deleteAll()
            SystemLogger.info("Cleared all cached keys ($count entries)$reasonMessage.")
        }
    }
}

private fun KeyMintAttestation.toAuthorizations(
    callingUid: Int,
    securityLevel: Int,
): Array<Authorization> {
    val authList = mutableListOf<Authorization>()

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
    this.blockMode.forEach { authList.add(createAuth(Tag.BLOCK_MODE, KeyParameterValue.blockMode(it))) }
    this.digest.forEach { authList.add(createAuth(Tag.DIGEST, KeyParameterValue.digest(it))) }
    this.padding.forEach { authList.add(createAuth(Tag.PADDING, KeyParameterValue.paddingMode(it))) }
    authList.add(createAuth(Tag.KEY_SIZE, KeyParameterValue.integer(this.keySize)))
    if (this.rsaPublicExponent != null) {
        authList.add(createAuth(Tag.RSA_PUBLIC_EXPONENT, KeyParameterValue.longInteger(this.rsaPublicExponent.toLong())))
    }
    authList.add(createAuth(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true)))
    authList.add(createAuth(Tag.ORIGIN, KeyParameterValue.origin(this.origin ?: KeyOrigin.GENERATED)))
    authList.add(createAuth(Tag.OS_VERSION, KeyParameterValue.integer(AndroidDeviceUtils.osVersion)))

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
    authList.add(createAuth(Tag.CREATION_DATETIME, KeyParameterValue.dateTime(System.currentTimeMillis())))
    authList.add(
        Authorization().apply {
            this.keyParameter =
                KeyParameter().apply {
                    this.tag = Tag.USER_ID
                    this.value = KeyParameterValue.integer(callingUid / 100000)
                }
            this.securityLevel = SecurityLevel.SOFTWARE
        }
    )

    return authList.toTypedArray()
}
