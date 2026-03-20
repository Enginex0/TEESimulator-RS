package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import java.security.SecureRandom
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Interceptor for the `IKeystoreService` on Android S (API 31) and newer.
 *
 * This version of Keystore delegates most cryptographic operations to `IKeystoreSecurityLevel`
 * sub-services (for TEE, StrongBox, etc.). This interceptor's main role is to set up interceptors
 * for those sub-services and to patch certificate chains on their way out.
 */
@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : AbstractKeystoreInterceptor() {
    private val stubBinderClass = IKeystoreService.Stub::class.java

    // Transaction codes for the IKeystoreService interface methods we are interested in.
    private val GET_KEY_ENTRY_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "getKeyEntry")
    private val DELETE_KEY_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "deleteKey")
    private val UPDATE_SUBCOMPONENT_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "updateSubcomponent")
    private val LIST_ENTRIES_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "listEntries")
    private val LIST_ENTRIES_BATCHED_TRANSACTION =
        if (Build.VERSION.SDK_INT >= 34)
            InterceptorUtils.getTransactCode(stubBinderClass, "listEntriesBatched")
        else null
    private val GET_NUMBER_OF_ENTRIES_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "getNumberOfEntries")

    private val transactionNames: Map<Int, String> by lazy {
        stubBinderClass.declaredFields
            .filter {
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    // Keys whose certs were updated via updateSubcomponent; skip re-patching on getKeyEntry.
    private val userUpdatedKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    override val interceptedCodes: IntArray by lazy {
        listOfNotNull(
                GET_KEY_ENTRY_TRANSACTION,
                DELETE_KEY_TRANSACTION,
                UPDATE_SUBCOMPONENT_TRANSACTION,
                LIST_ENTRIES_TRANSACTION,
                LIST_ENTRIES_BATCHED_TRANSACTION,
                GET_NUMBER_OF_ENTRIES_TRANSACTION,
            )
            .toIntArray()
    }

    /**
     * This method is called once the main service is hooked. It proceeds to find and hook the
     * security level sub-services (e.g., TEE, StrongBox).
     */
    override fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        val keystoreInterface = IKeystoreService.Stub.asInterface(service)
        setupSecurityLevelInterceptors(keystoreInterface, backdoor)
    }

    private fun setupSecurityLevelInterceptors(service: IKeystoreService, backdoor: IBinder) {
        // Attempt to get and intercept the TEE security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)?.let { tee ->
                    SystemLogger.info("Found TEE SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
                    register(
                        backdoor,
                        tee.asBinder(),
                        interceptor,
                        KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES,
                    )
                    interceptor.loadPersistedKeys()
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept TEE SecurityLevel.", it) }

        // Attempt to get and intercept the StrongBox security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.STRONGBOX)?.let { strongbox ->
                    SystemLogger.info("Found StrongBox SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(strongbox, SecurityLevel.STRONGBOX)
                    register(
                        backdoor,
                        strongbox.asBinder(),
                        interceptor,
                        KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES,
                    )
                    interceptor.loadPersistedKeys()
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept StrongBox SecurityLevel.", it) }
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)
            return if (ConfigurationManager.shouldSkipUid(callingUid))
                TransactionResult.ContinueAndSkipPost
            else TransactionResult.Continue
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)

            val packages = ConfigurationManager.getPackagesForUid(callingUid).joinToString()
            val isGMS = packages.contains("com.google.android.gms")

            if (isGMS || ConfigurationManager.shouldSkipUid(callingUid)) {
                return TransactionResult.ContinueAndSkipPost
            } else {
                return TransactionResult.Continue
            }
        } else if (
            code == GET_KEY_ENTRY_TRANSACTION ||
                code == DELETE_KEY_TRANSACTION ||
                code == UPDATE_SUBCOMPONENT_TRANSACTION
        ) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

            if (ConfigurationManager.shouldSkipUid(callingUid))
                return TransactionResult.ContinueAndSkipPost

            if (code == UPDATE_SUBCOMPONENT_TRANSACTION)
                return handleUpdateSubcomponent(callingUid, data)

            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost

            if (code == DELETE_KEY_TRANSACTION) {
                // Handle delete by alias (APP domain) or nspace (KEY_ID domain).
                val keyId =
                    if (descriptor.alias != null) {
                        KeyIdentifier(callingUid, descriptor.alias)
                    } else if (descriptor.domain == Domain.KEY_ID) {
                        KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                            callingUid, descriptor.nspace
                        )?.let { info ->
                            KeyMintSecurityLevelInterceptor.generatedKeys.entries
                                .find { it.value.nspace == info.nspace && it.key.uid == callingUid }
                                ?.key
                        }
                    } else null

                if (keyId != null) {
                    val isSoftwareKey =
                        KeyMintSecurityLevelInterceptor.generatedKeys.containsKey(keyId)
                    KeyMintSecurityLevelInterceptor.cleanupKeyData(keyId)
                    if (isSoftwareKey) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Deleted cached keypair ${keyId.alias}, replying with empty response."
                        )
                        return InterceptorUtils.createSuccessReply(writeResultCode = false)
                    }
                }
                return TransactionResult.ContinueAndSkipPost
            }

            if (descriptor.alias == null) {
                return TransactionResult.ContinueAndSkipPost
            }
            val keyId = KeyIdentifier(callingUid, descriptor.alias)

            val response =
                KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId)
                    ?: return TransactionResult.Continue

            if (KeyMintSecurityLevelInterceptor.isAttestationKey(keyId))
                SystemLogger.info("${descriptor.alias} was an attestation key")

            SystemLogger.info("[TX_ID: $txId] Found generated response for ${descriptor.alias}:")
            response.metadata?.authorizations?.forEach {
                KeyMintParameterLogger.logParameter(it.keyParameter)
            }
            return InterceptorUtils.createTypedObjectReply(response)
        } else {
            logTransaction(
                txId,
                transactionNames[code] ?: "unknown code=$code",
                callingUid,
                callingPid,
                true,
            )
        }

        // Let most calls go through to the real service.
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
        if (target != keystoreService || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)
            return runCatching {
                    val hardwareCount = reply.readInt()
                    val softwareCount =
                        KeyMintSecurityLevelInterceptor.generatedKeys.keys.count {
                            it.uid == callingUid
                        }
                    val totalCount = hardwareCount + softwareCount
                    val parcel = Parcel.obtain().apply {
                        writeNoException()
                        writeInt(totalCount)
                    }
                    TransactionResult.OverrideReply(parcel)
                }
                .getOrElse {
                    SystemLogger.error("[TX_ID: $txId] Failed to modify getNumberOfEntries.", it)
                    TransactionResult.SkipTransaction
                }
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            return runCatching {
                    val isBatchMode = code == LIST_ENTRIES_BATCHED_TRANSACTION
                    val params =
                        ListEntriesHandler.cacheParameters(txId, data, isBatchMode)
                            ?: throw Exception("Abort updating entries for invalid parameters.")
                    val updatedKeyDescriptors =
                        ListEntriesHandler.injectGeneratedKeys(txId, callingUid, params, reply)
                    InterceptorUtils.createTypedArrayReply(updatedKeyDescriptors)
                }
                .getOrElse {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to update the result of ${transactionNames[code]!!}.",
                        it,
                    )
                    TransactionResult.SkipTransaction
                }
        } else if (code == GET_KEY_ENTRY_TRANSACTION) {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction

            logTransaction(
                txId,
                "post-${transactionNames[code]!!} ${keyDescriptor.alias}",
                callingUid,
                callingPid,
            )

            runCatching {
                    val response = reply.readTypedObject(KeyEntryResponse.CREATOR)!!
                    val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)

                    // Skip patching for keys whose certs were explicitly set via updateSubcomponent.
                    if (userUpdatedKeys.remove(keyId)) {
                        SystemLogger.debug("[TX_ID: $txId] Skipping cert patch for user-updated key $keyId.")
                        return TransactionResult.SkipTransaction
                    }

                    val authorizations = response.metadata.authorizations
                    val parsedParameters =
                        KeyMintAttestation(
                            authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray()
                        )

                    if (parsedParameters.isAttestKey() &&
                        !KeyMintSecurityLevelInterceptor.importedKeys.contains(keyId)
                    ) {
                        SystemLogger.warning(
                            "[TX_ID: $txId] Found hardware attest key ${keyId.alias} in the reply."
                        )
                        // Attest keys that are not under our control should be overriden.
                        val keyData =
                            CertificateGenerator.generateAttestedKeyPair(
                                callingUid,
                                keyId.alias,
                                null,
                                parsedParameters,
                                response.metadata.keySecurityLevel,
                            ) ?: throw Exception("Failed to create overriding attest key pair.")

                        CertificateHelper.updateCertificateChain(
                                response.metadata,
                                keyData.second.toTypedArray(),
                            )
                            .getOrThrow()
                        response.metadata.authorizations =
                            InterceptorUtils.patchAuthorizations(
                                response.metadata.authorizations,
                                callingUid,
                            )

                        val newNspace = SecureRandom().nextLong()
                        response.metadata.key?.let { it.nspace = newNspace }
                        KeyMintSecurityLevelInterceptor.generatedKeys[keyId] =
                            KeyMintSecurityLevelInterceptor.GeneratedKeyInfo(
                                keyData.first,
                                null,
                                newNspace,
                                response,
                                parsedParameters,
                            )
                        KeyMintSecurityLevelInterceptor.attestationKeys.add(keyId)
                        return InterceptorUtils.createTypedObjectReply(response)
                    }

                    val originalChain = CertificateHelper.getCertificateChain(response)

                    // Check if we should perform attestation patch.
                    if (originalChain == null || originalChain.size < 2) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Skip patching short certificate chain of length ${originalChain?.size}."
                        )
                        return TransactionResult.SkipTransaction
                    }

                    // First, try to retrieve the already-patched chain from our cache to ensure
                    // consistency.
                    val cachedChain = KeyMintSecurityLevelInterceptor.getPatchedChain(keyId)

                    val finalChain: Array<Certificate>
                    if (cachedChain != null) {
                        SystemLogger.debug(
                            "[TX_ID: $txId] Using cached patched certificate chain for $keyId."
                        )
                        finalChain = cachedChain
                    } else {
                        // If no chain is cached (e.g., key existed before simulator started),
                        // perform a live patch as a fallback. This may still be detectable.
                        SystemLogger.info(
                            "[TX_ID: $txId] No cached chain for $keyId. Performing live patch as a fallback."
                        )
                        finalChain =
                            AttestationPatcher.patchCertificateChain(originalChain, callingUid)

                        KeyMintSecurityLevelInterceptor.patchedChains[keyId] = finalChain
                        SystemLogger.debug("Cached patched certificate chain for $keyId.")
                    }

                    CertificateHelper.updateCertificateChain(response.metadata, finalChain)
                        .getOrThrow()
                    response.metadata.authorizations =
                        InterceptorUtils.patchAuthorizations(
                            response.metadata.authorizations,
                            callingUid,
                        )

                    return InterceptorUtils.createTypedObjectReply(response)
                }
                .onFailure {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to modify hardware KeyEntryResponse.",
                        it,
                    )
                    return TransactionResult.SkipTransaction
                }
        }
        return TransactionResult.SkipTransaction
    }

    private fun handleUpdateSubcomponent(callingUid: Int, data: Parcel): TransactionResult {
        data.enforceInterface(IKeystoreService.DESCRIPTOR)
        val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            ?: return TransactionResult.ContinueAndSkipPost

        // Resolve by nspace (KEY_ID) or alias (APP), same as createOperation.
        val generatedKeyInfo =
            when (descriptor.domain) {
                Domain.KEY_ID ->
                    KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                        callingUid,
                        descriptor.nspace,
                    )
                Domain.APP ->
                    descriptor.alias?.let {
                        KeyMintSecurityLevelInterceptor.generatedKeys[KeyIdentifier(callingUid, it)]
                    }
                else -> null
            }

        if (generatedKeyInfo == null) {
            // Hardware key: mark so getKeyEntry skips cert re-patching.
            descriptor.alias?.let { userUpdatedKeys.add(KeyIdentifier(callingUid, it)) }
            return TransactionResult.ContinueAndSkipPost
        }

        SystemLogger.info("Updating sub-component with key[${generatedKeyInfo.nspace}]")
        val metadata = generatedKeyInfo.response.metadata
        val publicCert = data.createByteArray()
        val certificateChain = data.createByteArray()

        metadata.certificate = publicCert
        metadata.certificateChain = certificateChain
        SystemLogger.verbose(
            "Key updated with sizes: [publicCert, certificateChain] = [${publicCert?.size}, ${certificateChain?.size}]"
        )

        return InterceptorUtils.createSuccessReply(writeResultCode = false)
    }
}
