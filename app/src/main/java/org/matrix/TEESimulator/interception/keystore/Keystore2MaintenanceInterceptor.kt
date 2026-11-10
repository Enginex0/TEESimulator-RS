package org.matrix.TEESimulator.interception.keystore

import android.os.IBinder
import android.os.Parcel
import android.security.maintenance.IKeystoreMaintenance
import android.system.keystore2.Domain
import android.system.keystore2.KeyDescriptor
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor

/**
 * Intercepts the keystore2 daemon's `android.security.maintenance` binder so our synthetic key
 * state follows the same lifecycle events the platform applies to real keys.
 *
 * This is a pure side-effect hook: every handled transaction mutates only our own synthetic state
 * and then returns [TransactionResult.ContinueAndSkipPost], so the real keystore2 still performs
 * the real operation. We never fabricate a maintenance reply, so real key lifecycle is never
 * disturbed.
 *
 * Mounted via `register()` from [Keystore2Interceptor.onInterceptorReady]; the maintenance binder
 * is hosted by the same keystore2 process, so the already-injected native hook reaches it too.
 */
object Keystore2MaintenanceInterceptor : BinderInterceptor() {
    private val stubClass = IKeystoreMaintenance.Stub::class.java

    private val CLEAR_NAMESPACE_TRANSACTION =
        InterceptorUtils.getTransactCode(stubClass, "clearNamespace")
    private val DELETE_ALL_KEYS_TRANSACTION =
        InterceptorUtils.getTransactCode(stubClass, "deleteAllKeys")
    private val MIGRATE_KEY_NAMESPACE_TRANSACTION =
        InterceptorUtils.getTransactCode(stubClass, "migrateKeyNamespace")

    /** Only the lifecycle transactions we mirror; unresolved codes (-1) are dropped. */
    val interceptedCodes: IntArray by lazy {
        listOf(
                CLEAR_NAMESPACE_TRANSACTION,
                DELETE_ALL_KEYS_TRANSACTION,
                MIGRATE_KEY_NAMESPACE_TRANSACTION,
            )
            .filter { it != -1 }
            .toIntArray()
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
        when (code) {
            CLEAR_NAMESPACE_TRANSACTION -> handleClearNamespace(data)
            DELETE_ALL_KEYS_TRANSACTION ->
                KeyMintSecurityLevelInterceptor.clearAllGeneratedKeys("maintenance.deleteAllKeys")
            MIGRATE_KEY_NAMESPACE_TRANSACTION -> handleMigrateKeyNamespace(data, callingUid)
        }
        // Always let the real keystore2 perform the real lifecycle operation.
        return TransactionResult.ContinueAndSkipPost
    }

    private fun handleClearNamespace(data: Parcel) {
        data.enforceInterface(IKeystoreMaintenance.DESCRIPTOR)
        val domain = data.readInt()
        val nspace = data.readLong()
        // Only Domain.APP namespaces map to our per-uid synthetic keys; nspace is the app uid.
        if (domain == Domain.APP) {
            KeyMintSecurityLevelInterceptor.clearNamespaceKeys(nspace.toInt())
        }
    }

    private fun handleMigrateKeyNamespace(data: Parcel, callingUid: Int) {
        data.enforceInterface(IKeystoreMaintenance.DESCRIPTOR)
        val source = data.readTypedObject(KeyDescriptor.CREATOR) ?: return
        val destination = data.readTypedObject(KeyDescriptor.CREATOR) ?: return
        val srcId = resolveSyntheticKeyId(source, callingUid) ?: return
        if (!KeyMintSecurityLevelInterceptor.generatedKeys.containsKey(srcId)) return // not ours

        val dstId = resolveDestinationKeyId(destination, callingUid)
        if (dstId == null) {
            // Migrated out of our trackable (Domain.APP/alias) space -> drop our shadow so reads
            // fall through to the real keystore2, which now owns it at the new namespace.
            KeyMintSecurityLevelInterceptor.cleanupKeyData(srcId)
        } else {
            KeyMintSecurityLevelInterceptor.migrateGeneratedKey(srcId, dstId)
        }
    }

    /** Resolves a synthetic owner key from a source descriptor (Domain.APP alias or KEY_ID). */
    private fun resolveSyntheticKeyId(descriptor: KeyDescriptor, callingUid: Int): KeyIdentifier? =
        when {
            descriptor.alias != null -> KeyIdentifier(callingUid, descriptor.alias)
            descriptor.domain == Domain.KEY_ID ->
                KeyMintSecurityLevelInterceptor.generatedKeys.entries
                    .firstOrNull {
                        it.key.uid == callingUid && it.value.nspace == descriptor.nspace
                    }
                    ?.key
            else -> null
        }

    /** Destination must be an addressable Domain.APP alias for us to keep tracking the key. */
    private fun resolveDestinationKeyId(
        descriptor: KeyDescriptor,
        callingUid: Int,
    ): KeyIdentifier? {
        val alias = descriptor.alias ?: return null
        if (descriptor.domain != Domain.APP) return null
        val uid = if (descriptor.nspace > 0) descriptor.nspace.toInt() else callingUid
        return KeyIdentifier(uid, alias)
    }
}
