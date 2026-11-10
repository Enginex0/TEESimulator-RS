package org.matrix.TEESimulator.interception.keystore.shim

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyPair
import java.security.MessageDigest
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import org.matrix.TEESimulator.config.ConfigurationManager.CONFIG_PATH
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateHelper

data class PersistedKeyData(
    val uid: Int,
    val alias: String,
    val nspace: Long,
    val securityLevel: Int,
    val isAttestationKey: Boolean,
    val algorithm: Int,
    val keySize: Int,
    val ecCurve: Int,
    val purposes: List<Int>,
    val digests: List<Int>,
    /** PKCS#8-encoded private key for asymmetric records, empty for symmetric. */
    val privateKeyBytes: ByteArray,
    val certChainBytes: List<ByteArray>,
    /**
     * Byte-identical KeyMetadata parcel snapshot. Restoring authorizations directly from these
     * bytes preserves tag count, order, and exact security-level annotations across reboots — the
     * kind of structural details apps fingerprint to decide whether the alias is still "the same
     * key".
     */
    val metadataBytes: ByteArray,
    /**
     * Raw secret material for symmetric records (AES, HMAC, 3DES). Empty for asymmetric. Critical
     * for AndroidX security crypto MasterKey (AES-GCM-256) — without this every reboot regenerates
     * a fresh AES key and EncryptedSharedPreferences becomes undecryptable, which is what banking
     * apps interpret as session expiry and force a relogin.
     */
    val symmetricKeyBytes: ByteArray,
    val symmetricAlgorithm: String,
)

object GeneratedKeyPersistence {

    /**
     * Single source of truth for the on-disk format. Bump this every time the layout changes; older
     * numbers are silently skipped on read so stale dev artifacts and pre-fix upstream files can't
     * be partially rehydrated into broken in-memory state.
     *
     * History: 1 — original upstream layout (no metadata snapshot, no symmetric block; restored
     * keys lose authorization tags and AES master keys altogether — apps relying on persisted
     * keystore state across reboots get logged out) 2 — transitional dev-only format that added
     * metadata but still missed the symmetric block; never shipped 3 — current: byte-identical
     * KeyMetadata snapshot + raw symmetric key material so AES/HMAC keys survive reboots
     */
    private const val FORMAT_VERSION = 3
    private val PERSISTENCE_DIR = File(CONFIG_PATH, "persistent_keys")

    // Per-filename locks to prevent concurrent writes to the same key file
    private val fileLocks = ConcurrentHashMap<String, ReentrantLock>()

    private fun getLockForKey(filename: String): ReentrantLock {
        return fileLocks.computeIfAbsent(filename) { ReentrantLock() }
    }

    fun save(
        keyId: KeyIdentifier,
        keyPair: KeyPair?,
        secretKey: javax.crypto.SecretKey?,
        nspace: Long,
        securityLevel: Int,
        certChain: List<Certificate>,
        algorithm: Int,
        keySize: Int,
        ecCurve: Int,
        purposes: List<Int>,
        digests: List<Int>,
        isAttestationKey: Boolean,
        metadataBytes: ByteArray? = null,
    ) {
        require(keyPair != null || secretKey != null) {
            "Either keyPair or secretKey must be provided"
        }
        val filename = keyFileName(keyId.uid, keyId.alias)
        val lock = getLockForKey(filename)
        SystemLogger.debug("[Persistence] Acquiring lock for $filename")
        lock.lock()
        try {
            SystemLogger.debug("[Persistence] Lock acquired for $filename")
            runCatching {
                    PERSISTENCE_DIR.mkdirs()
                    val finalFile = File(PERSISTENCE_DIR, filename)
                    val tmpFile = File(PERSISTENCE_DIR, "$filename.tmp")

                    try {
                        DataOutputStream(BufferedOutputStream(FileOutputStream(tmpFile))).use { out
                            ->
                            out.writeInt(FORMAT_VERSION)
                            out.writeInt(securityLevel)
                            out.writeInt(keyId.uid)
                            out.writeUTF(keyId.alias)
                            out.writeLong(nspace)
                            out.writeBoolean(isAttestationKey)
                            out.writeInt(algorithm)
                            out.writeInt(keySize)
                            out.writeInt(ecCurve)

                            out.writeInt(purposes.size)
                            purposes.forEach { out.writeInt(it) }

                            out.writeInt(digests.size)
                            digests.forEach { out.writeInt(it) }

                            // Asymmetric key block (empty for symmetric-only).
                            val pkBytes = keyPair?.private?.encoded ?: ByteArray(0)
                            out.writeInt(pkBytes.size)
                            out.write(pkBytes)

                            out.writeInt(certChain.size)
                            certChain.forEach { cert ->
                                val encoded = cert.encoded
                                out.writeInt(encoded.size)
                                out.write(encoded)
                            }

                            // Metadata snapshot (always present, may be empty
                            // if the live KeyMetadata could not be marshalled).
                            val mdBytes = metadataBytes ?: ByteArray(0)
                            out.writeInt(mdBytes.size)
                            if (mdBytes.isNotEmpty()) out.write(mdBytes)

                            // Symmetric key block (empty for asymmetric keys).
                            if (secretKey != null) {
                                val skBytes = secretKey.encoded
                                out.writeUTF(secretKey.algorithm)
                                out.writeInt(skBytes.size)
                                out.write(skBytes)
                            } else {
                                out.writeUTF("")
                                out.writeInt(0)
                            }
                        }
                    } catch (e: Exception) {
                        tmpFile.delete()
                        throw e
                    }

                    // Atomic rename — if this fails the tmp is left behind and cleaned on next
                    // deleteAll
                    if (!tmpFile.renameTo(finalFile)) {
                        tmpFile.delete()
                        throw IllegalStateException(
                            "Failed to atomically rename $tmpFile -> $finalFile"
                        )
                    }

                    // Verify write succeeded - catches disk-full or filesystem errors
                    if (!finalFile.exists() || finalFile.length() < 20) {
                        throw IOException("File write verification failed - possible disk full")
                    }

                    SystemLogger.debug("Persisted key: $keyId")
                }
                .onFailure { e -> SystemLogger.error("Failed to persist key $keyId", e) }
        } finally {
            lock.unlock()
            SystemLogger.debug("[Persistence] Lock released for $filename")
        }
    }

    fun delete(keyId: KeyIdentifier) {
        runCatching {
                val file = File(PERSISTENCE_DIR, keyFileName(keyId.uid, keyId.alias))
                if (file.exists()) {
                    if (file.delete()) {
                        fileLocks.remove(keyFileName(keyId.uid, keyId.alias))
                        SystemLogger.debug("Deleted persisted key: $keyId")
                    } else {
                        SystemLogger.warning("Failed to delete persisted key file: ${file.name}")
                    }
                } else {
                    SystemLogger.debug("No persisted file to delete for: $keyId")
                }
            }
            .onFailure { e -> SystemLogger.error("Failed to delete persisted key $keyId", e) }
    }

    fun deleteAll() {
        runCatching {
                if (!PERSISTENCE_DIR.exists()) {
                    SystemLogger.debug("No persistent_keys directory, nothing to delete")
                    return
                }
                val files = PERSISTENCE_DIR.listFiles()
                if (files == null) {
                    SystemLogger.warning("Cannot list persistent_keys directory")
                    return
                }
                var count = 0
                files.forEach { file ->
                    if (file.name.endsWith(".bin") || file.name.endsWith(".tmp")) {
                        if (file.delete()) count++
                    }
                }
                fileLocks.clear()
                SystemLogger.info("Deleted $count persisted key files")
            }
            .onFailure { e -> SystemLogger.error("Failed to delete all persisted keys", e) }
    }

    fun loadAll(securityLevel: Int): List<PersistedKeyData> {
        if (!PERSISTENCE_DIR.exists()) {
            SystemLogger.debug("No persistent_keys directory, nothing to load")
            return emptyList()
        }
        val files = PERSISTENCE_DIR.listFiles { _, name -> name.endsWith(".bin") }
        if (files == null) {
            SystemLogger.warning("Cannot read persistent_keys directory")
            return emptyList()
        }
        if (files.isEmpty()) {
            SystemLogger.debug("No persisted key files found")
            return emptyList()
        }
        SystemLogger.info("Found ${files.size} persisted key files to process")

        val result = mutableListOf<PersistedKeyData>()

        for (file in files) {
            runCatching {
                    DataInputStream(BufferedInputStream(FileInputStream(file))).use { input ->
                        val version = input.readInt()
                        if (version != FORMAT_VERSION) {
                            // Old upstream files (v1) and dev-only intermediate
                            // files (v2) are missing the metadata snapshot
                            // and/or symmetric key block — restoring them
                            // would put broken state in memory (apps relying
                            // on those records get logged out). Skip and let
                            // the next generateKey re-create cleanly with the
                            // new format. Affected apps re-login once after
                            // upgrade, then never again.
                            SystemLogger.info(
                                "Skipping ${file.name}: legacy format version $version. " +
                                    "It will be replaced on next generateKey for this alias."
                            )
                            return@runCatching
                        }

                        val storedSecLevel = input.readInt()
                        val uid = input.readInt()
                        val alias = input.readUTF()
                        val nspace = input.readLong()
                        val isAttestKey = input.readBoolean()
                        val algo = input.readInt()
                        val kSize = input.readInt()
                        val curve = input.readInt()

                        val purposeCount = requireBounds(input.readInt(), 64, "purposeCount")
                        val purposes = (0 until purposeCount).map { input.readInt() }

                        val digestCount = requireBounds(input.readInt(), 64, "digestCount")
                        val digests = (0 until digestCount).map { input.readInt() }

                        val pkLen = requireBounds(input.readInt(), 8192, "pkLen")
                        val pkBytes = ByteArray(pkLen)
                        if (pkLen > 0) input.readFully(pkBytes)

                        val certCount = requireBounds(input.readInt(), 10, "certCount")
                        val certChainBytes =
                            (0 until certCount).map {
                                val certLen = requireBounds(input.readInt(), 65536, "certLen")
                                val certBytes = ByteArray(certLen)
                                input.readFully(certBytes)
                                certBytes
                            }

                        val metaLen = requireBounds(input.readInt(), 256 * 1024, "metaLen")
                        val metadataBytes =
                            ByteArray(metaLen).also { if (metaLen > 0) input.readFully(it) }

                        val skAlgo = input.readUTF()
                        val skLen = requireBounds(input.readInt(), 8192, "skLen")
                        val skBytes = ByteArray(skLen).also { if (skLen > 0) input.readFully(it) }

                        if (storedSecLevel == securityLevel) {
                            result.add(
                                PersistedKeyData(
                                    uid = uid,
                                    alias = alias,
                                    nspace = nspace,
                                    securityLevel = storedSecLevel,
                                    isAttestationKey = isAttestKey,
                                    algorithm = algo,
                                    keySize = kSize,
                                    ecCurve = curve,
                                    purposes = purposes,
                                    digests = digests,
                                    privateKeyBytes = pkBytes,
                                    certChainBytes = certChainBytes,
                                    metadataBytes = metadataBytes,
                                    symmetricKeyBytes = skBytes,
                                    symmetricAlgorithm = skAlgo,
                                )
                            )
                        }
                    }
                }
                .onFailure { e ->
                    SystemLogger.warning("Skipping corrupted persisted key file: ${file.name}", e)
                }
        }

        SystemLogger.info("Loaded ${result.size} persisted keys for security level $securityLevel")
        return result
    }

    // Re-persist updates the cert chain for an already-persisted key without
    // reconstructing authorization parameters from the response. This avoids
    // pulling keymint Tag dependencies into this file and is correct because
    // the only field that changes post-generation is the patched cert chain.
    fun rePersistIfNeeded(
        callingUid: Int,
        generatedKeyInfo: KeyMintSecurityLevelInterceptor.GeneratedKeyInfo,
    ) {
        val metadata = generatedKeyInfo.response.metadata
        if (metadata == null) {
            SystemLogger.debug("rePersist: no metadata, skipping")
            return
        }
        val secLevel = metadata.keySecurityLevel

        val entry =
            KeyMintSecurityLevelInterceptor.generatedKeys.entries.find { (id, info) ->
                id.uid == callingUid && info.nspace == generatedKeyInfo.nspace
            }
        if (entry == null) {
            SystemLogger.debug(
                "rePersist: key not found in map for uid=$callingUid nspace=${generatedKeyInfo.nspace}"
            )
            return
        }

        val keyId = entry.key
        val filename = keyFileName(keyId.uid, keyId.alias)
        val existing = File(PERSISTENCE_DIR, filename)

        if (!existing.exists()) {
            SystemLogger.debug("rePersist: no existing file for $keyId, skipping")
            return
        }

        val newChain = CertificateHelper.getCertificateChain(metadata)
        if (newChain == null) {
            SystemLogger.warning("rePersist: could not extract cert chain for $keyId")
            return
        }

        val persisted =
            runCatching {
                    DataInputStream(BufferedInputStream(FileInputStream(existing))).use { input ->
                        val version = input.readInt()
                        if (version != FORMAT_VERSION) {
                            SystemLogger.warning(
                                "rePersist: legacy format version $version for $keyId, will not re-persist (next generateKey replaces it)"
                            )
                            return
                        }
                        readPersistedKeyData(input)
                    }
                }
                .getOrNull()
        if (persisted == null) {
            SystemLogger.warning("rePersist: failed to read existing data for $keyId")
            return
        }

        val keyPair = generatedKeyInfo.keyPair
        val secretKey = generatedKeyInfo.secretKey
        if (keyPair == null && secretKey == null) {
            SystemLogger.warning("rePersist: no key material for $keyId")
            return
        }
        // Serialize the live KeyMetadata (now contains the user-installed cert
        // chain via updateSubcomponent) so the next boot restores byte-identical
        // metadata. KeyMetadata is binder-free, so marshall() is safe here.
        val metadataBytes =
            runCatching {
                    android.os.Parcel.obtain().let { parcel ->
                        try {
                            metadata.writeToParcel(parcel, 0)
                            parcel.marshall()
                        } finally {
                            parcel.recycle()
                        }
                    }
                }
                .getOrNull()
        save(
            keyId = keyId,
            keyPair = keyPair,
            secretKey = secretKey,
            nspace = generatedKeyInfo.nspace,
            securityLevel = secLevel,
            certChain = newChain.toList(),
            algorithm = persisted.algorithm,
            keySize = persisted.keySize,
            ecCurve = persisted.ecCurve,
            purposes = persisted.purposes,
            digests = persisted.digests,
            isAttestationKey = persisted.isAttestationKey,
            metadataBytes = metadataBytes,
        )
        SystemLogger.debug("Re-persisted key $keyId with updated cert chain")
    }

    // Corrupted binary files can have arbitrary length fields — cap allocations
    private fun requireBounds(value: Int, max: Int, name: String): Int {
        require(value in 0..max) { "$name out of bounds: $value (max $max)" }
        return value
    }

    private fun keyFileName(uid: Int, alias: String): String {
        val digest =
            MessageDigest.getInstance("SHA-256").digest("$uid:$alias".toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) } + ".bin"
    }

    // Reads all fields after the version int has already been consumed
    // and validated by the caller.
    private fun readPersistedKeyData(input: DataInputStream): PersistedKeyData {
        val secLevel = input.readInt()
        val uid = input.readInt()
        val alias = input.readUTF()
        val nspace = input.readLong()
        val isAttestKey = input.readBoolean()
        val algo = input.readInt()
        val kSize = input.readInt()
        val curve = input.readInt()

        val purposeCount = requireBounds(input.readInt(), 64, "purposeCount")
        val purposes = (0 until purposeCount).map { input.readInt() }

        val digestCount = requireBounds(input.readInt(), 64, "digestCount")
        val digests = (0 until digestCount).map { input.readInt() }

        val pkLen = requireBounds(input.readInt(), 8192, "pkLen")
        val pkBytes = ByteArray(pkLen)
        if (pkLen > 0) input.readFully(pkBytes)

        val certCount = requireBounds(input.readInt(), 10, "certCount")
        val certChainBytes =
            (0 until certCount).map {
                val certLen = requireBounds(input.readInt(), 65536, "certLen")
                val certBytes = ByteArray(certLen)
                input.readFully(certBytes)
                certBytes
            }

        val metaLen = requireBounds(input.readInt(), 256 * 1024, "metaLen")
        val metadataBytes = ByteArray(metaLen).also { if (metaLen > 0) input.readFully(it) }

        val skAlgo = input.readUTF()
        val skLen = requireBounds(input.readInt(), 8192, "skLen")
        val skBytes = ByteArray(skLen).also { if (skLen > 0) input.readFully(it) }

        return PersistedKeyData(
            uid = uid,
            alias = alias,
            nspace = nspace,
            securityLevel = secLevel,
            isAttestationKey = isAttestKey,
            algorithm = algo,
            keySize = kSize,
            ecCurve = curve,
            purposes = purposes,
            digests = digests,
            privateKeyBytes = pkBytes,
            certChainBytes = certChainBytes,
            metadataBytes = metadataBytes,
            symmetricKeyBytes = skBytes,
            symmetricAlgorithm = skAlgo,
        )
    }
}
