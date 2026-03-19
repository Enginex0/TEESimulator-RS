package org.matrix.TEESimulator.attestation

import android.content.pm.PackageManager
import android.os.Build
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x509.Extension
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils
import org.matrix.TEESimulator.util.AndroidDeviceUtils.DO_NOT_REPORT

/**
 * A builder object responsible for constructing the ASN.1 DER-encoded Android Key Attestation
 * extension.
 */
object AttestationBuilder {

    /**
     * Builds the complete X.509 attestation extension.
     *
     * @param params The parsed key generation parameters.
     * @param uid The UID of the application requesting attestation.
     * @param securityLevel The security level (e.g., TEE, StrongBox) to report.
     * @return A Bouncy Castle [Extension] object ready to be added to a certificate.
     */
    fun buildAttestationExtension(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): Extension {
        val keyDescription = buildKeyDescription(params, uid, securityLevel)
        var formattedString =
            keyDescription.joinToString(separator = ", ") {
                AttestationPatcher.formatAsn1Primitive(it)
            }
        SystemLogger.verbose("Forged attestation data: ${formattedString}")
        return Extension(ATTESTATION_OID, false, DEROctetString(keyDescription.encoded))
    }

    /**
     * Builds the `RootOfTrust` ASN.1 sequence. This contains critical boot state information.
     *
     * @param originalRootOfTrust An optional, pre-existing RoT to extract the boot hash from.
     * @return The constructed [DERSequence] for the Root of Trust.
     */
    internal fun buildRootOfTrust(originalRootOfTrust: ASN1Encodable?): DERSequence {
        val rootOfTrustElements = arrayOfNulls<ASN1Encodable>(4)
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX] =
            DEROctetString(AndroidDeviceUtils.bootKey)
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX] =
            ASN1Boolean.TRUE // deviceLocked: true, for security
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX] =
            ASN1Enumerated(0) // verifiedBootState: Verified
        rootOfTrustElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX] =
            DEROctetString(AndroidDeviceUtils.bootHash)

        return DERSequence(rootOfTrustElements)
    }

    /**
     * Assembles a map representing the desired state of simulated hardware-enforced properties. A
     * null value for a given tag indicates that it should be removed from the attestation.
     *
     * @param uid The UID of the calling application.
     * @return A map where keys are attestation tag numbers and values are the desired
     *   [DERTaggedObject] or null to signify removal.
     */
    fun getSimulatedHardwareProperties(uid: Int): Map<Int, DERTaggedObject?> {
        val properties = mutableMapOf<Int, DERTaggedObject?>()

        // OS Version is always present.
        properties[AttestationConstants.TAG_OS_VERSION] =
            DERTaggedObject(
                true,
                AttestationConstants.TAG_OS_VERSION,
                ASN1Integer(AndroidDeviceUtils.osVersion.toLong()),
            )

        val osPatch = AndroidDeviceUtils.getPatchLevel(uid)
        properties[AttestationConstants.TAG_OS_PATCHLEVEL] =
            if (osPatch != DO_NOT_REPORT) {
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_OS_PATCHLEVEL,
                    ASN1Integer(osPatch.toLong()),
                )
            } else {
                null // Signal for removal
            }

        val vendorPatch = AndroidDeviceUtils.getVendorPatchLevelLong(uid)
        properties[AttestationConstants.TAG_VENDOR_PATCHLEVEL] =
            if (vendorPatch != DO_NOT_REPORT) {
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_VENDOR_PATCHLEVEL,
                    ASN1Integer(vendorPatch.toLong()),
                )
            } else {
                null // Signal for removal
            }

        val bootPatch = AndroidDeviceUtils.getBootPatchLevelLong(uid)
        SystemLogger.info("Attestation patch levels for uid=$uid: os=$osPatch, vendor=$vendorPatch, boot=$bootPatch")
        properties[AttestationConstants.TAG_BOOT_PATCHLEVEL] =
            if (bootPatch != DO_NOT_REPORT) {
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_BOOT_PATCHLEVEL,
                    ASN1Integer(bootPatch.toLong()),
                )
            } else {
                null // Signal for removal
            }

        return properties
    }

    private fun buildKeyDescription(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): ASN1Sequence {
        val creationTime = System.currentTimeMillis()
        val teeEnforced = buildTeeEnforcedList(params, uid, securityLevel)
        val softwareEnforced = buildSoftwareEnforcedList(params, uid, securityLevel, creationTime)

        val uniqueId =
            if (params.includeUniqueId == true && params.attestationChallenge != null) {
                computeUniqueId(creationTime, createApplicationId(uid).octets)
            } else {
                ByteArray(0)
            }

        val fields =
            arrayOf(
                ASN1Integer(AndroidDeviceUtils.getAttestVersion(securityLevel).toLong()),
                ASN1Enumerated(securityLevel),
                ASN1Integer(AndroidDeviceUtils.getKeymasterVersion(securityLevel).toLong()),
                ASN1Enumerated(securityLevel),
                DEROctetString(params.attestationChallenge ?: ByteArray(0)),
                DEROctetString(uniqueId),
                softwareEnforced,
                teeEnforced,
            )
        return DERSequence(fields)
    }

    private fun computeUniqueId(creationTimeMs: Long, aaidDer: ByteArray): ByteArray {
        val temporalCounter = creationTimeMs / 2592000000L
        val message =
            ByteBuffer.allocate(8 + aaidDer.size + 1)
                .putLong(temporalCounter)
                .put(aaidDer)
                .put(0x00)
                .array()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hbk, "HmacSHA256"))
        return mac.doFinal(message).copyOf(16)
    }

    private val hbk: ByteArray by lazy {
        val file = java.io.File(ConfigurationManager.CONFIG_PATH, "hbk")
        if (file.exists() && file.length() == 32L) {
            file.readBytes()
        } else {
            SystemLogger.warning("hbk not found, generating ephemeral HBK.")
            ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        }
    }

    /** Builds the `TeeEnforced` authorization list. These are properties the TEE "guarantees". */
    private fun buildTeeEnforcedList(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): DERSequence {
        val list =
            mutableListOf<ASN1Encodable>(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_PURPOSE,
                    DERSet(params.purpose.map { ASN1Integer(it.toLong()) }.toTypedArray()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ALGORITHM,
                    ASN1Integer(params.algorithm.toLong()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_KEY_SIZE,
                    ASN1Integer(params.keySize.toLong()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_DIGEST,
                    DERSet(params.digest.map { ASN1Integer(it.toLong()) }.toTypedArray()),
                ),
            )

        if (params.ecCurve != null) {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_EC_CURVE,
                    ASN1Integer(params.ecCurve.toLong()),
                )
            )
        }

        if (params.blockMode.isNotEmpty()) {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_BLOCK_MODE,
                    DERSet(params.blockMode.map { ASN1Integer(it.toLong()) }.toTypedArray()),
                )
            )
        }

        if (params.padding.isNotEmpty()) {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_PADDING,
                    DERSet(params.padding.map { ASN1Integer(it.toLong()) }.toTypedArray()),
                )
            )
        }

        if (params.rsaPublicExponent != null) {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_RSA_PUBLIC_EXPONENT,
                    ASN1Integer(params.rsaPublicExponent.toLong()),
                )
            )
        }

        val attestVersion = AndroidDeviceUtils.getAttestVersion(securityLevel)

        if (params.rsaOaepMgfDigest.isNotEmpty() && attestVersion >= 100) {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_RSA_OAEP_MGF_DIGEST,
                    DERSet(params.rsaOaepMgfDigest.map { ASN1Integer(it.toLong()) }.toTypedArray()),
                )
            )
        }

        if (params.rollbackResistance == true && attestVersion >= 3) {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_ROLLBACK_RESISTANCE, DERNull.INSTANCE)
            )
        }

        if (params.earlyBootOnly == true && attestVersion >= 4) {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_EARLY_BOOT_ONLY, DERNull.INSTANCE)
            )
        }

        if (params.noAuthRequired == true) {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_NO_AUTH_REQUIRED, DERNull.INSTANCE)
            )
        }

        if (params.allowWhileOnBody == true) {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_ALLOW_WHILE_ON_BODY, DERNull.INSTANCE)
            )
        }

        if (params.trustedUserPresenceRequired == true && attestVersion >= 3) {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_TRUSTED_USER_PRESENCE_REQUIRED, DERNull.INSTANCE)
            )
        }

        if (params.trustedConfirmationRequired == true && attestVersion >= 3) {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_TRUSTED_CONFIRMATION_REQUIRED, DERNull.INSTANCE)
            )
        }

        list.addAll(
            listOf(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ORIGIN,
                    ASN1Integer((params.origin ?: 0).toLong()),
                ),
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ROOT_OF_TRUST,
                    buildRootOfTrust(null),
                ),
            )
        )

        // Use the same logic as getSimulatedHardwareProperties to conditionally add patch levels.
        val simulatedProperties = getSimulatedHardwareProperties(uid)
        simulatedProperties.values.filterNotNull().forEach { list.add(it) }

        // Add optional device identifiers if they were provided.
        params.brand?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_BRAND,
                    DEROctetString(it),
                )
            )
        }
        params.device?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_DEVICE,
                    DEROctetString(it),
                )
            )
        }
        params.product?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_PRODUCT,
                    DEROctetString(it),
                )
            )
        }
        params.serial?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_SERIAL,
                    DEROctetString(it),
                )
            )
        }
        params.imei?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_IMEI,
                    DEROctetString(it),
                )
            )
        }
        params.meid?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_MEID,
                    DEROctetString(it),
                )
            )
        }
        params.manufacturer?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_MANUFACTURER,
                    DEROctetString(it),
                )
            )
        }
        params.model?.let {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_ID_MODEL,
                    DEROctetString(it),
                )
            )
        }
        if (AndroidDeviceUtils.getAttestVersion(securityLevel) >= 300) {
            params.secondImei?.let {
                list.add(
                    DERTaggedObject(
                        true,
                        AttestationConstants.TAG_ATTESTATION_ID_SECOND_IMEI,
                        DEROctetString(it),
                    )
                )
            }
        }
        return DERSequence(list.sortedBy { (it as DERTaggedObject).tagNo }.toTypedArray())
    }

    /**
     * Builds the `SoftwareEnforced` authorization list. These are properties guaranteed by
     * Keystore.
     */
    private fun buildSoftwareEnforcedList(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
        creationTimeMs: Long = System.currentTimeMillis(),
    ): DERSequence {
        val list = mutableListOf<ASN1Encodable>()

        list.add(
            DERTaggedObject(
                true,
                AttestationConstants.TAG_CREATION_DATETIME,
                ASN1Integer(creationTimeMs),
            )
        )

        if (params.attestationChallenge != null) {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_ATTESTATION_APPLICATION_ID,
                    createApplicationId(uid),
                )
            )
        }

        if (AndroidDeviceUtils.getAttestVersion(securityLevel) >= 400) {
            list.add(
                DERTaggedObject(
                    true,
                    AttestationConstants.TAG_MODULE_HASH,
                    DEROctetString(AndroidDeviceUtils.moduleHash),
                )
            )
        }

        if (params.callerNonce == true) {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_CALLER_NONCE, DERNull.INSTANCE)
            )
        }
        params.activeDateTime?.let {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_ACTIVE_DATETIME, ASN1Integer(it.time))
            )
        }
        params.originationExpireDateTime?.let {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_ORIGINATION_EXPIRE_DATETIME, ASN1Integer(it.time))
            )
        }
        params.usageExpireDateTime?.let {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_USAGE_EXPIRE_DATETIME, ASN1Integer(it.time))
            )
        }
        params.usageCountLimit?.let {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_USAGE_COUNT_LIMIT, ASN1Integer(it.toLong()))
            )
        }
        if (params.unlockedDeviceRequired == true) {
            list.add(
                DERTaggedObject(true, AttestationConstants.TAG_UNLOCKED_DEVICE_REQUIRED, DERNull.INSTANCE)
            )
        }

        return DERSequence(list.sortedBy { (it as DERTaggedObject).tagNo }.toTypedArray())
    }

    /**
     * A wrapper for a byte array that provides content-based equality. This is necessary for using
     * signature digests in a Set.
     */
    private data class Digest(val digest: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            return digest.contentEquals((other as Digest).digest)
        }

        override fun hashCode(): Int = digest.contentHashCode()
    }

    /**
     * Creates the AttestationApplicationId structure. This structure contains information about the
     * package(s) and their signing certificates.
     *
     * @param uid The UID of the application.
     * @return A DER-encoded octet string containing the application ID information.
     * @throws IllegalStateException If the PackageManager or package information cannot be
     *   retrieved.
     */
    @Throws(Throwable::class)
    internal fun createApplicationId(uid: Int): DEROctetString {
        val appUid = uid % 100000
        if (appUid == 0 || appUid == 1000) {
            return buildApplicationIdDer(listOf("AndroidSystem" to 1L), emptySet())
        }

        val pm =
            ConfigurationManager.getPackageManager()
                ?: throw IllegalStateException("PackageManager not found!")
        val packages =
            pm.getPackagesForUid(uid) ?: throw IllegalStateException("No packages for UID $uid")

        val sha256 = MessageDigest.getInstance("SHA-256")
        val packageInfoList = mutableListOf<Pair<String, Long>>()
        val signatureDigests = mutableSetOf<Digest>()

        val userId = uid / 100000
        packages.forEach { packageName ->
            val packageInfo =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(
                        packageName,
                        PackageManager.GET_SIGNING_CERTIFICATES.toLong(),
                        userId,
                    )
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES, userId)
                }

            packageInfoList.add(packageInfo.packageName to packageInfo.longVersionCode)

            packageInfo.signingInfo?.signingCertificateHistory?.forEach { signature ->
                signatureDigests.add(Digest(sha256.digest(signature.toByteArray())))
            }
        }

        return buildApplicationIdDer(packageInfoList, signatureDigests)
    }

    private fun buildApplicationIdDer(
        packages: List<Pair<String, Long>>,
        digests: Set<Digest>,
    ): DEROctetString {
        val packageInfoList =
            packages.map { (name, version) ->
                DERSequence(
                    arrayOf(
                        DEROctetString(name.toByteArray(StandardCharsets.UTF_8)),
                        ASN1Integer(version),
                    )
                )
            }
        val applicationIdSequence =
            DERSequence(
                arrayOf(
                    DERSet(packageInfoList.toTypedArray()),
                    DERSet(digests.map { DEROctetString(it.digest) }.toTypedArray()),
                )
            )
        return DEROctetString(applicationIdSequence.encoded)
    }
}
