package org.matrix.TEESimulator.logging

import android.hardware.security.keymint.Tag
import android.system.keystore2.Authorization
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.util.AndroidDeviceUtils

/**
 * Assembles the per-UID "attestation dossier": for a targeted app, the full decoded attestation we
 * actually hand it, the identity of every certificate in the returned chain, and the source of each
 * device value that fed that attestation. Emitting all three where a chain is produced turns "the
 * app rejects us" into a field-by-field record that can be diffed against a genuine TEE.
 */
object AttestationDossier {

    /**
     * Records the dossier for [chain] under [uid], tagged with the [path] that produced it
     * (`FORGE-rust`, `FORGE-bouncycastle`, or `PATCH`). No-op for untargeted UIDs and release
     * builds; the expensive decoding is skipped entirely when the UID is out of scope.
     */
    fun log(uid: Int, txId: Long, path: String, chain: List<Certificate>) {
        if (!SystemLogger.isUidLogged(uid)) return
        val leaf = chain.firstOrNull() as? X509Certificate
        val extension =
            leaf?.let { AttestationPatcher.formatAttestationExtension(it) }
                ?: "<no attestation extension>"
        SystemLogger.uidLog(uid, txId, "attest", "path=$path depth=${chain.size} $extension")
        SystemLogger.uidLog(uid, txId, "keybox", "file=${ConfigurationManager.getKeyboxFileForUid(uid)}")
        SystemLogger.uidLog(uid, txId, "chain", AttestationPatcher.formatCertChain(chain))
        SystemLogger.uidLog(uid, txId, "chain-verify", AttestationPatcher.formatChainVerification(chain))
        SystemLogger.uidLog(uid, txId, "props", AndroidDeviceUtils.describeSources(uid))
    }

    /**
     * Records the *shape* of the emitted authorization list — count, ordered tags, and per-auth
     * securityLevel. This is the exact surface the duck detector's generate-mode parcel fingerprint
     * stride-walks, so logging it readably lets a "fingerprint" detection be compared against the
     * known genuine-TEE shape without decoding the marshalled reply offline.
     */
    fun logAuthShape(uid: Int, txId: Long, authorizations: Array<Authorization>?) {
        if (!SystemLogger.isUidLogged(uid)) return
        val auths = authorizations ?: return
        val shape = auths.joinToString(",") { "${tagName(it.keyParameter.tag)}/${it.securityLevel}" }
        SystemLogger.uidLog(uid, txId, "auth-shape", "n=${auths.size} [$shape]")
    }

    /** Names the authorization tags that occur in generate-mode replies; others render as numbers. */
    private fun tagName(tag: Int): String =
        when (tag) {
            Tag.PURPOSE -> "PURPOSE"
            Tag.ALGORITHM -> "ALGORITHM"
            Tag.KEY_SIZE -> "KEY_SIZE"
            Tag.DIGEST -> "DIGEST"
            Tag.PADDING -> "PADDING"
            Tag.EC_CURVE -> "EC_CURVE"
            Tag.RSA_PUBLIC_EXPONENT -> "RSA_PUBLIC_EXPONENT"
            Tag.NO_AUTH_REQUIRED -> "NO_AUTH_REQUIRED"
            Tag.ORIGIN -> "ORIGIN"
            Tag.OS_VERSION -> "OS_VERSION"
            Tag.OS_PATCHLEVEL -> "OS_PATCHLEVEL"
            Tag.VENDOR_PATCHLEVEL -> "VENDOR_PATCHLEVEL"
            Tag.BOOT_PATCHLEVEL -> "BOOT_PATCHLEVEL"
            Tag.CREATION_DATETIME -> "CREATION_DATETIME"
            Tag.ROOT_OF_TRUST -> "ROOT_OF_TRUST"
            Tag.USER_ID -> "USER_ID"
            Tag.USAGE_COUNT_LIMIT -> "USAGE_COUNT_LIMIT"
            Tag.UNLOCKED_DEVICE_REQUIRED -> "UNLOCKED_DEVICE_REQUIRED"
            Tag.ACTIVE_DATETIME -> "ACTIVE_DATETIME"
            else -> "tag${tag and 0x0FFFFFFF}"
        }
}
