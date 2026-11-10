package org.matrix.TEESimulator.interception.soter

import android.os.IBinder
import android.os.Parcel
import android.util.Base64
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Forges healthy `com.tencent.soter.soterserver.ISoterService` (Layer A: AIDL over
 * `/dev/binder`) replies from inside the injected soterserver app process, so the SOTER
 * capability probe (春秋 / DuckDetector `SoterCapabilityProbe`) reads `available = true`
 * / `damaged = false` on a bootloader-unlocked device whose SOTER TA can no longer use
 * its factory ATTK. Replaces the external SoterFixer loop + the Hail freeze.
 *
 * Unconditional by design: the forge decision never consults `ConfigurationManager` /
 * `target.txt` (Phase 10 spec §Decision, gate G). It is mounted by the SOTER process
 * supervisor (10.B/10.W) against the ISoterService binder, so `onPreTransact` only sees
 * transactions on that binder — matching the raw transaction code is therefore enough.
 *
 * Diagnostics follow the module's standard three-layer capture (debug-gated, per-UID
 * NDJSON via [SystemLogger]; see `logging/SystemLogger.kt`): a `tx` line for every
 * transaction ([logTransaction]), the raw inbound request parcel, and the raw forged
 * reply wire. Capture is scoped to targeted UIDs (`isUidLogged`) exactly like the
 * keystore lane — it does NOT make the forge conditional; the forge still fires for all.
 *
 * Transaction codes are HARDCODED 1..13 in AIDL declaration order, NOT resolved via
 * [org.matrix.TEESimulator.interception.keystore.InterceptorUtils.getTransactCode]: the
 * shipped soterserver build is R8/ProGuard obfuscated — there is no `ISoterService$Stub`
 * class and no `TRANSACTION_*` fields (recon 2026-06-26, `a$a.smali` packed-switch). The
 * codes are fixed by Tencent's `ISoterService.aidl` and are obfuscation-independent.
 *
 * Scope boundary (10.A vs 10.M): the seven primitive-returning methods are fully forged
 * here. The six parcelable-returning methods emit the correct AIDL envelope + the
 * recon-verified `writeToParcel` field order; 10.M fills the payloads with
 * detector-satisfying values — a framed SOTER pubkey envelope the SDK's
 * `retrieveJsonFromExportedData` parses to a non-null `SoterPubKeyModel`, a non-zero sign
 * session, and a 256-byte signature.
 */
object SoterServiceInterceptor : BinderInterceptor() {

    /** The surviving, obfuscation-stable interface identifier (used by the 10.B/10.W mount). */
    const val DESCRIPTOR = "com.tencent.soter.soterserver.ISoterService"

    // AIDL transaction codes = FIRST_CALL_TRANSACTION (1) + declaration index, verified
    // against the obfuscated `a$a.smali` packed-switch (recon 2026-06-26). NOTE the 5/6
    // order: removeAuthKey precedes getAuthKey in the real .aidl (the spec prose had it
    // reversed). Comments record each method's return shape.
    private const val TX_GENERATE_APP_SECURE_KEY = 1 // int
    private const val TX_GET_APP_SECURE_KEY = 2 // SoterExportResult
    private const val TX_HAS_ASK_ALREADY = 3 // boolean
    private const val TX_GENERATE_AUTH_KEY = 4 // int
    private const val TX_REMOVE_AUTH_KEY = 5 // int   (NOT getAuthKey)
    private const val TX_GET_AUTH_KEY = 6 // SoterExportResult   (NOT removeAuthKey)
    private const val TX_REMOVE_ALL_AUTH_KEY = 7 // int
    private const val TX_HAS_AUTH_KEY = 8 // boolean
    private const val TX_INIT_SIGH = 9 // SoterSessionResult   (sic: Tencent's spelling)
    private const val TX_FINISH_SIGN = 10 // SoterSignResult
    private const val TX_GET_DEVICE_ID = 11 // SoterDeviceResult
    private const val TX_GET_VERSION = 12 // int   (real service returns 1)
    private const val TX_GET_EXTRA_PARAM = 13 // SoterExtraParam

    /** SOTER success result code (`SoterCoreResult` ERR_OK). */
    private const val SOTER_OK = 0

    /** finishSign signature length the probe expects. */
    private const val SIGNATURE_LEN = 256

    /** `cpu_id` placeholder in the export envelope; the local probe never reads its value
     *  (the backend pins the real per-`cpu_id` ATTK, which the forge cannot satisfy). */
    private const val CPU_ID = "0000000000000000"

    /** Code -> Tencent method name, for the `tx` diagnostic line. Names from the recon decompile. */
    private val methodNames =
        mapOf(
            TX_GENERATE_APP_SECURE_KEY to "generateAppSecureKey",
            TX_GET_APP_SECURE_KEY to "getAppSecureKey",
            TX_HAS_ASK_ALREADY to "hasAskAlready",
            TX_GENERATE_AUTH_KEY to "generateAuthKey",
            TX_REMOVE_AUTH_KEY to "removeAuthKey",
            TX_GET_AUTH_KEY to "getAuthKey",
            TX_REMOVE_ALL_AUTH_KEY to "removeAllAuthKey",
            TX_HAS_AUTH_KEY to "hasAuthKey",
            TX_INIT_SIGH to "initSigh",
            TX_FINISH_SIGN to "finishSign",
            TX_GET_DEVICE_ID to "getDeviceId",
            TX_GET_VERSION to "getVersion",
            TX_GET_EXTRA_PARAM to "getExtraParam",
        )

    /** The codes this interceptor forges; consumed by the supervisor's registration (10.B/10.W). */
    val interceptedCodes: IntArray = methodNames.keys.toIntArray()

    /**
     * Payload of [SoterExportResult.exportData] for getAppSecureKey (txn 2) and getAuthKey
     * (txn 6). The detector's capability probe gates `damaged=false` on
     * `SoterCore.getApp/AuthKeyModel() != null`, and the SDK's `retrieveJsonFromExportedData`
     * (`SoterCoreBase`) returns a non-null `SoterPubKeyModel` only when this exact framing
     * parses: `[4-byte LITTLE-ENDIAN json length][UTF-8 json][signature bytes]`. A
     * non-empty-but-unframed blob throws inside the SDK and is read as `damaged` silently.
     * The JSON parser swallows every exception, so only the framing is load-bearing; the
     * `pub_key` is a genuine RSA-2048 SubjectPublicKeyInfo so a probe that base64/X.509-parses
     * the field locally still succeeds. Lazily built — keygen runs once, off the mount path.
     */
    private val exportBlob: ByteArray by lazy { buildExportBlob() }

    /** getDeviceId (txn 11) payload — well-formed, non-empty; the probe never parses it. */
    private val deviceIdBlob = "TEESIM-SOTER-0001".toByteArray(Charsets.UTF_8)

    /** finishSign (txn 10) signature payload — [SIGNATURE_LEN] bytes. */
    private val signatureBlob = ByteArray(SIGNATURE_LEN)

    private fun buildExportBlob(): ByteArray {
        val pubKey =
            runCatching {
                    val generator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
                    Base64.encodeToString(generator.generateKeyPair().public.encoded, Base64.NO_WRAP)
                }
                .getOrDefault("")
        val json =
            """{"pub_key":"$pubKey","counter":0,"cpu_id":"$CPU_ID","uid":0}"""
                .toByteArray(Charsets.UTF_8)
        val lengthPrefix = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(json.size).array()
        return lengthPrefix + json + signatureBlob
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
        val method = methodNames[code]
        if (method == null) {
            // Not an ISoterService method we forge — record it as observed, then pass through.
            logTransaction(txId, "code=$code", callingUid, callingPid, skipPost = true)
            return TransactionResult.ContinueAndSkipPost
        }
        logTransaction(txId, method, callingUid, callingPid)
        captureRequest(callingUid, txId, method, data)

        return when (code) {
            // Primitive returns — fully forged here.
            TX_GENERATE_APP_SECURE_KEY,
            TX_GENERATE_AUTH_KEY,
            TX_REMOVE_AUTH_KEY,
            TX_REMOVE_ALL_AUTH_KEY -> forgedReply(callingUid, txId, method) { writeInt(SOTER_OK) }
            TX_GET_VERSION -> forgedReply(callingUid, txId, method) { writeInt(1) }
            TX_HAS_ASK_ALREADY,
            TX_HAS_AUTH_KEY -> forgedReply(callingUid, txId, method) { writeInt(1) } // boolean true

            // Parcelable returns — correct envelope + recon field order, payloads filled (10.M).
            TX_GET_APP_SECURE_KEY,
            TX_GET_AUTH_KEY ->
                forgedReply(callingUid, txId, method) {
                    writeInt(1) // non-null marker
                    writeInt(SOTER_OK) // resultCode
                    writeByteArray(exportBlob) // exportData — framed SOTER pubkey envelope
                    writeInt(exportBlob.size) // exportDataLength
                }
            TX_INIT_SIGH ->
                forgedReply(callingUid, txId, method) {
                    writeInt(1)
                    writeLong(1L) // session — any non-zero satisfies the probe
                    writeInt(SOTER_OK) // resultCode — probe requires == 0 (SoterCapabilityProbe.kt:107)
                }
            TX_FINISH_SIGN ->
                forgedReply(callingUid, txId, method) {
                    writeInt(1)
                    writeInt(SOTER_OK) // resultCode — finishSign throws on != 0
                    writeByteArray(signatureBlob) // exportData = signature
                    writeInt(signatureBlob.size) // exportDataLength
                }
            TX_GET_DEVICE_ID ->
                forgedReply(callingUid, txId, method) {
                    writeInt(1)
                    writeInt(SOTER_OK) // resultCode
                    writeByteArray(deviceIdBlob) // exportData = device id
                    writeInt(deviceIdBlob.size) // exportDataLength
                }
            TX_GET_EXTRA_PARAM ->
                forgedReply(callingUid, txId, method) {
                    writeInt(1)
                    writeValue("optical") // SoterExtraParam.result = fingerprint sensor type
                }

            // Unreachable: method != null means code is one of the 13 above.
            else -> TransactionResult.ContinueAndSkipPost
        }
    }

    /** Snapshots the inbound request parcel to the per-UID NDJSON plane (debug + targeted only). */
    private fun captureRequest(uid: Int, txId: Long, method: String, data: Parcel) {
        if (!SystemLogger.isUidLogged(uid)) return
        runCatching { data.marshall() }
            .onSuccess { raw ->
                SystemLogger.uidLogRaw(uid, txId, "$method-request", "len=${raw.size}", raw)
            }
    }

    /**
     * Builds an AIDL reply (`writeNoException()` then [body]) and snapshots its wire bytes to the
     * per-UID NDJSON plane before handing it to the native hook. Parcelable bodies write their own
     * `writeInt(1)` non-null marker; the native hook recycles the parcel after use.
     */
    private fun forgedReply(
        uid: Int,
        txId: Long,
        method: String,
        body: Parcel.() -> Unit,
    ): TransactionResult.OverrideReply {
        val reply = Parcel.obtain()
        reply.writeNoException()
        reply.body()
        if (SystemLogger.isUidLogged(uid)) {
            runCatching { reply.marshall() }
                .onSuccess { raw ->
                    SystemLogger.uidLogRaw(uid, txId, "$method-reply", "len=${raw.size}", raw)
                }
        }
        return TransactionResult.OverrideReply(reply)
    }
}
