package org.matrix.TEESimulator.logging

import android.util.Base64
import android.util.Log
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONObject
import org.matrix.TEESimulator.BuildConfig
import org.matrix.TEESimulator.config.ConfigurationManager

/**
 * A centralized logging utility for the TEESimulator application. This object provides a consistent
 * logging tag and format for all application logs, making it easier to filter and debug in Logcat.
 *
 * Includes a rate limiter that caps logd syscalls during binder stress to prevent thread pool
 * contention. The first [RATE_LIMIT_BURST] messages per [RATE_LIMIT_WINDOW_MS] window are logged
 * normally; subsequent messages are suppressed and a summary is emitted when the window resets.
 */
object SystemLogger {
    @PublishedApi internal const val TAG = "TEESimulator"

    @PublishedApi internal val isDebugBuild = BuildConfig.DEBUG

    // Rate limiter: allow BURST messages per WINDOW, then suppress until window resets.
    private const val RATE_LIMIT_BURST = 15
    private const val RATE_LIMIT_WINDOW_MS = 1000L
    private val windowStart = AtomicLong(System.currentTimeMillis())
    private val windowCount = AtomicInteger(0)
    private val suppressedCount = AtomicInteger(0)

    /**
     * Returns true if this message should be emitted. Resets the window if expired and emits a
     * suppression summary for the previous window.
     */
    @PublishedApi
    internal fun acquireLogPermit(): Boolean {
        val now = System.currentTimeMillis()
        val start = windowStart.get()
        if (now - start > RATE_LIMIT_WINDOW_MS) {
            // Window expired: reset and emit suppression summary if needed.
            if (windowStart.compareAndSet(start, now)) {
                val suppressed = suppressedCount.getAndSet(0)
                windowCount.set(1) // this call counts as #1 in the new window
                if (suppressed > 0) {
                    Log.i(
                        TAG,
                        "[rate-limit] suppressed $suppressed log messages in previous window",
                    )
                }
                return true
            }
        }
        val count = windowCount.incrementAndGet()
        if (count <= RATE_LIMIT_BURST) return true
        suppressedCount.incrementAndGet()
        return false
    }

    /** Logs a debug message. Use this for fine-grained information that is useful for debugging. */
    fun debug(message: String) {
        if (!isDebugBuild) return
        if (!acquireLogPermit()) return
        Log.d(TAG, message)
    }

    /** Lazy debug: lambda only evaluates if message will be logged. */
    inline fun debug(message: () -> String) {
        if (!isDebugBuild) return
        if (!acquireLogPermit()) return
        Log.d(TAG, message())
    }

    /** Logs an informational message. Use this to report major application lifecycle events. */
    fun info(message: String) {
        if (!acquireLogPermit()) return
        Log.i(TAG, message)
    }

    /** Lazy info: lambda only evaluates if message will be logged. */
    inline fun info(message: () -> String) {
        if (!acquireLogPermit()) return
        Log.i(TAG, message())
    }

    /** Logs a warning message. Warnings are never rate-limited. */
    fun warning(message: String, throwable: Throwable? = null) {
        if (throwable != null) {
            Log.w(TAG, message, throwable)
        } else {
            Log.w(TAG, message)
        }
    }

    /** Logs an error message. Errors are never rate-limited. */
    fun error(message: String, throwable: Throwable? = null) {
        if (throwable != null) {
            Log.e(TAG, message, throwable)
        } else {
            Log.e(TAG, message)
        }
    }

    /**
     * Logs a verbose message. This level is for highly detailed logs that are generally not needed
     * unless tracking a very specific issue.
     */
    fun verbose(message: String) {
        if (!isDebugBuild) return
        if (!acquireLogPermit()) return
        Log.v(TAG, message)
    }

    /** Lazy verbose: lambda only evaluates if message will be logged. */
    inline fun verbose(message: () -> String) {
        if (!isDebugBuild) return
        if (!acquireLogPermit()) return
        Log.v(TAG, message())
    }

    inline fun trace(message: () -> String) {
        if (!isDebugBuild) return
        Log.w(TAG, message())
    }

    // --- UID-keyed diagnostic plane (debug builds only) -------------------------------------

    /**
     * True when [uid] should receive deep, per-UID diagnostic logging: a debug build AND the UID is
     * targeted in `target.txt`. This is the single scope gate for the diagnostic plane; it reuses
     * the existing activation set, so no new configuration surface is introduced.
     */
    fun isUidLogged(uid: Int): Boolean = isDebugBuild && !ConfigurationManager.shouldSkipUid(uid)

    /** Resolves a UID to its primary package name for log labelling, falling back to `uid:N`. */
    private fun label(uid: Int): String =
        ConfigurationManager.getPackagesForUid(uid).firstOrNull() ?: "uid:$uid"

    /**
     * Emits one structured diagnostic record for a targeted [uid]. The human form
     * `[<pkg> tx=<txId>] <event>: <detail>` goes to logcat; the file sink receives one NDJSON object
     * per line under that UID's own file. In-scope records bypass the global rate limiter: a
     * targeted app's traffic is already volume-bounded, and dropping a line mid-probe would corrupt
     * the very trace we are trying to read. No-op for untargeted UIDs and in release builds.
     */
    fun uidLog(uid: Int, txId: Long?, event: String, detail: String) {
        if (!isUidLogged(uid)) return
        val correlation = txId?.let { " tx=$it" } ?: ""
        Log.d(TAG, "[${label(uid)}$correlation] $event: $detail")
        runCatching { uidWriter(uid).append(jsonRecord(uid, txId, event, detail, null)) }
    }

    /** Lazy [uidLog]: [detail] is only built for targeted UIDs in debug builds. */
    inline fun uidLog(uid: Int, txId: Long?, event: String, detail: () -> String) {
        if (!isUidLogged(uid)) return
        uidLog(uid, txId, event, detail())
    }

    /**
     * [uidLog] plus the exact wire bytes that produced the event, base64 (NO_WRAP) in a `raw_b64`
     * field. This is the structured replacement for the per-call `.bin` parcel dumps: one NDJSON
     * line on the per-UID file instead of a fresh undecodable file per transaction, with the raw
     * parcel still recoverable for offline parsers.
     */
    fun uidLogRaw(uid: Int, txId: Long?, event: String, detail: String, raw: ByteArray) {
        if (!isUidLogged(uid)) return
        val correlation = txId?.let { " tx=$it" } ?: ""
        Log.d(TAG, "[${label(uid)}$correlation] $event: $detail (raw ${raw.size}B)")
        runCatching {
            val encoded = Base64.encodeToString(raw, Base64.NO_WRAP)
            uidWriter(uid).append(jsonRecord(uid, txId, event, detail, encoded))
        }
    }

    /**
     * External-storage root for every debug diagnostic. `/data/media/0/TEESimulator` is the
     * in-namespace backing path the keystore domain can reach; a normal file manager sees the same
     * files at `/sdcard/TEESimulator`. Release builds never write here and purge it on boot
     * (App.purgeDebugDiagnostics). The domain reaches it via a debug-only media_rw_data_file
     * sepolicy grant, and service.sh pre-creates the directory.
     */
    const val DIAGNOSTIC_DIR = "/data/media/0/TEESimulator"

    private val uidLogDir = File(DIAGNOSTIC_DIR)
    private const val UID_LOG_MAX_BYTES = 4L * 1024 * 1024
    private val uidWriters = ConcurrentHashMap<Int, UidLogFile>()

    private val recordClock =
        DateTimeFormatter.ofPattern("MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault())

    private fun jsonRecord(
        uid: Int,
        txId: Long?,
        event: String,
        detail: String,
        rawB64: String?,
    ): String =
        JSONObject()
            .apply {
                put("ts", recordClock.format(Instant.now()))
                put("uid", uid)
                put("pkg", label(uid))
                txId?.let { put("tx", it) }
                put("event", event)
                put("detail", detail)
                rawB64?.let { put("raw_b64", it) }
            }
            .toString()

    private fun uidWriter(uid: Int): UidLogFile =
        uidWriters.computeIfAbsent(uid) { key ->
            UidLogFile(key, uidLogDir).also { file ->
                val packages =
                    ConfigurationManager.getPackagesForUid(key).joinToString().ifEmpty { "<unresolved>" }
                runCatching {
                    file.append(jsonRecord(key, null, "session", "packages=[$packages]", null))
                }
            }
        }

    /**
     * Append-only NDJSON sink for a single UID at `<logDir>/teesim-uid-<uid>.ndjson`, rotated once
     * to `.ndjson.1` at [UID_LOG_MAX_BYTES]; one JSON object per line. Writes are synchronised
     * because the keystore binder pool is multi-threaded, and every operation is wrapped so a
     * logging fault can never propagate into the daemon. Created only on the debug-gated path.
     */
    private class UidLogFile(uid: Int, private val logDir: File) {
        private val primary = File(logDir, "teesim-uid-$uid.ndjson")
        private val rotated = File(logDir, "teesim-uid-$uid.ndjson.1")
        private var writer: BufferedWriter? = null
        private var size = 0L

        @Synchronized
        fun append(jsonLine: String) {
            runCatching {
                val out = writer ?: open()
                out.write(jsonLine)
                out.write("\n")
                out.flush()
                size += jsonLine.length + 1
                if (size >= UID_LOG_MAX_BYTES) rotate()
            }
        }

        private fun open(): BufferedWriter {
            logDir.mkdirs()
            val out = BufferedWriter(FileWriter(primary, /* append = */ true))
            writer = out
            size = primary.length()
            return out
        }

        private fun rotate() {
            runCatching {
                writer?.flush()
                writer?.close()
            }
            writer = null
            runCatching {
                if (rotated.exists()) rotated.delete()
                primary.renameTo(rotated)
            }
            size = 0L
        }
    }
}
