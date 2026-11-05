package org.matrix.TEESimulator.interception.soter

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.SystemProperties
import java.io.File
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Keeps [SoterServiceInterceptor] mounted on the on-demand, restartable
 * `com.tencent.soter.soterserver` process.
 *
 * `AbstractKeystoreInterceptor` injects `keystore2` exactly once: it is always alive and
 * servicemanager-published, so the daemon gets its binder from `ServiceManager` and may
 * `exitProcess` on failure. soterserver inverts both — it is Intent-bound (NOT in
 * `ServiceManager`) and may die and respawn. This supervisor therefore *binds* the SOTER
 * service, which both triggers its on-demand start AND yields the `ISoterService` binder
 * (the target the native MITM registry keys on); injects `libTEESimulator.so` on every
 * (re)start; confirms the landing with the `0xdeadbeef` backdoor handshake; then registers
 * the forge. It re-binds — re-poking, re-injecting, re-registering — whenever the process
 * dies, never exiting.
 *
 * Boot safety (issue #48): the daemon itself launches in the `late_start` window, long before
 * `sys.boot_completed`. Binding an on-demand system app there — and ptrace-injecting it — can
 * destabilise ROMs that wire SOTER into vendor early-start services (reported: OnePlus 9 Pro /
 * OxygenOS 11 never finished booting on v307). The supervisor therefore waits for boot
 * completion before its first bind, disables itself outright when the package is absent or the
 * disable file exists, and never injects the same live process twice: every remote `entry`
 * call re-registers the LSPLT ioctl hook, so a second injection into one process would
 * double-hook `/dev/binder` and crash the target.
 *
 * The bind recipe (action = the interface descriptor, package, `BIND_AUTO_CREATE`) and the
 * rebind-on-death lifecycle mirror the SOTER SDK's own `SoterCoreTreble`, so the daemon
 * connects exactly as a real client would. Everything runs on a dedicated [HandlerThread]
 * so it never stalls keystore init or `Looper.loop()` in [org.matrix.TEESimulator.App].
 *
 * Observability (the checkpoint's mandatory gate): every lifecycle event — bind, connect,
 * inject ok/fail, handshake, respawn — is logged via [SystemLogger], debug-gated. It never
 * gates the forge.
 */
object SoterProcessSupervisor {

    /** soterserver hosts the package's own process (recon 2026-06-26: process == package). */
    private const val SOTER_PACKAGE = "com.tencent.soter.soterserver"

    private const val REBIND_DELAY_MS = 1000L
    private const val REBIND_MAX_MS = 30_000L

    /** Poll interval while waiting for the boot to finish before the first bind. */
    private const val BOOT_POLL_MS = 2000L

    /**
     * Presence of this file under the tricky_store config dir disables the SOTER forge entirely —
     * an escape hatch for devices where mounting it destabilises the vendor SOTER stack.
     */
    private const val DISABLE_FILE = "/data/adb/tricky_store/disable_soter_forge"

    private val started = AtomicBoolean(false)

    /** Re-bind backoff; doubles each failed (re)bind up to [REBIND_MAX_MS], resets on a clean mount. Handler-thread-confined. */
    private var rebindDelay = REBIND_DELAY_MS

    private data class ProcessIdentity(val pid: Int, val startTime: Long)

    // Keep attempted identities even after a disconnect: the same process may still be alive.
    private var injectedProcess: ProcessIdentity? = null

    private lateinit var context: Context
    private lateinit var handler: Handler

    /** Delivers bind callbacks onto the supervisor thread so nothing touches the main looper. */
    private val executor = Executor { command -> handler.post(command) }

    /**
     * Starts supervising on a dedicated thread and returns immediately. Idempotent. [context]
     * must be able to bind services (the daemon's system context); supplied by the App wiring.
     *
     * The first bind is deferred until `sys.boot_completed`: the daemon itself starts in the
     * `late_start` window, and pulling the on-demand soterserver process up — then ptrace
     * injecting it — while the system is still coming up can stall the boot on devices whose ROM
     * wires SOTER into early-start vendor services (observed: OnePlus 9 Pro, OxygenOS 11, where
     * v307 never reached boot_completed; issue #48). Devices without the package and users who
     * dropped the disable file skip the forge entirely instead of idling in a rebind storm.
     */
    fun start(context: Context) {
        if (!started.compareAndSet(false, true)) return
        this.context = context
        handler = Handler(HandlerThread("soter-supervisor").apply { start() }.looper)
        handler.post {
            if (File(DISABLE_FILE).exists()) {
                SystemLogger.info("SOTER forge disabled by $DISABLE_FILE")
                return@post
            }
            if (!waitForBootCompleted()) return@post
            if (!isSoterServerInstalled()) {
                SystemLogger.info("SOTER forge disabled: $SOTER_PACKAGE is not installed")
                return@post
            }
            bind()
        }
    }

    /** True when the soterserver package exists on this device. */
    private fun isSoterServerInstalled(): Boolean =
        runCatching {
                context.packageManager.getPackageInfo(SOTER_PACKAGE, 0)
                true
            }
            .getOrElse {
                if (it !is PackageManager.NameNotFoundException) {
                    SystemLogger.warning("SOTER package lookup failed; assuming absent", it)
                }
                false
            }

    /** Blocks the supervisor thread until the system reports boot completed; false on interrupt. */
    private fun waitForBootCompleted(): Boolean {
        while (SystemProperties.get("sys.boot_completed", "0") != "1") {
            try {
                Thread.sleep(BOOT_POLL_MS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                SystemLogger.warning("SOTER boot wait interrupted", e)
                started.set(false)
                return false
            }
        }
        return true
    }

    private val connection =
        object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                SystemLogger.debug("SOTER service connected; mounting forge")
                service?.let(::mount)
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                SystemLogger.debug("SOTER service disconnected (process died); rebinding")
                scheduleRetry()
            }

            override fun onBindingDied(name: ComponentName?) {
                SystemLogger.debug("SOTER binding died; rebinding")
                scheduleRetry()
            }

            override fun onNullBinding(name: ComponentName?) {
                SystemLogger.debug("SOTER onBind returned null; rebinding")
                scheduleRetry()
            }
        }

    private fun bind() {
        val intent = Intent(SoterServiceInterceptor.DESCRIPTOR).setPackage(SOTER_PACKAGE)
        val bound =
            runCatching {
                    context.bindService(intent, Context.BIND_AUTO_CREATE, executor, connection)
                }
                .getOrElse {
                    SystemLogger.debug { "SOTER bindService threw: $it" }
                    false
                }
        if (bound) {
            SystemLogger.debug("SOTER bind requested (on-demand poke)")
        } else {
            SystemLogger.debug("SOTER bindService returned false; retrying")
            scheduleRetry()
        }
    }

    private fun rebind() {
        runCatching { context.unbindService(connection) }
        bind()
    }

    /**
     * Re-attempts the bind after the current backoff, then widens it (capped at [REBIND_MAX_MS]).
     * Every path that fails to leave the forge mounted routes here, so a live-but-uninjected
     * binding is re-attempted instead of stranding the forge. A clean [mount] resets the backoff.
     */
    private fun scheduleRetry() {
        val delay = rebindDelay
        rebindDelay = (rebindDelay * 2).coerceAtMost(REBIND_MAX_MS)
        handler.postDelayed({ rebind() }, delay)
    }

    /** Confirms injection via the `0xdeadbeef` handshake, injecting first if absent, then registers. */
    private fun mount(soterBinder: IBinder) {
        var backdoor = BinderInterceptor.getBackdoor(soterBinder)
        if (backdoor == null) {
            val process = soterServerProcess()
            if (process == null) {
                SystemLogger.warning("Cannot resolve SOTER process identity; retrying")
                scheduleRetry()
                return
            }
            if (process == injectedProcess) {
                // This exact process was already injected and still has no backdoor: running
                // `entry` again would double-register the LSPLT ioctl hook and crash the target.
                // Drop the binding and wait out a respawn instead of re-injecting.
                SystemLogger.debug(
                    "SOTER pid ${process.pid} already injected but handshake failed; awaiting respawn"
                )
                scheduleRetry()
                return
            }
            SystemLogger.debug("SOTER backdoor absent; injecting libTEESimulator.so")
            injectedProcess = process
            if (!injectLibrary(process.pid)) {
                SystemLogger.debug("SOTER injection failed; scheduling re-bind")
                scheduleRetry()
                return
            }
            backdoor = BinderInterceptor.getBackdoor(soterBinder)
        }
        if (backdoor == null) {
            SystemLogger.debug("SOTER backdoor handshake failed after injection; scheduling re-bind")
            scheduleRetry()
            return
        }
        val registered =
            BinderInterceptor.register(
                backdoor,
                soterBinder,
                SoterServiceInterceptor,
                SoterServiceInterceptor.interceptedCodes,
            )
        if (!registered) {
            SystemLogger.debug("SOTER register failed; scheduling re-bind")
            scheduleRetry()
            return
        }
        rebindDelay = REBIND_DELAY_MS
        SystemLogger.debug("SOTER forge mounted; handshake ok")
    }

    /** Includes the process start time so a reused PID is not mistaken for an earlier injection. */
    private fun soterServerProcess(): ProcessIdentity? =
        runCatching {
                val process = Runtime.getRuntime().exec(arrayOf("pidof", SOTER_PACKAGE))
                val output = process.inputStream.bufferedReader().readText().trim()
                if (process.waitFor() != 0) return@runCatching null
                val pid = output.toIntOrNull()?.takeIf { it > 0 } ?: return@runCatching null
                val stat = File("/proc/$pid/stat").readText()
                val fields = stat.substringAfterLast(") ").split(" ")
                val startTime = fields.getOrNull(19)?.toLongOrNull() ?: return@runCatching null
                ProcessIdentity(pid, startTime)
            }
            .getOrElse {
                SystemLogger.debug { "SOTER pidof failed: $it" }
                null
            }

    private fun injectLibrary(pid: Int): Boolean =
        runCatching {
                Runtime.getRuntime()
                    .exec(arrayOf("./inject", pid.toString(), "libTEESimulator.so", "entry"))
                    .waitFor() == 0
            }
            .getOrElse {
                SystemLogger.debug { "SOTER inject exec failed: $it" }
                false
            }
}
