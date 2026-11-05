package org.matrix.TEESimulator.interception.keystore

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.UserHandle
import java.util.concurrent.CountDownLatch
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

internal class CameraUidMonitor(private val context: Context, private val backdoor: IBinder) {
    private val handler = Handler(HandlerThread("camera-uid-monitor").apply { start() }.looper)
    private var packageReceiverRegistered = false
    private var userReceiverRegistered = false
    private val refreshTask = Runnable { refresh() }
    private val uidRefresh =
        CameraUidRefresh(
            discover = ::discoverCameraUids,
            publish = { uids ->
                BinderInterceptor.setBypassUids(backdoor, uids).also {
                    if (it) SystemLogger.info("Configured ${uids.size} camera bypass UIDs")
                }
            },
            reportFailure = {
                SystemLogger.error("Failed to discover camera UIDs; clearing stale bypasses", it)
            },
        )
    private val receiver =
        object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                handler.removeCallbacks(refreshTask)
                refresh(invalidate = true)
            }
        }

    fun start() {
        val initialized = CountDownLatch(1)
        check(
            handler.post {
                try {
                    refresh()
                } finally {
                    initialized.countDown()
                }
            }
        ) { "Failed to start camera UID monitor" }
        try {
            initialized.await()
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IllegalStateException("Interrupted while initializing camera UID monitor", e)
        }
    }

    private fun refresh(invalidate: Boolean = false) {
        val registered = registerReceivers()
        val updated = uidRefresh.update(invalidate)
        handler.removeCallbacks(refreshTask)
        handler.postDelayed(refreshTask, if (registered && updated) REFRESH_MS else RETRY_MS)
    }

    private fun registerReceivers(): Boolean {
        try {
            val allUsers = UserHandle::class.java.getField("ALL").get(null) as UserHandle
            val register =
                Context::class.java.getMethod(
                    "registerReceiverAsUser",
                    BroadcastReceiver::class.java,
                    UserHandle::class.java,
                    IntentFilter::class.java,
                    String::class.java,
                    Handler::class.java,
                )
            if (!packageReceiverRegistered) {
                val filter =
                    IntentFilter().apply {
                        addAction(Intent.ACTION_PACKAGE_ADDED)
                        addAction(Intent.ACTION_PACKAGE_REMOVED)
                        addAction(Intent.ACTION_PACKAGE_REPLACED)
                        addAction(Intent.ACTION_PACKAGE_CHANGED)
                        addDataScheme("package")
                    }
                register.invoke(context, receiver, allUsers, filter, null, handler)
                packageReceiverRegistered = true
            }
            if (!userReceiverRegistered) {
                val filter =
                    IntentFilter().apply {
                        addAction("android.intent.action.USER_ADDED")
                        addAction("android.intent.action.USER_REMOVED")
                        addAction("android.intent.action.USER_STARTED")
                        addAction("android.intent.action.USER_UNLOCKED")
                        addAction("android.intent.action.USER_STOPPED")
                        addAction("android.intent.action.MANAGED_PROFILE_AVAILABLE")
                        addAction("android.intent.action.MANAGED_PROFILE_UNAVAILABLE")
                    }
                register.invoke(context, receiver, allUsers, filter, null, handler)
                userReceiverRegistered = true
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to register camera UID change receivers; retrying", e)
        }
        return packageReceiverRegistered && userReceiverRegistered
    }

    private fun discoverCameraUids(): Set<Int> {
        val users =
            context.getSystemService(Context.USER_SERVICE) ?: error("UserManager unavailable")
        val userInfos =
            users.javaClass.getMethod("getUsers").invoke(users) as? List<*>
                ?: error("Unable to enumerate users")
        check(userInfos.isNotEmpty()) { "UserManager returned no users" }
        val pm = ConfigurationManager.getPackageManager() ?: error("PackageManager unavailable")
        return userInfos.flatMap { user ->
                requireNotNull(user) { "Null user returned by UserManager" }
                val userId = user.javaClass.getField("id").getInt(user)
                val packages =
                    if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(0L, userId)
                    else pm.getInstalledPackages(0, userId)
                requireNotNull(packages) { "Package enumeration failed for user $userId" }
                    .list
                    .filter { it.packageName.contains("camera", ignoreCase = true) }
                    .map {
                        requireNotNull(it.applicationInfo) {
                                "Camera app has no UID: ${it.packageName}"
                            }
                            .uid
                    }
            }
            .toSet()
    }

    private companion object {
        const val RETRY_MS = 5_000L
        const val REFRESH_MS = 60_000L
    }
}
