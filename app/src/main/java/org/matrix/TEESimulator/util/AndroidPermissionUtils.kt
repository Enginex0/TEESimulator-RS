package org.matrix.TEESimulator.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import org.matrix.TEESimulator.logging.SystemLogger

object AndroidPermissionUtils {

    @SuppressLint("PrivateApi", "DiscouragedPrivateApi")
    private fun getGlobalContext(): Context? {
        return try {
            // 1. Get the hidden ActivityThread class via reflection
            val activityThreadClass = Class.forName("android.app.ActivityThread")

            // 2. Invoke the static currentActivityThread() method
            val currentActivityThreadMethod =
                activityThreadClass.getDeclaredMethod("currentActivityThread")
            currentActivityThreadMethod.isAccessible = true
            val activityThread = currentActivityThreadMethod.invoke(null)

            if (activityThread == null) {
                SystemLogger.warning(
                    "Reflection: ActivityThread.currentActivityThread() returned null"
                )
                return null
            }

            // 3. Try to get the application context
            val getApplicationMethod = activityThreadClass.getDeclaredMethod("getApplication")
            getApplicationMethod.isAccessible = true
            val application = getApplicationMethod.invoke(activityThread) as? Context

            if (application != null) return application

            // 4. Fallback to getSystemContext() if application is null (often happens in
            // system_server)
            val getSystemContextMethod = activityThreadClass.getDeclaredMethod("getSystemContext")
            getSystemContextMethod.isAccessible = true
            getSystemContextMethod.invoke(activityThread) as? Context
        } catch (e: Exception) {
            SystemLogger.error("Reflection failed to get global context for permission check", e)
            null
        }
    }

    /** Core permission check. */
    fun hasPermission(uid: Int, permission: String): Boolean {
        val context =
            getGlobalContext()
                ?: run {
                    SystemLogger.warning(
                        "AndroidPermissionUtils: Context is null, failing permission check safely."
                    )
                    return false
                }

        val result = context.checkPermission(permission, -1, uid)
        return result == PackageManager.PERMISSION_GRANTED
    }

    fun hasDeviceAttestationPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.READ_PRIVILEGED_PHONE_STATE")
    }

    fun hasUniqueIdAttestationPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.REQUEST_UNIQUE_ID_ATTESTATION")
    }

    fun hasManageUsersPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.MANAGE_USERS")
    }

    fun hasDumpPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.DUMP")
    }
}
