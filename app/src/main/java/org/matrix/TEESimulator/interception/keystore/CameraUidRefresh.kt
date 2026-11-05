package org.matrix.TEESimulator.interception.keystore

internal class CameraUidRefresh(
    private val discover: () -> Set<Int>,
    private val publish: (Set<Int>) -> Boolean,
    private val reportFailure: (Exception) -> Unit,
) {
    fun update(invalidate: Boolean): Boolean {
        return try {
            if (invalidate && !publish(emptySet())) return false
            if (!publish(discover())) {
                publish(emptySet())
                return false
            }
            true
        } catch (e: Exception) {
            reportFailure(e)
            publish(emptySet())
            false
        }
    }
}
