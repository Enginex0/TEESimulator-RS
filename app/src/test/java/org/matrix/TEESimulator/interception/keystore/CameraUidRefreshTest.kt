package org.matrix.TEESimulator.interception.keystore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CameraUidRefreshTest {
    @Test
    fun `package changes clear old UIDs before publishing the new set`() {
        val published = mutableListOf<Set<Int>>()
        val refresh = CameraUidRefresh({ setOf(10125, 1010123) }, { published.add(it); true }, {})
        assertTrue(refresh.update(invalidate = true))
        assertEquals(listOf(emptySet<Int>(), setOf(10125, 1010123)), published)
    }

    @Test
    fun `discovery failure clears stale UIDs and allows retry`() {
        val published = mutableListOf<Set<Int>>()
        var fail = true
        var reported = false
        val refresh =
            CameraUidRefresh(
                { if (fail) error("unavailable") else setOf(10125) },
                { published.add(it); true },
                { reported = true },
            )
        assertFalse(refresh.update(invalidate = false))
        assertTrue(reported)
        assertEquals(listOf(emptySet<Int>()), published)
        fail = false
        assertTrue(refresh.update(invalidate = false))
        assertEquals(setOf(10125), published.last())
    }

    @Test
    fun `failed invalidation does not publish an unverified update`() {
        var discovered = false
        val refresh = CameraUidRefresh({ discovered = true; setOf(10125) }, { false }, {})
        assertFalse(refresh.update(invalidate = true))
        assertFalse(discovered)
    }

    @Test
    fun `failed publication clears stale UIDs and is retried`() {
        val published = mutableListOf<Set<Int>>()
        var fail = true
        val refresh =
            CameraUidRefresh(
                { setOf(10125) },
                {
                    published.add(it)
                    if (fail && it.isNotEmpty()) false else true
                },
                {},
            )
        assertFalse(refresh.update(invalidate = false))
        assertEquals(listOf(setOf(10125), emptySet<Int>()), published)
        fail = false
        assertTrue(refresh.update(invalidate = false))
    }
}
