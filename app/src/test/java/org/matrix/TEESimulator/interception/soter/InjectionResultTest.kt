package org.matrix.TEESimulator.interception.soter

import org.junit.Assert.assertEquals
import org.junit.Test

class InjectionResultTest {
    @Test
    fun `only confirmed pre-entry failures are retryable`() {
        assertEquals(InjectionResult.SUCCESS, classifyInjectorExitCode(0))
        assertEquals(InjectionResult.PRE_ENTRY_FAILURE, classifyInjectorExitCode(2))
        assertEquals(InjectionResult.UNCERTAIN, classifyInjectorExitCode(1))
        assertEquals(InjectionResult.UNCERTAIN, classifyInjectorExitCode(137))
    }
}
