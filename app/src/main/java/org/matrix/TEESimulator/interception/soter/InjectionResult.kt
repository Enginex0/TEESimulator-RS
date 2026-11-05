package org.matrix.TEESimulator.interception.soter

internal enum class InjectionResult {
    SUCCESS,
    PRE_ENTRY_FAILURE,
    UNCERTAIN,
}

internal fun classifyInjectorExitCode(exitCode: Int): InjectionResult =
    when (exitCode) {
        0 -> InjectionResult.SUCCESS
        2 -> InjectionResult.PRE_ENTRY_FAILURE
        else -> InjectionResult.UNCERTAIN
    }
