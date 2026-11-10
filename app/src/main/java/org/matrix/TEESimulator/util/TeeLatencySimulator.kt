package org.matrix.TEESimulator.util

import android.hardware.security.keymint.Algorithm
import java.security.SecureRandom
import java.util.concurrent.locks.LockSupport
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.max

object TeeLatencySimulator {

    private val rng = SecureRandom()

    private val sessionBiasMs: Double by lazy { rng.nextGaussian() * 5.0 }
    private val coldPenaltyMs: Double by lazy { abs(rng.nextGaussian() * 12.0) }

    @Volatile private var firstCall = true

    fun simulateGenerateKeyDelay(algorithm: Int, elapsedNanos: Long) {
        val elapsedMs = elapsedNanos / 1_000_000.0
        val targetMs = sampleTotalDelay(algorithm)
        val remainingMs = targetMs - elapsedMs

        if (remainingMs > 1.0) {
            LockSupport.parkNanos((remainingMs * 1_000_000).toLong())
        }
    }

    private fun sampleTotalDelay(algorithm: Int): Double {
        val base = sampleBaseCryptoDelay(algorithm)
        val transit = sampleExponential(2.5)
        val jitter = (rng.nextGaussian() * 2.5).coerceIn(-8.0, 12.0)

        var cold = 0.0
        if (firstCall) {
            firstCall = false
            cold = coldPenaltyMs
        }

        return max(20.0, base + transit + jitter + sessionBiasMs + cold)
    }

    private fun sampleBaseCryptoDelay(algorithm: Int): Double {
        val (mu, sigma) =
            when (algorithm) {
                Algorithm.EC -> ln(60.0) to 0.08
                Algorithm.RSA -> ln(70.0) to 0.08
                Algorithm.AES -> ln(35.0) to 0.10
                else -> ln(40.0) to 0.10
            }
        return sampleLogNormal(mu, sigma)
    }

    private fun sampleLogNormal(mu: Double, sigma: Double): Double {
        return exp(mu + sigma * rng.nextGaussian())
    }

    private fun sampleExponential(mean: Double): Double {
        var u = rng.nextDouble()
        while (u == 0.0) u = rng.nextDouble()
        return -mean * ln(u)
    }
}
