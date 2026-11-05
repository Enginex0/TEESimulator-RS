package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.PaddingMode
import javax.crypto.Cipher
import org.junit.Assert.assertEquals
import org.junit.Test

class JcaAlgorithmMapperTest {
    @Test
    fun `RSA ignores block mode and uses a valid JCA transformation`() {
        for (mode in listOf(BlockMode.CBC, BlockMode.CTR, BlockMode.GCM, BlockMode.ECB, null)) {
            val transformation =
                JcaAlgorithmMapper.mapCipherAlgorithm(
                    Algorithm.RSA,
                    mode,
                    PaddingMode.RSA_PKCS1_1_5_ENCRYPT,
                )
            assertEquals("RSA/ECB/PKCS1Padding", transformation)
            Cipher.getInstance(transformation)
        }
        assertEquals(
            "RSA/ECB/OAEPPadding",
            JcaAlgorithmMapper.mapCipherAlgorithm(Algorithm.RSA, BlockMode.CBC, PaddingMode.RSA_OAEP),
        )
    }

    @Test
    fun `AES keeps the requested block mode`() {
        assertEquals(
            "AES/CBC/NoPadding",
            JcaAlgorithmMapper.mapCipherAlgorithm(Algorithm.AES, BlockMode.CBC, PaddingMode.NONE),
        )
        assertEquals(
            "AES/GCM/NoPadding",
            JcaAlgorithmMapper.mapCipherAlgorithm(Algorithm.AES, BlockMode.GCM, PaddingMode.NONE),
        )
    }
}
