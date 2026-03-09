package org.matrix.TEESimulator.pki

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import org.matrix.TEESimulator.logging.SystemLogger

data class CertGenConfig(
    val algorithm: Int,
    val keySize: Int,
    val ecCurve: Int,
    val rsaPublicExponent: Long,
    val attestationChallenge: ByteArray?,
    val purposes: IntArray,
    val digests: IntArray,
    val certSerial: ByteArray?,
    val certSubject: ByteArray?,
    val certNotBefore: Long,
    val certNotAfter: Long,
    val keyboxPrivateKey: ByteArray,
    val keyboxCertChain: ByteArray,
    val securityLevel: Int,
    val attestVersion: Int,
    val keymasterVersion: Int,
    val osVersion: Int,
    val osPatchLevel: Int,
    val vendorPatchLevel: Int,
    val bootPatchLevel: Int,
    val bootKey: ByteArray,
    val bootHash: ByteArray,
    val creationDatetime: Long,
    val attestationApplicationId: ByteArray,
    val moduleHash: ByteArray?,
    val idBrand: ByteArray?,
    val idDevice: ByteArray?,
    val idProduct: ByteArray?,
    val idSerial: ByteArray?,
    val idImei: ByteArray?,
    val idMeid: ByteArray?,
    val idManufacturer: ByteArray?,
    val idModel: ByteArray?,
    val idSecondImei: ByteArray?,
)

object NativeCertGen {

    @Volatile
    var isAvailable: Boolean = false
        private set

    fun initialize(libraryPath: String) {
        try {
            System.load(libraryPath)
            isAvailable = true
            SystemLogger.info("NativeCertGen: loaded libcertgen.so successfully")
        } catch (e: UnsatisfiedLinkError) {
            SystemLogger.error("NativeCertGen: failed to load libcertgen.so, falling back to BouncyCastle", e)
        }
    }

    external fun generateAttestedKeyPair(config: CertGenConfig): ByteArray?

    external fun generateSoftwareKeyPair(
        algorithm: Int,
        keySize: Int,
        ecCurve: Int,
        rsaPublicExponent: Long,
    ): ByteArray?

    external fun initLogging(verbose: Boolean)

    external fun dumpLogs(): String

    fun parseNativeResult(bytes: ByteArray): Pair<KeyPair, List<Certificate>> {
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)

        val pkLen = buf.getInt()
        val pkBytes = ByteArray(pkLen)
        buf.get(pkBytes)

        val numCerts = buf.getInt()
        val certs = mutableListOf<Certificate>()
        val certFactory = CertificateFactory.getInstance("X.509")
        repeat(numCerts) {
            val certLen = buf.getInt()
            val certBytes = ByteArray(certLen)
            buf.get(certBytes)
            certs.add(certFactory.generateCertificate(ByteArrayInputStream(certBytes)))
        }

        val algorithmName = when (certs[0].publicKey.algorithm) {
            "EC" -> "EC"
            "RSA" -> "RSA"
            else -> certs[0].publicKey.algorithm
        }
        val keyFactory = KeyFactory.getInstance(algorithmName)
        val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(pkBytes))
        val publicKey = certs[0].publicKey
        return Pair(KeyPair(publicKey, privateKey), certs)
    }
}
