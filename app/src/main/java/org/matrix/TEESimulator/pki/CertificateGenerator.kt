package org.matrix.TEESimulator.pki

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyPurpose
import android.os.Build
import android.util.Pair
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.matrix.TEESimulator.attestation.AttestationBuilder
import org.matrix.TEESimulator.attestation.AttestationConstants
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Responsible for generating new cryptographic key pairs and X.509 certificate chains.
 *
 * This object simulates the behavior of the Android KeyMint/Keymaster HAL by creating certificates
 * that include a fully-featured, simulated attestation extension.
 */
object CertificateGenerator {

    private const val UNDEFINED_NOT_AFTER = 253402300799000L

    /**
     * Generates a software-based cryptographic key pair.
     *
     * @param params The parameters specifying the key's algorithm, size, and other properties.
     * @return A new [KeyPair], or `null` on failure.
     */
    fun generateSoftwareKeyPair(params: KeyMintAttestation): KeyPair? {
        return runCatching {
                val (algorithm, spec) =
                    when (params.algorithm) {
                        Algorithm.EC -> "EC" to ECGenParameterSpec(params.ecCurveName)
                        Algorithm.RSA ->
                            "RSA" to
                                RSAKeyGenParameterSpec(
                                    params.keySize,
                                    params.rsaPublicExponent ?: RSAKeyGenParameterSpec.F4,
                                )
                        else ->
                            throw IllegalArgumentException(
                                "Unsupported algorithm: ${params.algorithm}"
                            )
                    }
                SystemLogger.debug("Generating $algorithm key pair with size ${params.keySize}")
                KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME)
                    .apply { initialize(spec) }
                    .generateKeyPair()
            }
            .onFailure { SystemLogger.error("Failed to generate software key pair.", it) }
            .getOrNull()
    }

    /**
     * Generates a certificate chain for a given key pair. This is the primary function for creating
     * attested certificates.
     *
     * @param uid The UID of the application requesting the key.
     * @param subjectKeyPair The key pair for which the certificate will be generated.
     * @param attestKeyAlias Optional alias of a key to use for attestation signing.
     * @param params The parameters for the new key and its attestation.
     * @param securityLevel The security level to embed in the attestation.
     * @return A [List] of [Certificate] forming the new chain, or `null` on failure.
     */
    fun generateCertificateChain(
        uid: Int,
        subjectKeyPair: KeyPair,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): List<Certificate>? {
        val challenge = params.attestationChallenge
        if (challenge != null && challenge.size > AttestationConstants.CHALLENGE_LENGTH_LIMIT)
            throw IllegalArgumentException(
                "Attestation challenge exceeds length limit (${challenge.size} > ${AttestationConstants.CHALLENGE_LENGTH_LIMIT})"
            )

        return try {
            // AOSP ta/src/keys.rs:451-478: no challenge + no attestKey = self-signed, depth 1
            if (challenge == null && attestKeyAlias == null) {
                SystemLogger.trace {
                    "[certgen] no-challenge key: self-signed, depth=1, purposes=${params.purpose}"
                }
                return listOf(buildSelfSignedCertificate(subjectKeyPair, params))
            }

            val keybox = getKeyboxForAlgorithm(uid, params.algorithm)

            val wantsAttestKey =
                attestKeyAlias != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
            val attestKeyInfo =
                if (wantsAttestKey) getAttestationKeyInfo(uid, attestKeyAlias) else null

            // When the caller designates an attest key, the leaf MUST be signed by it and returned
            // alone (the caller appends the attest key's own chain). Re-rooting under the keybox
            // here instead yields a self-rooted leaf that, concatenated with the attest key chain,
            // double-roots and fails verification (WRONG_PUBLIC_KEY_TYPE). Refuse rather than emit
            // a
            // broken chain.
            if (wantsAttestKey && attestKeyInfo == null) {
                SystemLogger.error(
                    "Designated attest key '$attestKeyAlias' not found for uid $uid; refusing to " +
                        "emit a keybox-rooted leaf that would break the caller's chain."
                )
                return null
            }

            val (signingKey, issuer) =
                attestKeyInfo?.let { it.first to it.second }
                    ?: (keybox.keyPair to getIssuerFromKeybox(keybox))

            val leafCert =
                buildCertificate(subjectKeyPair, signingKey, issuer, params, uid, securityLevel)

            if (attestKeyInfo != null) {
                listOf(leafCert)
            } else {
                listOf(leafCert) + keybox.certificates
            }
        } catch (e: android.os.ServiceSpecificException) {
            throw e
        } catch (e: Exception) {
            SystemLogger.error("Failed to generate certificate chain.", e)
            null
        }
    }

    /**
     * A convenience function that combines key pair generation and certificate chain generation.
     * Primarily used by the modern Keystore2 interceptor where generation is a single step.
     */
    fun generateAttestedKeyPair(
        uid: Int,
        alias: String,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): Pair<KeyPair, List<Certificate>>? {
        return try {
            SystemLogger.info("Generating new attested key pair for alias: '$alias' (UID: $uid)")
            val newKeyPair =
                generateSoftwareKeyPair(params)
                    ?: throw Exception("Failed to generate underlying software key pair.")

            val chain =
                generateCertificateChain(uid, newKeyPair, attestKeyAlias, params, securityLevel)
                    ?: throw Exception("Failed to generate certificate chain for new key pair.")

            SystemLogger.info("Successfully generated new certificate chain for alias: '$alias'.")
            Pair(newKeyPair, chain)
        } catch (e: android.os.ServiceSpecificException) {
            throw e
        } catch (e: Exception) {
            SystemLogger.error("Failed to generate attested key pair for alias '$alias'.", e)
            null
        }
    }

    fun getIssuerFromKeybox(keybox: KeyBox) =
        X509CertificateHolder(keybox.certificates[0].encoded).subject

    private fun getKeyboxForAlgorithm(uid: Int, algorithm: Int): KeyBox {
        val keyboxFile = ConfigurationManager.getKeyboxFileForUid(uid)
        val algorithmName =
            when (algorithm) {
                Algorithm.EC -> "EC"
                Algorithm.RSA -> "RSA"
                else -> throw IllegalArgumentException("Unsupported algorithm ID: $algorithm")
            }
        // Prefer the algorithm-matching keybox, but fall back to any usable key (EC preferred) when
        // none exists. An EC attestation key validly ECDSA-signs a leaf carrying an RSA subject key,
        // so an EC-only keybox can still root an RSA forge. Without this fallback an RSA ATTEST_KEY
        // request on an EC-only keybox throws -75 and the caller's chain never roots ("unknown
        // certificate"). Mirrors the patch path's fail-safe
        // (AttestationPatcher.getKeyboxForUidAndAlgorithm) and the RSA-leaf-under-EC-keybox handling
        // in commit e6d5e4d.
        val matched = KeyBoxManager.getAttestationKey(keyboxFile, algorithmName)
        val keybox =
            matched
                ?: KeyBoxManager.getAnyAttestationKey(keyboxFile)
                ?: throw android.os.ServiceSpecificException(
                    -75, // ATTESTATION_KEYS_NOT_PROVISIONED
                    "No usable attestation key in $keyboxFile",
                )
        // Surface which keybox actually signs the forge, so an EC-only-keybox fallback (an RSA leaf
        // rooted under the EC key) is visible on the per-UID plane instead of silent.
        SystemLogger.uidLog(uid, null, "keybox-pick") {
            "req=$algorithmName ${if (matched != null) "matched" else "fellback-to-any"} " +
                "signer=${getIssuerFromKeybox(keybox)}"
        }
        return keybox
    }

    /** Retrieves the key pair and issuer name for a given attestation key alias. */
    private fun getAttestationKeyInfo(uid: Int, attestKeyAlias: String): Pair<KeyPair, X500Name>? {
        SystemLogger.debug("Looking for attestation key: uid=$uid alias=$attestKeyAlias")
        val keyId = KeyIdentifier(uid, attestKeyAlias)
        // Access the public map of generated keys
        val keyInfo = KeyMintSecurityLevelInterceptor.generatedKeys[keyId]
        return if (keyInfo != null) {
            val certChain = CertificateHelper.getCertificateChain(keyInfo.response)
            if (!certChain.isNullOrEmpty()) {
                val issuer = X509CertificateHolder(certChain[0].encoded).subject
                // The leaf is signed by keyInfo.keyPair, but the caller verifies it against the
                // public key of the chain getCertChain(attestKeyAlias) serves. A two-rooted EC chain
                // (DATA_TOO_LARGE_FOR_MODULUS) is exactly those two disagreeing on algorithm; log
                // both at the signing instant so an EC attest-key run pins the mismatched edge.
                SystemLogger.uidLog(uid, null, "attest-sign") {
                    "alias=$attestKeyAlias signerKey=${keyInfo.keyPair?.public?.algorithm} " +
                        "servedLeafKey=${certChain[0].publicKey.algorithm} " +
                        "depth=${certChain.size} issuer=$issuer"
                }
                Pair(keyInfo.keyPair, issuer)
            } else {
                null
            }
        } else {
            SystemLogger.warning(
                "Attestation key '$attestKeyAlias' not found in generated key cache."
            )
            null
        }
    }

    /** Maps KeyPurpose values to X.509 KeyUsage bits per KeyCreationResult.aidl spec */
    private fun buildKeyUsageFromPurposes(purposes: List<Int>): Int {
        var bits = 0
        for (purpose in purposes) {
            bits =
                bits or
                    when (purpose) {
                        KeyPurpose.SIGN -> KeyUsage.digitalSignature
                        KeyPurpose.DECRYPT -> KeyUsage.dataEncipherment
                        KeyPurpose.WRAP_KEY -> KeyUsage.keyEncipherment
                        KeyPurpose.AGREE_KEY -> KeyUsage.keyAgreement
                        KeyPurpose.ATTEST_KEY -> KeyUsage.keyCertSign
                        else -> 0
                    }
        }
        return bits
    }

    /** Constructs a new X.509 certificate with a simulated attestation extension. */
    private fun buildCertificate(
        subjectKeyPair: KeyPair,
        signingKeyPair: KeyPair,
        issuer: X500Name,
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): Certificate {
        val subject = params.certificateSubject ?: X500Name("CN=Android Keystore Key")
        val notBefore = params.certificateNotBefore ?: Date(0)
        val notAfter = params.certificateNotAfter ?: Date(UNDEFINED_NOT_AFTER)

        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                params.certificateSerial ?: BigInteger.ONE,
                notBefore,
                notAfter,
                subject,
                subjectKeyPair.public,
            )

        // Add KeyUsage extension only if purposes map to valid bits
        val keyUsageBits = buildKeyUsageFromPurposes(params.purpose)
        if (keyUsageBits != 0) {
            builder.addExtension(Extension.keyUsage, true, KeyUsage(keyUsageBits))
        }
        if (params.attestationChallenge != null) {
            builder.addExtension(
                AttestationBuilder.buildAttestationExtension(params, uid, securityLevel)
            )
        }

        val signerAlgorithm =
            when (signingKeyPair.private.algorithm) {
                "EC",
                "ECDSA" -> "SHA256withECDSA"
                "RSA" -> "SHA256withRSA"
                else ->
                    throw IllegalArgumentException(
                        "Unsupported signing key: ${signingKeyPair.private.algorithm}"
                    )
            }
        val contentSigner =
            JcaContentSignerBuilder(signerAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signingKeyPair.private)

        return JcaX509CertificateConverter().getCertificate(builder.build(contentSigner))
    }

    // AOSP ta/src/keys.rs:452-478, ta/src/cert.rs:111-114
    private fun buildSelfSignedCertificate(
        keyPair: KeyPair,
        params: KeyMintAttestation,
    ): Certificate {
        val subject = params.certificateSubject ?: X500Name("CN=Android Keystore Key")
        val notBefore = params.certificateNotBefore ?: Date(0)
        val notAfter = params.certificateNotAfter ?: Date(UNDEFINED_NOT_AFTER)

        val builder =
            JcaX509v3CertificateBuilder(
                subject,
                params.certificateSerial ?: BigInteger.ONE,
                notBefore,
                notAfter,
                subject,
                keyPair.public,
            )

        val keyUsageBits = buildKeyUsageFromPurposes(params.purpose)
        if (keyUsageBits != 0) {
            builder.addExtension(Extension.keyUsage, true, KeyUsage(keyUsageBits))
        }

        val signerAlgorithm =
            when (keyPair.private.algorithm) {
                "EC",
                "ECDSA" -> "SHA256withECDSA"
                "RSA" -> "SHA256withRSA"
                else ->
                    throw IllegalArgumentException("Unsupported key: ${keyPair.private.algorithm}")
            }
        val contentSigner =
            JcaContentSignerBuilder(signerAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.private)

        return JcaX509CertificateConverter().getCertificate(builder.build(contentSigner))
    }
}
