package org.matrix.TEESimulator.pki

import java.security.KeyPair
import java.security.cert.Certificate

/**
 * A data class representing a complete cryptographic identity used for signing attestations.
 *
 * A KeyBox is the fundamental building block for creating new, simulated certificate chains. It
 * encapsulates a single private key and the full public certificate chain needed to establish its
 * authenticity.
 *
 * @property keyPair The asymmetric cryptographic key pair. The private key from this pair is used
 *   to sign new leaf certificates during the attestation patching or generation process. The public
 *   key corresponds to the subject of the first certificate in the `certificates` list.
 * @property certificates The public certificate chain corresponding to the `keyPair`. This list is
 *   ordered from the intermediate certificate down to the root. `certificates[0]` is the issuer
 *   certificate for any new leaf signed by this KeyBox's private key.
 */
data class KeyBox(val keyPair: KeyPair, val certificates: List<Certificate>)
