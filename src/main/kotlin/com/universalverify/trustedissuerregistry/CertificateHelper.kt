@file:JvmName("Certificates")

package com.universalverify.trustedissuerregistry

import com.universalverify.trustedissuerregistry.internal.*
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import java.security.cert.X509Certificate
import java.util.Base64

/** Parses a PEM certificate without evaluating its signature, dates, or trust. */
public fun parsePemCertificate(pemString: String): X509Certificate =
    certificateOperation {
        JcaX509CertificateConverter().setProvider(cryptoProvider).getCertificate(parseCertificate(pemString))
    }

/** Encodes the original certificate DER as PEM with 64-character Base64 lines. */
public fun certificateToPem(certificate: X509Certificate): String = certificateOperation { pemEncode(certificate.encoded) }

/** Checks the issuer name and certificate signature, independently of trust and validity. */
public fun verifyCertificateSignature(
    certificate: String,
    issuerCertificate: String,
): Boolean = verifyCertificate(parseCertificate(certificate), parseCertificate(issuerCertificate))

/** Checks the issuer name and certificate signature, independently of trust and validity. */
public fun verifyCertificateSignature(
    certificate: X509Certificate,
    issuerCertificate: X509Certificate,
): Boolean = verifyCertificate(parseCertificate(certificate), parseCertificate(issuerCertificate))

/** Checks the issuer name and certificate signature, independently of trust and validity. */
public fun verifyCertificateSignature(
    certificate: String,
    issuerCertificate: X509Certificate,
): Boolean = verifyCertificate(parseCertificate(certificate), parseCertificate(issuerCertificate))

/** Checks the issuer name and certificate signature, independently of trust and validity. */
public fun verifyCertificateSignature(
    certificate: X509Certificate,
    issuerCertificate: String,
): Boolean = verifyCertificate(parseCertificate(certificate), parseCertificate(issuerCertificate))

/**
 * Verifies a data signature using a PEM certificate's public key. ECDSA signatures must be DER.
 * RSA requires explicit [options]. Malformed inputs and unsupported algorithms throw [RegistryException].
 */
@JvmOverloads
public fun verifySignatureWithPem(
    pemKey: String,
    signature: String,
    data: ByteArray,
    options: SignatureVerificationOptions? = null,
): Boolean {
    val certificate = parseCertificate(pemKey)
    val bytes =
        try {
            Base64.getDecoder().decode(signature.replace(Regex("\\s"), ""))
        } catch (error: IllegalArgumentException) {
            throw RegistryException(RegistryErrorCategory.CRYPTOGRAPHIC_ERROR, "Invalid Base64 signature", error)
        }
    return verifyData(data.copyOf(), bytes, certificate.subjectPublicKeyInfo, options)
}
