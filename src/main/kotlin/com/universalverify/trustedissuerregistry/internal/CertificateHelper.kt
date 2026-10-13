package com.universalverify.trustedissuerregistry.internal

import com.universalverify.trustedissuerregistry.*
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.Base64
import java.util.Locale

internal val cryptoProvider = BouncyCastleProvider()

internal inline fun <T> certificateOperation(block: () -> T): T =
    try {
        block()
    } catch (error: RegistryException) {
        throw error
    } catch (error: Exception) {
        throw RegistryException(RegistryErrorCategory.MALFORMED_CERTIFICATE, "Unable to parse or encode certificate", error)
    }

internal fun parseCertificate(pem: String): X509CertificateHolder =
    certificateOperation {
        val content =
            pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace(Regex("\\s"), "")
        X509CertificateHolder(Base64.getDecoder().decode(content))
    }

internal fun parseCertificate(certificate: X509Certificate): X509CertificateHolder =
    certificateOperation {
        X509CertificateHolder(certificate.encoded)
    }

internal fun pemEncode(bytes: ByteArray): String =
    "-----BEGIN CERTIFICATE-----\n${Base64.getEncoder().encodeToString(bytes).chunked(64).joinToString("\n")}\n-----END CERTIFICATE-----"

internal fun subjectKeyIdentifier(certificate: X509CertificateHolder): String? =
    runCatching {
        certificate.getExtension(Extension.subjectKeyIdentifier)?.parsedValue?.let {
            val octets = ASN1OctetString.getInstance(it).octets
            if (octets.isEmpty()) null else Base64.getUrlEncoder().withoutPadding().encodeToString(octets)
        }
    }.getOrNull()

@Suppress("DEPRECATION")
internal fun authorityKeyIdentifier(certificate: X509CertificateHolder): String? =
    runCatching {
        certificate.getExtension(Extension.authorityKeyIdentifier)?.parsedValue?.let {
            val octets = AuthorityKeyIdentifier.getInstance(it).keyIdentifier
            if (octets == null || octets.isEmpty()) null else Base64.getUrlEncoder().withoutPadding().encodeToString(octets)
        }
    }.getOrNull()

internal fun subjectAttribute(
    certificate: X509CertificateHolder,
    oid: ASN1ObjectIdentifier,
): String? =
    certificate.subject.rdNs
        .flatMap { it.typesAndValues.toList() }
        .lastOrNull { it.type == oid }
        ?.value
        ?.let { (it as? ASN1String)?.let { value -> nameString(value) } }
        ?.takeIf { it.isNotEmpty() }

internal fun displayName(certificate: X509CertificateHolder): String? =
    subjectAttribute(certificate, BCStyle.O) ?: subjectAttribute(certificate, BCStyle.CN)

/** PKIjs compares flattened, ordered attributes; X500Name.equals also permits reordered RDNs. */
internal fun namesEqual(
    first: X500Name,
    second: X500Name,
): Boolean {
    val left = first.rdNs.flatMap { it.typesAndValues.toList() }
    val right = second.rdNs.flatMap { it.typesAndValues.toList() }
    if (left.size != right.size) return false
    val collator = nameComparator()
    return left.zip(right).all { (a, b) ->
        if (a.type != b.type) {
            false
        } else {
            val aValue = a.value.toASN1Primitive()
            val bValue = b.value.toASN1Primitive()
            when {
                aValue is ASN1String && bValue is ASN1String ->
                    collator.compare(prepareNameString(nameString(aValue)), prepareNameString(nameString(bValue))) == 0
                aValue is ASN1String || bValue is ASN1String -> false
                else -> aValue.getEncoded(ASN1Encoding.DER).contentEquals(bValue.getEncoded(ASN1Encoding.DER))
            }
        }
    }
}

private fun nameString(value: ASN1String): String =
    if (value is ASN1UniversalString) {
        // BC exposes UniversalString as DER hex; PKIjs compares its decoded UCS-4 text.
        val bytes = value.octets
        require(bytes.size % 4 == 0) { "Malformed UniversalString" }
        buildString {
            for (offset in bytes.indices step 4) {
                val code = (0..3).fold(0) { result, index -> (result shl 8) or (bytes[offset + index].toInt() and 0xff) }
                appendCodePoint(code)
            }
        }
    } else {
        value.string
    }

private fun prepareNameString(value: String): String =
    value
        .trim { character ->
            when (character.code) {
                in 9..13, 32, 0xa0, 0x1680, in 0x2000..0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff -> true
                else -> false
            }
        }.replace(Regex(" +"), " ")
        .lowercase(Locale.ROOT)

internal fun verifyCertificate(
    certificate: X509CertificateHolder,
    issuer: X509CertificateHolder,
): Boolean {
    return try {
        if (!namesEqual(certificate.issuer, issuer.subject)) return false
        val structure = certificate.toASN1Structure()
        if (structure.signatureAlgorithm != structure.tbsCertificate.signature) return false
        verifySignedData(
            structure.tbsCertificate.getEncoded(ASN1Encoding.DER),
            certificate.signature,
            issuer.subjectPublicKeyInfo,
            certificate.signatureAlgorithm,
        )
    } catch (_: Exception) {
        false
    }
}

private val hashOids =
    mapOf(
        "1.3.14.3.2.26" to HashAlgorithm.SHA1,
        "2.16.840.1.101.3.4.2.1" to HashAlgorithm.SHA256,
        "2.16.840.1.101.3.4.2.2" to HashAlgorithm.SHA384,
        "2.16.840.1.101.3.4.2.3" to HashAlgorithm.SHA512,
    )
private val signatureOids =
    mapOf(
        "1.2.840.10045.4.1" to SignatureVerificationOptions.Ecdsa(HashAlgorithm.SHA1),
        "1.2.840.10045.4.3.2" to SignatureVerificationOptions.Ecdsa(HashAlgorithm.SHA256),
        "1.2.840.10045.4.3.3" to SignatureVerificationOptions.Ecdsa(HashAlgorithm.SHA384),
        "1.2.840.10045.4.3.4" to SignatureVerificationOptions.Ecdsa(HashAlgorithm.SHA512),
        "1.2.840.113549.1.1.5" to SignatureVerificationOptions.RsaPkcs1v15(HashAlgorithm.SHA1),
        "1.2.840.113549.1.1.11" to SignatureVerificationOptions.RsaPkcs1v15(HashAlgorithm.SHA256),
        "1.2.840.113549.1.1.12" to SignatureVerificationOptions.RsaPkcs1v15(HashAlgorithm.SHA384),
        "1.2.840.113549.1.1.13" to SignatureVerificationOptions.RsaPkcs1v15(HashAlgorithm.SHA512),
    )

private fun unsupported(message: String): Nothing = throw RegistryException(RegistryErrorCategory.UNSUPPORTED_ALGORITHM, message)

internal fun parsePssParameters(algorithm: AlgorithmIdentifier): SignatureVerificationOptions.RsaPss {
    try {
        val sequence = ASN1Sequence.getInstance(algorithm.parameters ?: unsupported("RSA-PSS parameters are required"))
        var previousTag = -1
        for (field in sequence) {
            val tagged = ASN1TaggedObject.getInstance(field)
            if (tagged.tagClass != BERTags.CONTEXT_SPECIFIC ||
                !tagged.isExplicit ||
                tagged.tagNo !in 0..3 ||
                tagged.tagNo <= previousTag
            ) {
                unsupported("Malformed RSA-PSS parameters")
            }
            previousTag = tagged.tagNo
        }
        val params = RSASSAPSSparams.getInstance(sequence)
        if (params.maskGenAlgorithm.algorithm != PKCSObjectIdentifiers.id_mgf1 ||
            params.trailerField != java.math.BigInteger.ONE
        ) {
            unsupported("Unsupported RSA-PSS MGF or trailer")
        }
        val hash = hashOids[params.hashAlgorithm.algorithm.id] ?: unsupported("Unsupported PSS hash")
        val mgfHash = AlgorithmIdentifier.getInstance(params.maskGenAlgorithm.parameters)
        if (mgfHash.algorithm != params.hashAlgorithm.algorithm) unsupported("RSA-PSS MGF1 hash must match signature hash")
        val salt = params.saltLength.intValueExact()
        if (salt < 0) unsupported("RSA-PSS salt length must be nonnegative")
        return SignatureVerificationOptions.RsaPss(hash, salt)
    } catch (error: RegistryException) {
        throw error
    } catch (error: Exception) {
        throw RegistryException(RegistryErrorCategory.UNSUPPORTED_ALGORITHM, "Malformed RSA-PSS parameters", error)
    }
}

internal fun verifySignedData(
    data: ByteArray,
    signature: ByteArray,
    key: SubjectPublicKeyInfo,
    algorithm: AlgorithmIdentifier,
): Boolean {
    val options =
        if (algorithm.algorithm == PKCSObjectIdentifiers.id_RSASSA_PSS) {
            parsePssParameters(algorithm)
        } else {
            signatureOids[algorithm.algorithm.id] ?: unsupported("Unsupported signature algorithm: ${algorithm.algorithm.id}")
        }
    return verifyData(data, signature, key, options)
}

internal fun verifyData(
    data: ByteArray,
    signature: ByteArray,
    key: SubjectPublicKeyInfo,
    requested: SignatureVerificationOptions?,
): Boolean {
    val keyOid = key.algorithm.algorithm.id
    val options: SignatureVerificationOptions
    when (keyOid) {
        "1.2.840.10045.2.1" -> {
            if (requested != null && requested !is SignatureVerificationOptions.Ecdsa) unsupported("EC keys require ECDSA")
            val defaultHash =
                when ((key.algorithm.parameters as? ASN1ObjectIdentifier)?.id) {
                    "1.2.840.10045.3.1.7" -> HashAlgorithm.SHA256
                    "1.3.132.0.34" -> HashAlgorithm.SHA384
                    "1.3.132.0.35" -> HashAlgorithm.SHA512
                    else -> unsupported("Unsupported or missing EC named curve")
                }
            options = SignatureVerificationOptions.Ecdsa(requested?.hash ?: defaultHash)
            try {
                val sequence = ASN1Primitive.fromByteArray(signature) as? ASN1Sequence
                if (sequence == null ||
                    sequence.size() != 2 ||
                    sequence.any { it !is ASN1Integer }
                ) {
                    throw IllegalArgumentException("Invalid ECDSA signature")
                }
                if (!sequence
                        .getEncoded(
                            ASN1Encoding.DER,
                        ).contentEquals(signature)
                ) {
                    throw IllegalArgumentException("ECDSA signature must be DER")
                }
            } catch (error: Exception) {
                throw RegistryException(RegistryErrorCategory.CRYPTOGRAPHIC_ERROR, "Invalid DER signature structure", error)
            }
        }
        "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10" -> {
            options = requested ?: unsupported("RSA signatures require explicit algorithm and hash")
            if (options is SignatureVerificationOptions.Ecdsa) unsupported("RSA signatures require RSA options")
            if (keyOid == "1.2.840.113549.1.1.10") {
                if (options !is SignatureVerificationOptions.RsaPss) unsupported("PSS-only keys require RSA-PSS")
                key.algorithm.parameters?.let {
                    val restrictions = parsePssParameters(key.algorithm)
                    if (options.hash != restrictions.hash ||
                        options.saltLength < restrictions.saltLength
                    ) {
                        unsupported("Signature parameters violate PSS-only key restrictions")
                    }
                }
            }
        }
        else -> unsupported("Unsupported public key algorithm: $keyOid")
    }
    if (options is SignatureVerificationOptions.RsaPss) {
        val modulusBits =
            org.bouncycastle.asn1.pkcs.RSAPublicKey
                .getInstance(key.parsePublicKey())
                .modulus
                .bitLength()
        val maximumSalt = (modulusBits - 1 + 7) / 8 - options.hash.digestLength - 2
        if (options.saltLength > maximumSalt) unsupported("RSA-PSS salt length exceeds key capacity")
    }
    return try {
        val name =
            when (options) {
                is SignatureVerificationOptions.Ecdsa -> "${options.hash!!.algorithmName.replace("-", "")}withECDSA"
                is SignatureVerificationOptions.RsaPkcs1v15 -> "${options.hash.algorithmName.replace("-", "")}withRSA"
                is SignatureVerificationOptions.RsaPss -> "RSASSA-PSS"
            }
        val verifier = Signature.getInstance(name, cryptoProvider)
        if (options is SignatureVerificationOptions.RsaPss) {
            verifier.setParameter(
                PSSParameterSpec(options.hash.algorithmName, "MGF1", MGF1ParameterSpec(options.hash.algorithmName), options.saltLength, 1),
            )
        }
        verifier.initVerify(JcaPEMKeyConverter().setProvider(cryptoProvider).getPublicKey(key))
        verifier.update(data)
        verifier.verify(signature)
    } catch (error: Exception) {
        throw RegistryException(RegistryErrorCategory.CRYPTOGRAPHIC_ERROR, "Signature verification failed", error)
    }
}
