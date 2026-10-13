package com.universalverify.trustedissuerregistry.internal

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509CertificateHolder
import java.time.Clock
import java.util.Base64

internal data class RevocationResult(
    val checked: Boolean = false,
    val revoked: Boolean = false,
)

internal fun parseCrl(bytes: ByteArray): ParsedCrl {
    val text = bytes.toString(Charsets.UTF_8)
    val der =
        if (text.trimStart().startsWith("-----BEGIN X509 CRL-----")) {
            val content = text.substringAfter("-----BEGIN X509 CRL-----").substringBefore("-----END X509 CRL-----")
            require(text.contains("-----END X509 CRL-----")) { "Malformed PEM CRL" }
            Base64.getDecoder().decode(content.replace(Regex("\\s"), ""))
        } else {
            bytes
        }
    return ParsedCrl(CertificateList.getInstance(ASN1Primitive.fromByteArray(der)))
}

private const val ALL_REASONS = 0x1fe

// Match PKIjs CertificateRevocationList.verify's critical-extension allowlist.
private val knownCrlExtensions =
    setOf(
        Extension.authorityKeyIdentifier,
        Extension.issuerAlternativeName,
        Extension.cRLNumber,
        Extension.deltaCRLIndicator,
        Extension.issuingDistributionPoint,
        Extension.freshestCRL,
        Extension.authorityInfoAccess,
        Extension.reasonCode,
        Extension.invalidityDate,
        Extension.certificateIssuer,
    )

private data class Point(
    val value: DistributionPoint,
    val urls: List<String>,
    val reasonsMask: Int,
)

private data class CrlResult(
    val url: String,
    val crl: ParsedCrl?,
)

private fun getDistributionPoints(certificate: X509CertificateHolder): List<Point> {
    val extension = certificate.getExtension(Extension.cRLDistributionPoints) ?: return emptyList()
    return ASN1Sequence.getInstance(extension.parsedValue).mapNotNull { encodedPoint ->
        val fields = ASN1Sequence.getInstance(encodedPoint).map { ASN1TaggedObject.getInstance(it) }
        require(fields.map { it.tagNo }.distinct().size == fields.size) { "Duplicate distribution point field" }
        // PKIjs treats the implicit reason payload as raw flag bytes, including its non-DER
        // writer output. Interpret those bytes exactly; do not alter the certificate's DER.
        val reasonBytes = fields.firstOrNull { it.tagNo == 1 }?.let { ASN1OctetString.getInstance(it, false).octets }
        val point = DistributionPoint.getInstance(DERSequence(fields.filter { it.tagNo != 1 }.toTypedArray()))
        val name = point.distributionPoint
        val urls =
            if (name?.type == DistributionPointName.FULL_NAME) {
                GeneralNames
                    .getInstance(name.name)
                    .names
                    .filter { it.tagNo == GeneralName.uniformResourceIdentifier }
                    .map { (it.name as ASN1String).string }
                    .distinct()
            } else {
                emptyList()
            }
        if (urls.isEmpty()) null else Point(point, urls, reasonBytes?.let { reasonMask(it) } ?: ALL_REASONS)
    }
}

internal suspend fun checkCertificateRevocation(
    certificate: X509CertificateHolder,
    issuer: X509CertificateHolder,
    fetcher: CachedFetcher,
    clock: Clock,
): RevocationResult {
    val points =
        runCatching { getDistributionPoints(certificate) }
            .getOrElse { return RevocationResult() }
            .filter {
                it.value.crlIssuer
                    ?.names
                    .isNullOrEmpty()
            }
    val urls = points.flatMap { it.urls }.distinct()
    if (urls.isEmpty()) return RevocationResult()
    val issuerMaySign =
        runCatching {
            issuer.versionNumber != 3 ||
                issuer.getExtension(Extension.keyUsage)?.parsedValue?.let {
                    KeyUsage.getInstance(it).hasUsages(KeyUsage.cRLSign)
                } == true
        }.getOrDefault(false)
    if (!issuerMaySign) return RevocationResult()

    return coroutineScope {
        val responses = Channel<CrlResult>(Channel.UNLIMITED)
        val jobs =
            urls.map { url ->
                launch {
                    val crl =
                        try {
                            val response = fetcher.fetch(url, FetchPurpose.CRL)
                            if (response.ok && response.error == null) response.crl else null
                        } catch (error: CancellationException) {
                            throw error
                        } catch (_: Exception) {
                            null
                        }
                    responses.send(CrlResult(url, crl))
                }
            }
        var coveredReasons = 0
        try {
            repeat(urls.size) {
                val response = responses.receive()
                val crl = response.crl ?: return@repeat
                try {
                    val structure = crl.structure
                    if (!namesEqual(crl.issuer, issuer.subject) ||
                        structure.tbsCertList.extensions
                            ?.criticalExtensionOIDs
                            .orEmpty()
                            .any { it !in knownCrlExtensions }
                    ) {
                        return@repeat
                    }
                    if (structure.signatureAlgorithm != structure.tbsCertList.signature) return@repeat
                    if (!verifySignedData(
                            structure.tbsCertList.getEncoded(ASN1Encoding.DER),
                            structure.signature.octets,
                            issuer.subjectPublicKeyInfo,
                            structure.signatureAlgorithm,
                        )
                    ) {
                        return@repeat
                    }
                    for (point in points.filter { response.url in it.urls }) {
                        val reasons = coverage(certificate, crl, point)
                        if (reasons == 0 || crl.thisUpdate.toInstant() > clock.instant()) continue
                        val delta = crl.getExtension(Extension.deltaCRLIndicator) != null
                        val entry = crl.getRevokedCertificate(certificate.serialNumber)
                        if (entry != null) {
                            val reason =
                                entry.extensions
                                    ?.getExtension(
                                        Extension.reasonCode,
                                    )?.parsedValue
                                    ?.let { ASN1Enumerated.getInstance(it).value.intValueExact() }
                            if (reason != 8) return@coroutineScope RevocationResult(checked = true, revoked = true)
                            if (!delta) continue
                        }
                        if (delta) continue
                        val stale = crl.nextUpdate?.toInstant()?.let { it < clock.instant() } == true
                        if (!stale) {
                            coveredReasons = coveredReasons or reasons
                            if (coveredReasons and ALL_REASONS == ALL_REASONS) return@coroutineScope RevocationResult(checked = true)
                        }
                    }
                } catch (error: CancellationException) {
                    throw error
                } catch (_: Exception) {
                    // Malformed or unsupported CRLs cannot establish status.
                }
            }
            RevocationResult()
        } finally {
            jobs.forEach { it.cancel() }
            responses.cancel()
        }
    }
}

private fun coverage(
    certificate: X509CertificateHolder,
    crl: ParsedCrl,
    point: Point,
): Int {
    if (!namesEqual(crl.issuer, certificate.issuer)) return 0
    var crlReasons = ALL_REASONS
    val issuing =
        crl.getExtension(Extension.issuingDistributionPoint)?.parsedValue?.let {
            val fields = ASN1Sequence.getInstance(it).map { field -> ASN1TaggedObject.getInstance(field) }
            require(fields.map { field -> field.tagNo }.distinct().size == fields.size) { "Duplicate issuing distribution point field" }
            fields.firstOrNull { field -> field.tagNo == 3 }?.let { reasons ->
                val bytes = ASN1OctetString.getInstance(reasons, false).octets
                crlReasons = reasonMask(byteArrayOf(bytes.first()))
            }
            IssuingDistributionPoint.getInstance(DERSequence(fields.filter { field -> field.tagNo != 3 }.toTypedArray()))
        }
    if (issuing != null) {
        if (issuing.isIndirectCRL || issuing.onlyContainsAttributeCerts()) return 0
        val isCa = certificate.getExtension(Extension.basicConstraints)?.parsedValue?.let { BasicConstraints.getInstance(it).isCA } == true
        if (issuing.onlyContainsCACerts() && !isCa || issuing.onlyContainsUserCerts() && isCa) return 0
        issuing.distributionPoint?.let { name ->
            if (nameKeys(name)
                    .intersect(
                        point.value.distributionPoint
                            ?.let { nameKeys(it) }
                            .orEmpty(),
                    ).isEmpty()
            ) {
                return 0
            }
        }
    }
    return point.reasonsMask and crlReasons
}

private fun reasonMask(bytes: ByteArray): Int {
    var mask = 0
    bytes.forEachIndexed { byteIndex, byte ->
        for (bit in 0..7) if (byte.toInt() and (0x80 shr bit) != 0) mask = mask or (1 shl (byteIndex * 8 + bit))
    }
    return mask and ALL_REASONS
}

private fun nameKeys(name: DistributionPointName): Set<String> =
    if (name.type == DistributionPointName.FULL_NAME) {
        GeneralNames
            .getInstance(name.name)
            .names
            .map { general ->
                if (general.tagNo == GeneralName.uniformResourceIdentifier) {
                    "uri:${(general.name as ASN1String).string}"
                } else {
                    "asn1:${Base64.getEncoder().encodeToString(general.getEncoded(ASN1Encoding.DER))}"
                }
            }.toSet()
    } else {
        setOf("rdn:${Base64.getEncoder().encodeToString(name.name.toASN1Primitive().getEncoded(ASN1Encoding.DER))}")
    }

/** Keeps signed CRL fields intact while interpreting PKIjs extension payloads separately. */
internal class ParsedCrl(
    val structure: CertificateList,
) {
    val issuer get() = structure.issuer
    val thisUpdate get() = structure.thisUpdate.date
    val nextUpdate get() = structure.nextUpdate?.date

    fun getExtension(oid: ASN1ObjectIdentifier): Extension? = structure.tbsCertList.extensions?.getExtension(oid)

    fun getRevokedCertificate(serial: java.math.BigInteger): TBSCertList.CRLEntry? =
        structure.revokedCertificates?.firstOrNull { it.userCertificate.value == serial }
}
