package com.universalverify.trustedissuerregistry.internal

import com.universalverify.trustedissuerregistry.*
import kotlinx.serialization.json.*
import org.bouncycastle.asn1.x500.style.BCStyle

internal fun snapshot(issuer: Issuer): Issuer =
    issuer.copy(
        trustScopes = freeze(issuer.trustScopes),
        certificates = freeze(issuer.certificates.map { it.copy(trustLists = freeze(it.trustLists)) }),
    )

internal fun mergeIssuers(
    user: Issuer?,
    registry: Issuer?,
): Issuer? {
    if (user == null && registry == null) return null
    val preferred = user ?: registry!!
    val metadata =
        EntityMetadata(
            user?.entityMetadata?.country ?: registry?.entityMetadata?.country,
            user?.entityMetadata?.region ?: registry?.entityMetadata?.region,
        )
    val display =
        IssuerDisplay(
            user?.display?.name ?: registry!!.display.name,
            user?.display?.logo ?: registry?.display?.logo,
            user?.display?.description ?: registry?.display?.description,
        )
    val certificates = linkedMapOf<String, IssuerCertificate>()
    for (certificate in user?.certificates.orEmpty() + registry?.certificates.orEmpty()) {
        val existing = certificates[certificate.data]
        certificates[certificate.data] =
            certificate.copy(trustLists = freeze((existing?.trustLists.orEmpty() + certificate.trustLists).distinct()))
    }
    return Issuer(
        preferred.issuerId,
        preferred.entityType,
        metadata,
        display,
        freeze((user?.trustScopes.orEmpty() + registry?.trustScopes.orEmpty()).distinct()),
        freeze(certificates.values),
    )
}

internal fun buildUserTrustedIssuers(certificates: List<UserTrustedIssuerCertificate>): Map<String, Issuer> {
    val issuers = linkedMapOf<String, Issuer>()
    for (input in certificates) {
        val certificate =
            try {
                parseCertificate(input.data)
            } catch (error: RegistryException) {
                throw IllegalArgumentException("Invalid user issuer certificate", error)
            }
        val ski =
            subjectKeyIdentifier(certificate)
                ?: throw IllegalArgumentException("User issuer certificate must include a nonempty Subject Key Identifier")
        val id = "x509_aki:$ski"
        val issuer =
            Issuer(
                id,
                input.entityType,
                EntityMetadata(
                    input.entityMetadata.country ?: subjectAttribute(certificate, BCStyle.C).orEmpty(),
                    input.entityMetadata.region ?: subjectAttribute(certificate, BCStyle.ST)?.replaceFirst("US-", ""),
                ),
                IssuerDisplay(input.display.name ?: displayName(certificate) ?: id, input.display.logo, input.display.description),
                freeze(input.trustScopes),
                freeze(
                    listOf(
                        IssuerCertificate(
                            pemEncode(certificate.encoded),
                            CertificateFormat.PEM,
                            freeze(listOf(CertificateProvenance.USER_PROVIDED)),
                        ),
                    ),
                ),
            )
        issuers[ski] = mergeIssuers(issuers[ski], issuer)!!
    }
    return issuers
}

internal fun decodeVerifiedIssuer(
    bytes: ByteArray,
    signingCertificate: String = PUBLIC_SIGNING_CERT,
): Issuer? {
    val objectValue =
        try {
            registryJson.parseToJsonElement(decodeJsonText(bytes)) as? JsonObject
                ?: throw IllegalArgumentException("Issuer JSON must be an object")
        } catch (error: Exception) {
            throw RegistryException(RegistryErrorCategory.MALFORMED_RESPONSE, "Malformed issuer JSON", error)
        }
    val verified =
        runCatching {
            val signature = objectValue["signature"]?.jsonPrimitive?.content ?: return@runCatching false
            val payload = JsonObject(objectValue.filterKeys { it != "signature" })
            verifySignatureWithPem(signingCertificate, signature, encodeUtf8(CanonicalJson.stringify(payload)))
        }.getOrDefault(false)
    if (!verified) return null
    return try {
        snapshot(registryJson.decodeFromJsonElement<Issuer>(objectValue))
    } catch (error: Exception) {
        throw RegistryException(RegistryErrorCategory.MALFORMED_RESPONSE, "Malformed signed issuer data", error)
    }
}
