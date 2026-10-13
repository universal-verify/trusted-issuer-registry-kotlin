package com.universalverify.trustedissuerregistry.internal

import com.universalverify.trustedissuerregistry.*
import kotlinx.coroutines.*
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.bouncycastle.cert.X509CertificateHolder
import java.time.Clock
import java.time.Instant

internal suspend fun getRegistryIssuer(
    aki: String,
    fetcher: CachedFetcher,
): Issuer? {
    val url =
        REGISTRY_URL_BASE
            .toHttpUrl()
            .newBuilder()
            .addPathSegments("issuers/x509_aki")
            .addPathSegment("$aki.json")
            .build()
    val response = fetcher.fetch(url.toString(), FetchPurpose.ISSUER)
    if (!response.ok &&
        response.status != 404
    ) {
        throw RegistryException(
            RegistryErrorCategory.HTTP_ERROR,
            "Failed to fetch issuer $aki: HTTP ${response.status}",
            httpStatus = response.status,
        )
    }
    return response.issuer?.let { snapshot(it) }
}

internal suspend fun resolveTrust(
    certificate: X509CertificateHolder?,
    options: ResolveCertificateTrustOptions,
    users: Map<String, Issuer>,
    fetcher: CachedFetcher,
    revocationMode: RevocationCheckMode,
    clock: Clock,
): CertificateTrustResult {
    if (certificate == null) return CertificateTrustResult(false, untrustedReasons = freeze(listOf(UntrustedReason.CERTIFICATE_MISSING)))
    val aki =
        authorityKeyIdentifier(certificate)
            ?: return CertificateTrustResult(false, untrustedReasons = freeze(listOf(UntrustedReason.CERTIFICATE_AKI_MISSING)))
    val reasons = mutableListOf<UntrustedReason>()
    val now = clock.instant()
    if (certificate.notBefore.toInstant() > now) reasons.add(UntrustedReason.CERTIFICATE_NOT_YET_VALID)
    if (certificate.notAfter.toInstant() < now) reasons.add(UntrustedReason.CERTIFICATE_EXPIRED)
    var fetchFailed = false
    val registry =
        if (options.trustLists.isNotEmpty()) {
            try {
                getRegistryIssuer(aki, fetcher)
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                fetchFailed = true
                null
            }
        } else {
            null
        }
    val issuer = mergeIssuers(users[aki], registry)
    val resolved =
        issuer?.let {
            val certificates =
                coroutineScope {
                    it.certificates
                        .map { candidate ->
                            async {
                                evaluateCertificate(
                                    certificate,
                                    candidate,
                                    it.trustScopes,
                                    options,
                                    fetcher,
                                    revocationMode,
                                    clock,
                                    now,
                                )
                            }
                        }.awaitAll()
                }
            ResolvedIssuer(it.issuerId, it.entityType, it.entityMetadata, it.display, freeze(it.trustScopes), freeze(certificates))
        }
    val selected = resolved?.certificates?.minByOrNull { it.untrustedReasons.size }
    if (selected == null) reasons.add(UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND) else reasons.addAll(selected.untrustedReasons)
    if (fetchFailed && selected?.trusted != true) reasons.add(UntrustedReason.ISSUER_FETCH_FAILED)
    return CertificateTrustResult(reasons.isEmpty(), resolved, freeze(reasons))
}

private suspend fun evaluateCertificate(
    certificate: X509CertificateHolder,
    candidate: IssuerCertificate,
    scopes: List<TrustScope>,
    options: ResolveCertificateTrustOptions,
    fetcher: CachedFetcher,
    mode: RevocationCheckMode,
    clock: Clock,
    now: Instant,
): ResolvedIssuerCertificate {
    val issuer = parseCertificate(candidate.data)
    val reasons = mutableListOf<UntrustedReason>()
    if (issuer.notBefore.toInstant() > now) reasons.add(UntrustedReason.ISSUER_CERTIFICATE_NOT_YET_VALID)
    if (issuer.notAfter.toInstant() < now) reasons.add(UntrustedReason.ISSUER_CERTIFICATE_EXPIRED)
    if (CertificateProvenance.USER_PROVIDED !in candidate.trustLists &&
        candidate.trustLists.none { provenance -> options.trustLists.any { it.wireValue == provenance.wireValue } }
    ) {
        reasons.add(UntrustedReason.ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS)
    }
    if (options.trustScope != null && options.trustScope !in scopes) reasons.add(UntrustedReason.ISSUER_MISSING_REQUIRED_TRUST_SCOPE)
    var status = RevocationStatus.NOT_CHECKED
    if (!verifyCertificate(certificate, issuer)) {
        reasons.add(UntrustedReason.CERTIFICATE_SIGNATURE_VERIFICATION_FAILED)
    } else if (mode != RevocationCheckMode.SKIP) {
        val revocation = checkCertificateRevocation(certificate, issuer, fetcher, clock)
        when {
            revocation.revoked -> {
                status = RevocationStatus.REVOKED
                reasons.add(UntrustedReason.CERTIFICATE_REVOKED)
            }
            revocation.checked -> status = RevocationStatus.NOT_REVOKED
            mode == RevocationCheckMode.REQUIRED -> reasons.add(UntrustedReason.REVOCATION_STATUS_UNDETERMINED)
        }
    }
    return ResolvedIssuerCertificate(
        candidate.data,
        candidate.format,
        freeze(candidate.trustLists),
        reasons.isEmpty(),
        status,
        freeze(reasons),
    )
}
