package com.universalverify.trustedissuerregistry

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Geographic issuer metadata. Null override values leave certificate-derived defaults intact. */
@Serializable
public data class EntityMetadata
    @JvmOverloads
    constructor(
        public val country: String? = null,
        public val region: String? = null,
    )

/** Display information returned for an issuer. */
@Serializable
public data class IssuerDisplay
    @JvmOverloads
    constructor(
        public val name: String,
        public val logo: String? = null,
        public val description: String? = null,
    )

/** Optional display overrides for a user-provided issuer certificate. */
public data class IssuerDisplayOverrides
    @JvmOverloads
    constructor(
        public val name: String? = null,
        public val logo: String? = null,
        public val description: String? = null,
    )

/** A local PEM issuer certificate. It must contain a nonempty Subject Key Identifier. */
public data class UserTrustedIssuerCertificate
    @JvmOverloads
    constructor(
        public val data: String,
        public val format: CertificateFormat = CertificateFormat.PEM,
        public val trustScopes: List<TrustScope> = emptyList(),
        public val entityType: EntityType = EntityType.OTHER,
        public val entityMetadata: EntityMetadata = EntityMetadata(),
        public val display: IssuerDisplayOverrides = IssuerDisplayOverrides(),
    )

/** A certificate and the sources that vouch for it. */
@Serializable
public data class IssuerCertificate(
    public val data: String,
    public val format: CertificateFormat,
    @SerialName("trust_lists") public val trustLists: List<CertificateProvenance>,
)

/** Signed registry data or merged issuer data. Merged values have no [signature]. */
@Serializable
public data class Issuer(
    @SerialName("issuer_id") public val issuerId: String,
    @SerialName("entity_type") public val entityType: EntityType,
    @SerialName("entity_metadata") public val entityMetadata: EntityMetadata,
    public val display: IssuerDisplay,
    @SerialName("trust_scopes") public val trustScopes: List<TrustScope>,
    public val certificates: List<IssuerCertificate>,
    public val signature: String? = null,
)

/** Trust evaluation of an issuer certificate for the supplied input certificate. */
@Serializable
public data class ResolvedIssuerCertificate(
    public val data: String,
    public val format: CertificateFormat,
    @SerialName("trust_lists") public val trustLists: List<CertificateProvenance>,
    public val trusted: Boolean,
    public val revocationStatus: RevocationStatus,
    public val untrustedReasons: List<UntrustedReason> = emptyList(),
)

/** Issuer metadata and runtime certificate evaluations; no registry signature applies. */
@Serializable
public data class ResolvedIssuer(
    @SerialName("issuer_id") public val issuerId: String,
    @SerialName("entity_type") public val entityType: EntityType,
    @SerialName("entity_metadata") public val entityMetadata: EntityMetadata,
    public val display: IssuerDisplay,
    @SerialName("trust_scopes") public val trustScopes: List<TrustScope>,
    public val certificates: List<ResolvedIssuerCertificate>,
)

/** A normal trust failure is a result value, rather than an exception. */
@Serializable
public data class CertificateTrustResult(
    public val trusted: Boolean,
    public val issuer: ResolvedIssuer? = null,
    public val untrustedReasons: List<UntrustedReason> = emptyList(),
)
