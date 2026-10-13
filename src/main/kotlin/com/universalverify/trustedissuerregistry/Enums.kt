package com.universalverify.trustedissuerregistry

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** A stable string used by the registry protocol. */
public interface WireValue {
    public val wireValue: String
}

/** Registry trust lists that can be requested during resolution. */
@Serializable
public enum class TrustList(
    override val wireValue: String,
) : WireValue {
    @SerialName("uv")
    UV("uv"),

    @SerialName("aamva_dts")
    AAMVA_DTS("aamva_dts"),
}

/** Provenance of an issuer certificate, including explicitly trusted local certificates. */
@Serializable
public enum class CertificateProvenance(
    override val wireValue: String,
) : WireValue {
    @SerialName("uv")
    UV("uv"),

    @SerialName("aamva_dts")
    AAMVA_DTS("aamva_dts"),

    @SerialName("user_provided")
    USER_PROVIDED("user_provided"),
}

/** The context in which an issuer is trusted. */
@Serializable
public enum class TrustScope(
    override val wireValue: String,
) : WireValue {
    @SerialName("government_issued_id")
    GOVERNMENT_ISSUED_ID("government_issued_id"),

    @SerialName("document_signing")
    DOCUMENT_SIGNING("document_signing"),
}

/** Whether an undetermined CRL status prevents trust. */
@Serializable
public enum class RevocationCheckMode(
    override val wireValue: String,
) : WireValue {
    @SerialName("skip")
    SKIP("skip"),

    @SerialName("best_effort")
    BEST_EFFORT("best_effort"),

    @SerialName("required")
    REQUIRED("required"),
}

/** Stable failure reasons; list order follows the JavaScript SDK. */
@Serializable
public enum class UntrustedReason(
    override val wireValue: String,
) : WireValue {
    @SerialName("certificate_missing")
    CERTIFICATE_MISSING("certificate_missing"),

    @SerialName("certificate_aki_missing")
    CERTIFICATE_AKI_MISSING("certificate_aki_missing"),

    @SerialName("certificate_not_yet_valid")
    CERTIFICATE_NOT_YET_VALID("certificate_not_yet_valid"),

    @SerialName("certificate_expired")
    CERTIFICATE_EXPIRED("certificate_expired"),

    @SerialName("certificate_revoked")
    CERTIFICATE_REVOKED("certificate_revoked"),

    @SerialName("revocation_status_undetermined")
    REVOCATION_STATUS_UNDETERMINED("revocation_status_undetermined"),

    @SerialName("issuer_fetch_failed")
    ISSUER_FETCH_FAILED("issuer_fetch_failed"),

    @SerialName("issuer_certificate_not_found")
    ISSUER_CERTIFICATE_NOT_FOUND("issuer_certificate_not_found"),

    @SerialName("certificate_signature_verification_failed")
    CERTIFICATE_SIGNATURE_VERIFICATION_FAILED("certificate_signature_verification_failed"),

    @SerialName("issuer_certificate_not_yet_valid")
    ISSUER_CERTIFICATE_NOT_YET_VALID("issuer_certificate_not_yet_valid"),

    @SerialName("issuer_certificate_expired")
    ISSUER_CERTIFICATE_EXPIRED("issuer_certificate_expired"),

    @SerialName("issuer_certificate_not_in_trust_lists")
    ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS("issuer_certificate_not_in_trust_lists"),

    @SerialName("issuer_missing_required_trust_scope")
    ISSUER_MISSING_REQUIRED_TRUST_SCOPE("issuer_missing_required_trust_scope"),
}

/** High-level issuer organization type. */
@Serializable
public enum class EntityType(
    override val wireValue: String,
) : WireValue {
    @SerialName("government")
    GOVERNMENT("government"),

    @SerialName("educational_institution")
    EDUCATIONAL_INSTITUTION("educational_institution"),

    @SerialName("commercial")
    COMMERCIAL("commercial"),

    @SerialName("non_profit")
    NON_PROFIT("non_profit"),

    @SerialName("international_body")
    INTERNATIONAL_BODY("international_body"),

    @SerialName("other")
    OTHER("other"),
}

/** Supported issuer certificate encoding. */
@Serializable
public enum class CertificateFormat(
    override val wireValue: String,
) : WireValue {
    @SerialName("pem")
    PEM("pem"),
}

/** Undetermined revocation is represented as [NOT_CHECKED], matching JavaScript. */
@Serializable
public enum class RevocationStatus(
    override val wireValue: String,
) : WireValue {
    @SerialName("not_checked")
    NOT_CHECKED("not_checked"),

    @SerialName("not_revoked")
    NOT_REVOKED("not_revoked"),

    @SerialName("revoked")
    REVOKED("revoked"),
}

/** Hashes supported by the signature helpers. */
public enum class HashAlgorithm(
    public val algorithmName: String,
    public val digestLength: Int,
) {
    SHA1("SHA-1", 20),
    SHA256("SHA-256", 32),
    SHA384("SHA-384", 48),
    SHA512("SHA-512", 64),
}
