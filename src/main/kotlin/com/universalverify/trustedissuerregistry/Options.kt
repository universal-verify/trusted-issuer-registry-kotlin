package com.universalverify.trustedissuerregistry

import com.universalverify.trustedissuerregistry.internal.freeze
import java.time.Duration

/** Client configuration. Durations apply to individual requests, including their bodies. */
public data class RegistryOptions
    @JvmOverloads
    constructor(
        public val trustedIssuerCertificates: List<UserTrustedIssuerCertificate> = emptyList(),
        public val revocationCheckMode: RevocationCheckMode = RevocationCheckMode.SKIP,
        public val timeout: Duration = Duration.ofSeconds(10),
        public val cacheEnabled: Boolean = true,
        public val cacheTtl: Duration = Duration.ofHours(24),
    ) {
        init {
            require(!timeout.isZero && !timeout.isNegative) { "timeout must be positive" }
            require(!cacheTtl.isNegative) { "cacheTtl must be nonnegative" }
            require(
                runCatching {
                    timeout.toNanos()
                    cacheTtl.toNanos()
                }.isSuccess,
            ) { "Duration is too large" }
        }

        public companion object {
            @JvmStatic public fun builder(): Builder = Builder()
        }

        /** Java-friendly builder; both PEM strings and metadata-bearing certificates may be added. */
        public class Builder {
            private val certificates = mutableListOf<UserTrustedIssuerCertificate>()
            private var revocation = RevocationCheckMode.SKIP
            private var timeout = Duration.ofSeconds(10)
            private var caching = true
            private var ttl = Duration.ofHours(24)

            public fun addTrustedIssuerCertificate(pem: String): Builder = addTrustedIssuerCertificate(UserTrustedIssuerCertificate(pem))

            public fun addTrustedIssuerCertificate(certificate: UserTrustedIssuerCertificate): Builder =
                apply {
                    certificates.add(certificate.copy(trustScopes = freeze(certificate.trustScopes)))
                }

            public fun revocationCheckMode(mode: RevocationCheckMode): Builder = apply { revocation = mode }

            public fun timeout(timeout: Duration): Builder = apply { this.timeout = timeout }

            public fun cacheEnabled(enabled: Boolean): Builder = apply { caching = enabled }

            public fun cacheTtl(ttl: Duration): Builder = apply { this.ttl = ttl }

            public fun build(): RegistryOptions = RegistryOptions(freeze(certificates), revocation, timeout, caching, ttl)
        }
    }

/** Empty [trustLists] uses only local issuers and never queries the registry. */
public data class ResolveCertificateTrustOptions
    @JvmOverloads
    constructor(
        public val trustLists: List<TrustList> = emptyList(),
        public val trustScope: TrustScope? = null,
    ) {
        public companion object {
            @JvmStatic public fun builder(): Builder = Builder()
        }

        public class Builder {
            private val lists = mutableListOf<TrustList>()
            private var scope: TrustScope? = null

            public fun addTrustList(list: TrustList): Builder = apply { lists.add(list) }

            public fun trustScope(scope: TrustScope?): Builder = apply { this.scope = scope }

            public fun build(): ResolveCertificateTrustOptions = ResolveCertificateTrustOptions(freeze(lists), scope)
        }
    }

/** Parameters of a data signature; RSA has no implicit algorithm or hash defaults. */
public sealed interface SignatureVerificationOptions {
    public data class Ecdsa
        @JvmOverloads
        constructor(
            public val hash: HashAlgorithm? = null,
        ) : SignatureVerificationOptions

    public data class RsaPkcs1v15(
        public val hash: HashAlgorithm,
    ) : SignatureVerificationOptions

    public data class RsaPss(
        public val hash: HashAlgorithm,
        public val saltLength: Int,
    ) : SignatureVerificationOptions {
        init {
            require(saltLength >= 0) { "saltLength must be nonnegative" }
        }
    }
}
