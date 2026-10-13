package com.universalverify.trustedissuerregistry

import com.universalverify.trustedissuerregistry.internal.*
import kotlinx.coroutines.*
import kotlinx.coroutines.future.future
import kotlinx.serialization.json.*
import okhttp3.OkHttpClient
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Thread-safe client for signed registry issuers and local issuer certificates.
 * Reuse an instance to share downloads and caches. Close it when its lifecycle ends.
 */
public class Registry private constructor(
    options: RegistryOptions,
    suppliedClient: OkHttpClient?,
    private val clock: Clock,
    signingCertificate: String,
) : AutoCloseable {
    @JvmOverloads
    public constructor(
        options: RegistryOptions = RegistryOptions(),
        httpClient: OkHttpClient? = null,
    ) : this(options, httpClient, Clock.systemUTC(), PUBLIC_SIGNING_CERT)

    private val options =
        options.copy(
            trustedIssuerCertificates =
                freeze(
                    options.trustedIssuerCertificates.map {
                        it.copy(trustScopes = freeze(it.trustScopes))
                    },
                ),
        )
    private val users = buildUserTrustedIssuers(this.options.trustedIssuerCertificates)
    private val client = suppliedClient ?: OkHttpClient()
    private val ownsClient = suppliedClient == null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val fetcher = CachedFetcher(this.options, client, scope, clock, signingCertificate)
    private val closed = AtomicBoolean()

    public companion object {
        /** Registry protocol minor version, independent of the Kotlin SDK version. */
        @JvmField public val minorVersion: String = MINOR_VERSION

        @JvmSynthetic
        internal fun forTesting(
            options: RegistryOptions,
            client: OkHttpClient,
            clock: Clock,
            signingCertificate: String = PUBLIC_SIGNING_CERT,
        ): Registry = Registry(options, client, clock, signingCertificate)
    }

    private suspend fun <T> operation(block: suspend () -> T): T {
        check(!closed.get()) { "Registry is closed" }
        val child = scope.async { block() }
        return try {
            child.await()
        } finally {
            child.cancel()
        }
    }

    /** Fetches an applicable unsigned deprecation notice, or returns null on 404/older version. */
    @JvmSynthetic
    public suspend fun getEndOfLifeDate(): Instant? =
        operation {
            val response = fetcher.fetch("$REGISTRY_URL_BASE/deprecation_notice.json", FetchPurpose.DEPRECATION)
            if (response.status == 404) return@operation null
            if (!response.ok) {
                throw RegistryException(
                    RegistryErrorCategory.HTTP_ERROR,
                    "Failed to fetch deprecation notice: HTTP ${response.status}",
                    httpStatus = response.status,
                )
            }
            response.error?.let { throw it }
            try {
                val notice = response.deprecation!!
                val version = notice["version"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotEmpty() } ?: return@operation null
                val parts = version.split('.').map { it.toInt() }
                val current = MINOR_VERSION.split('.').map { it.toInt() }
                if (parts.size < 2) throw IllegalArgumentException("Missing minor version")
                if (parts[0] < current[0] || parts[0] == current[0] && parts[1] < current[1]) return@operation null
                val seconds = notice["end_of_life"]?.jsonPrimitive?.doubleOrNull ?: throw IllegalArgumentException("Missing end_of_life")
                if (!seconds.isFinite()) throw IllegalArgumentException("Invalid end_of_life")
                Instant.ofEpochMilli((seconds * 1000).toLong())
            } catch (error: Exception) {
                throw RegistryException(RegistryErrorCategory.MALFORMED_RESPONSE, "Malformed deprecation notice", error)
            }
        }

    /** Always checks the registry and merges a matching local issuer. [x509aki] excludes its prefix. */
    @JvmSynthetic
    public suspend fun getIssuerFromX509AKI(x509aki: String): Issuer? =
        operation {
            val registry = getRegistryIssuer(x509aki, fetcher)
            users[x509aki]?.let { mergeIssuers(it, registry) } ?: registry
        }

    /** Resolves issuer trust. A null or empty PEM reports [UntrustedReason.CERTIFICATE_MISSING]. */
    @JvmSynthetic
    public suspend fun resolveCertificateTrust(
        certificate: String? = null,
        options: ResolveCertificateTrustOptions = ResolveCertificateTrustOptions(),
    ): CertificateTrustResult {
        val snapshot = options.copy(trustLists = freeze(options.trustLists))
        return operation {
            resolveTrust(
                certificate
                    ?.takeIf {
                        it.isNotEmpty()
                    }?.let { parseCertificate(it) },
                snapshot,
                users,
                fetcher,
                this.options.revocationCheckMode,
                clock,
            )
        }
    }

    /** Resolves issuer trust using the encoded bytes of a parsed certificate. */
    @JvmSynthetic
    public suspend fun resolveCertificateTrust(
        certificate: X509Certificate,
        options: ResolveCertificateTrustOptions = ResolveCertificateTrustOptions(),
    ): CertificateTrustResult {
        val parsed = parseCertificate(certificate)
        val snapshot = options.copy(trustLists = freeze(options.trustLists))
        return operation { resolveTrust(parsed, snapshot, users, fetcher, this.options.revocationCheckMode, clock) }
    }

    /** Blocking Java facade. Call from a worker thread on Android. */
    public fun getEndOfLifeDateBlocking(): Instant? = runBlocking { getEndOfLifeDate() }

    /** Blocking Java facade. Call from a worker thread on Android. */
    public fun getIssuerFromX509AKIBlocking(x509aki: String): Issuer? = runBlocking { getIssuerFromX509AKI(x509aki) }

    /** Blocking Java facade; omitting the certificate reports missing input. */
    @JvmOverloads
    public fun resolveCertificateTrustBlocking(
        certificate: String? = null,
        options: ResolveCertificateTrustOptions = ResolveCertificateTrustOptions(),
    ): CertificateTrustResult = runBlocking { resolveCertificateTrust(certificate, options) }

    /** Blocking Java facade for parsed input. */
    @JvmOverloads
    public fun resolveCertificateTrustBlocking(
        certificate: X509Certificate,
        options: ResolveCertificateTrustOptions = ResolveCertificateTrustOptions(),
    ): CertificateTrustResult = runBlocking { resolveCertificateTrust(certificate, options) }

    /** A cancellable future; cancelling it releases this caller's participation in shared requests. */
    public fun getEndOfLifeDateAsync(): CompletableFuture<Instant?> = scope.future { getEndOfLifeDate() }

    /** A cancellable future; lookup failures complete it exceptionally. */
    public fun getIssuerFromX509AKIAsync(x509aki: String): CompletableFuture<Issuer?> = scope.future { getIssuerFromX509AKI(x509aki) }

    /** A cancellable Java future for PEM input. */
    @JvmOverloads
    public fun resolveCertificateTrustAsync(
        certificate: String? = null,
        options: ResolveCertificateTrustOptions = ResolveCertificateTrustOptions(),
    ): CompletableFuture<CertificateTrustResult> {
        val snapshot = options.copy(trustLists = freeze(options.trustLists))
        return scope.future { resolveCertificateTrust(certificate, snapshot) }
    }

    /** A cancellable Java future for parsed input. */
    @JvmOverloads
    public fun resolveCertificateTrustAsync(
        certificate: X509Certificate,
        options: ResolveCertificateTrustOptions = ResolveCertificateTrustOptions(),
    ): CompletableFuture<CertificateTrustResult> {
        val snapshot = options.copy(trustLists = freeze(options.trustLists))
        return scope.future { resolveCertificateTrust(certificate, snapshot) }
    }

    /** Cancels operations and clears caches, leaving an application-supplied HTTP client open. */
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            fetcher.close()
            scope.cancel()
            if (ownsClient) {
                client.dispatcher.executorService.shutdown()
                client.connectionPool.evictAll()
                client.cache?.close()
            }
        }
    }
}
