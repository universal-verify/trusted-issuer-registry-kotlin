package com.universalverify.trustedissuerregistry.internal

import com.universalverify.trustedissuerregistry.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.JsonObject
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException
import java.time.Clock
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.time.toKotlinDuration

internal enum class FetchPurpose { ISSUER, DEPRECATION, CRL }

internal data class CachedResponse(
    val status: Int,
    val issuer: Issuer? = null,
    val deprecation: JsonObject? = null,
    val crl: ParsedCrl? = null,
    val error: RegistryException? = null,
) {
    val ok: Boolean get() = status in 200..299
}

internal class CachedFetcher(
    private val options: RegistryOptions,
    client: OkHttpClient,
    private val scope: CoroutineScope,
    private val clock: Clock,
    private val signingCertificate: String = PUBLIC_SIGNING_CERT,
) {
    // Deadlines belong to consumers, not a shared transport call. Preserve other client settings.
    private val client =
        client
            .newBuilder()
            .callTimeout(0, TimeUnit.MILLISECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .build()

    private data class Download(
        val status: Int,
        val bytes: ByteArray?,
    )

    private data class Entry(
        val value: CachedResponse,
        val expiresAt: Long,
    )

    private class Shared(
        val result: CompletableDeferred<Download>,
    ) {
        var consumers = 0
        lateinit var job: Job
    }

    private val lock = Any()
    private val cache = LinkedHashMap<Pair<FetchPurpose, String>, Entry>(16, 0.75f, true)
    private val inFlight = mutableMapOf<String, Shared>()
    private var lastSweepAt = clock.millis()
    private var closed = false
    internal val cacheSize: Int get() = synchronized(lock) { cache.size }
    internal val inFlightSize: Int get() = synchronized(lock) { inFlight.size }

    suspend fun fetch(
        url: String,
        purpose: FetchPurpose,
    ): CachedResponse {
        val cached =
            synchronized(lock) {
                check(!closed) { "Registry is closed" }
                if (!options.cacheEnabled) {
                    null
                } else {
                    sweep()
                    val key = purpose to url
                    cache[key]?.let {
                        if (it.expiresAt <= clock.millis()) {
                            cache.remove(key)
                            null
                        } else {
                            it.value
                        }
                    }
                }
            }
        if (cached != null) return cached
        val download = fetchShared(url)
        var expiration: Long? = null
        val result =
            if (download.status in 200..299) {
                val bytes = download.bytes!!
                when (purpose) {
                    FetchPurpose.ISSUER -> CachedResponse(download.status, issuer = decodeVerifiedIssuer(bytes, signingCertificate))
                    FetchPurpose.DEPRECATION ->
                        try {
                            CachedResponse(
                                download.status,
                                deprecation = registryJson.parseToJsonElement(decodeJsonText(bytes)) as JsonObject,
                            )
                        } catch (error: Exception) {
                            CachedResponse(
                                download.status,
                                error = RegistryException(RegistryErrorCategory.MALFORMED_RESPONSE, "Malformed deprecation notice", error),
                            )
                        }
                    FetchPurpose.CRL ->
                        try {
                            val crl = parseCrl(bytes)
                            expiration = crl.nextUpdate?.time?.takeIf { it > clock.millis() }
                            CachedResponse(download.status, crl = crl)
                        } catch (error: Exception) {
                            CachedResponse(
                                download.status,
                                error = RegistryException(RegistryErrorCategory.MALFORMED_RESPONSE, "Malformed CRL", error),
                            )
                        }
                }
            } else {
                CachedResponse(download.status)
            }
        if (result.status == 404 || result.ok && (purpose != FetchPurpose.ISSUER || result.issuer != null)) {
            synchronized(lock) {
                if (!closed && options.cacheEnabled) {
                    sweep()
                    val expiresAt = minOf(clock.millis() + options.cacheTtl.toMillis(), expiration ?: Long.MAX_VALUE)
                    val key = purpose to url
                    if (expiresAt > clock.millis()) {
                        cache[key] = Entry(result, expiresAt)
                        if (cache.size > 1024) cache.remove(cache.keys.first())
                    } else {
                        cache.remove(key)
                    }
                }
            }
        }
        return result
    }

    private fun sweep() {
        val now = clock.millis()
        if (now - lastSweepAt < 60_000) return
        lastSweepAt = now
        cache.entries.removeAll { it.value.expiresAt <= now }
    }

    private suspend fun fetchShared(url: String): Download {
        val request =
            synchronized(lock) {
                check(!closed) { "Registry is closed" }
                inFlight
                    .getOrPut(url) {
                        val shared = Shared(CompletableDeferred(scope.coroutineContext[Job]))
                        shared.job =
                            scope.launch(start = CoroutineStart.LAZY) {
                                try {
                                    shared.result.complete(download(url))
                                } catch (error: CancellationException) {
                                    shared.result.cancel(error)
                                    throw error
                                } catch (error: Exception) {
                                    shared.result.completeExceptionally(error)
                                } finally {
                                    synchronized(lock) { if (inFlight[url] === shared) inFlight.remove(url) }
                                }
                            }
                        shared
                    }.also { it.consumers++ }
            }
        request.job.start()
        try {
            return withTimeoutOrNull(options.timeout.toKotlinDuration()) { request.result.await() }
                ?: throw RegistryException(RegistryErrorCategory.TIMEOUT, "Request timed out after ${options.timeout}")
        } finally {
            synchronized(lock) {
                request.consumers--
                if (request.consumers == 0 && inFlight[url] === request) {
                    inFlight.remove(url)
                    request.job.cancel()
                    request.result.cancel()
                }
            }
        }
    }

    private suspend fun download(url: String): Download =
        suspendCancellableCoroutine { continuation ->
            val call = client.newCall(Request.Builder().url(url).build())
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(
                object : Callback {
                    override fun onFailure(
                        call: Call,
                        e: IOException,
                    ) {
                        if (continuation.isActive) {
                            continuation.resumeWithException(
                                RegistryException(RegistryErrorCategory.NETWORK_ERROR, "Unable to download $url", e),
                            )
                        }
                    }

                    override fun onResponse(
                        call: Call,
                        response: Response,
                    ) {
                        try {
                            val result = response.use { Download(it.code, if (it.isSuccessful) it.body.bytes() else null) }
                            if (continuation.isActive) continuation.resume(result)
                        } catch (error: Exception) {
                            if (continuation.isActive) {
                                continuation.resumeWithException(
                                    RegistryException(RegistryErrorCategory.NETWORK_ERROR, "Unable to read response body", error),
                                )
                            }
                        }
                    }
                },
            )
        }

    fun close() =
        synchronized(lock) {
            if (!closed) {
                closed = true
                cache.clear()
                inFlight.values.toList().forEach {
                    it.job.cancel()
                    it.result.cancel()
                }
                inFlight.clear()
            }
        }
}
