package com.universalverify.trustedissuerregistry

import com.universalverify.trustedissuerregistry.internal.*
import kotlinx.coroutines.*
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

private class MutableClock(
    var millisValue: Long = 0,
) : Clock() {
    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId): Clock = this

    override fun instant(): Instant = Instant.ofEpochMilli(millisValue)

    override fun millis(): Long = millisValue
}

private inline fun <T> withFetcher(
    options: RegistryOptions = RegistryOptions(),
    clock: Clock = Fixtures.clock,
    client: OkHttpClient,
    block: (CachedFetcher) -> T,
): T {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val fetcher = CachedFetcher(options, client, scope, clock)
    return try {
        block(fetcher)
    } finally {
        fetcher.close()
        scope.cancel()
    }
}

class CachedFetcherTest {
    @Test
    fun `conclusive CRL releases unfinished body downloads`() =
        runBlocking {
            MockWebServer().use { server ->
                val secondStarted = CountDownLatch(1)
                server.dispatcher =
                    object : Dispatcher() {
                        override fun dispatch(request: RecordedRequest): MockResponse {
                            if (request.url.encodedPath.endsWith("second.crl")) {
                                secondStarted.countDown()
                                return MockResponse
                                    .Builder()
                                    .body(okio.Buffer().write(Fixtures.crl("valid")))
                                    .bodyDelay(3, TimeUnit.SECONDS)
                                    .build()
                            }
                            check(secondStarted.await(5, TimeUnit.SECONDS))
                            return MockResponse.Builder().body(okio.Buffer().write(Fixtures.crl("revoked"))).build()
                        }
                    }
                server.start()
                withClient(
                    Interceptor { chain ->
                        chain.proceed(
                            chain
                                .request()
                                .newBuilder()
                                .url(server.url(chain.request().url.encodedPath))
                                .build(),
                        )
                    },
                ) { client ->
                    withFetcher(RegistryOptions(cacheEnabled = false), client = client) { fetcher ->
                        val result =
                            withTimeout(2_000) {
                                checkCertificateRevocation(
                                    parseCertificate(Fixtures.pem("twoReasons")),
                                    parseCertificate(Fixtures.pem("issuer")),
                                    fetcher,
                                    Fixtures.clock,
                                )
                            }
                        assertEquals(RevocationResult(checked = true, revoked = true), result)
                        assertEquals(2, server.requestCount)
                        assertEquals(0, fetcher.inFlightSize)
                    }
                }
            }
        }

    @Test
    fun `404s are cached for every purpose while other HTTP errors retry`() =
        runBlocking {
            for (purpose in FetchPurpose.entries) {
                for (status in listOf(404, 500)) {
                    val count = AtomicInteger()
                    withClient(
                        Interceptor { chain ->
                            count.incrementAndGet()
                            response(chain.request(), byteArrayOf(), status)
                        },
                    ) { client ->
                        withFetcher(client = client) { fetcher ->
                            repeat(2) { assertEquals(status, fetcher.fetch("https://example.test/file", purpose).status) }
                            assertEquals(if (status == 404) 1 else 2, count.get())
                        }
                    }
                }
            }
        }

    @Test
    fun `invalid signatures and malformed issuer JSON are not admitted`() =
        runBlocking {
            for (body in listOf("{", Fixtures.actualIssuerJson.replace("\"issuer_id\"", "\"tampered_id\""))) {
                val count = AtomicInteger()
                withClient(
                    Interceptor { chain ->
                        count.incrementAndGet()
                        response(chain.request(), body.toByteArray())
                    },
                ) { client ->
                    withFetcher(client = client) { fetcher ->
                        repeat(2) { runCatching { fetcher.fetch("https://example.test/issuer", FetchPurpose.ISSUER) } }
                        assertEquals(2, count.get())
                        assertEquals(0, fetcher.cacheSize)
                    }
                }
            }
        }

    @Test
    fun `completed malformed CRL and deprecation downloads remain reusable`() =
        runBlocking {
            for (purpose in listOf(FetchPurpose.CRL, FetchPurpose.DEPRECATION)) {
                val count = AtomicInteger()
                withClient(
                    Interceptor { chain ->
                        count.incrementAndGet()
                        response(chain.request(), "malformed".toByteArray())
                    },
                ) { client ->
                    withFetcher(client = client) { fetcher ->
                        repeat(2) { assertNotNull(fetcher.fetch("https://example.test/file", purpose).error) }
                        assertEquals(1, count.get())
                    }
                }
            }
        }

    @Test
    fun `cache uses a bounded LRU and activity-triggered expiration`() =
        runBlocking {
            val counts = mutableMapOf<String, Int>()
            val clock = MutableClock()
            withClient(
                Interceptor { chain ->
                    val url = chain.request().url.toString()
                    counts[url] = (counts[url] ?: 0) + 1
                    response(chain.request(), "{}".toByteArray())
                },
            ) { client ->
                withFetcher(clock = clock, client = client) { fetcher ->
                    repeat(1024) { fetcher.fetch("https://example.test/$it", FetchPurpose.DEPRECATION) }
                    fetcher.fetch("https://example.test/0", FetchPurpose.DEPRECATION)
                    fetcher.fetch("https://example.test/1024", FetchPurpose.DEPRECATION)
                    assertEquals(1024, fetcher.cacheSize)
                    fetcher.fetch("https://example.test/0", FetchPurpose.DEPRECATION)
                    fetcher.fetch("https://example.test/1", FetchPurpose.DEPRECATION)
                    assertEquals(1, counts["https://example.test/0"])
                    assertEquals(2, counts["https://example.test/1"])
                    clock.millisValue = Duration.ofHours(24).toMillis() + 1
                    fetcher.fetch("https://example.test/new", FetchPurpose.DEPRECATION)
                    assertEquals(1, fetcher.cacheSize)
                }
            }
        }

    @Test
    fun `TTL zero and disabled caching retain no results`() =
        runBlocking {
            for (options in listOf(RegistryOptions(cacheTtl = Duration.ZERO), RegistryOptions(cacheEnabled = false))) {
                val count = AtomicInteger()
                withClient(
                    Interceptor { chain ->
                        count.incrementAndGet()
                        response(chain.request(), "{}".toByteArray())
                    },
                ) { client ->
                    withFetcher(options, client = client) { fetcher ->
                        repeat(2) { fetcher.fetch("https://example.test/file", FetchPurpose.DEPRECATION) }
                        assertEquals(2, count.get())
                        assertEquals(0, fetcher.cacheSize)
                    }
                }
            }
        }

    @Test
    fun `CRL nextUpdate shortens TTL only when in the future`() =
        runBlocking {
            for ((name, expires) in listOf("soon" to 5_000L, "stale" to Duration.ofHours(24).toMillis())) {
                val clock = MutableClock(Fixtures.clock.millis())
                val count = AtomicInteger()
                withClient(
                    Interceptor { chain ->
                        count.incrementAndGet()
                        response(chain.request(), Fixtures.crl(name))
                    },
                ) { client ->
                    withFetcher(clock = clock, client = client) { fetcher ->
                        fetcher.fetch("https://example.test/crl", FetchPurpose.CRL)
                        clock.millisValue += expires - 1
                        fetcher.fetch("https://example.test/crl", FetchPurpose.CRL)
                        assertEquals(1, count.get())
                        clock.millisValue += 1
                        fetcher.fetch("https://example.test/crl", FetchPurpose.CRL)
                        assertEquals(2, count.get())
                    }
                }
            }
        }

    @Test
    fun `one consumer timing out does not cancel a later shared body reader`() =
        runBlocking {
            MockWebServer().use { server ->
                server.enqueue(
                    MockResponse
                        .Builder()
                        .body("{}")
                        .bodyDelay(450, TimeUnit.MILLISECONDS)
                        .build(),
                )
                server.start()
                withClient(
                    Interceptor { chain ->
                        chain.proceed(
                            chain
                                .request()
                                .newBuilder()
                                .url(server.url("/file"))
                                .build(),
                        )
                    },
                ) { client ->
                    withFetcher(RegistryOptions(timeout = Duration.ofMillis(350), cacheEnabled = false), client = client) { fetcher ->
                        val first =
                            async(
                                start = CoroutineStart.UNDISPATCHED,
                            ) { runCatching { fetcher.fetch("https://example.test/file", FetchPurpose.DEPRECATION) } }
                        assertNotNull(server.takeRequest(5, TimeUnit.SECONDS))
                        delay(200)
                        val second = async { fetcher.fetch("https://example.test/file", FetchPurpose.DEPRECATION) }
                        assertEquals(RegistryErrorCategory.TIMEOUT, (first.await().exceptionOrNull() as RegistryException).category)
                        assertTrue(second.await().ok)
                        assertEquals(1, server.requestCount)
                    }
                }
            }
        }

    @Test
    fun `timed out downloads can retry and late cleanup cannot remove retries`() =
        runBlocking {
            MockWebServer().use { server ->
                server.enqueue(
                    MockResponse
                        .Builder()
                        .body("{}")
                        .bodyDelay(500, TimeUnit.MILLISECONDS)
                        .build(),
                )
                server.enqueue(MockResponse.Builder().body("{}").build())
                server.start()
                withClient(
                    Interceptor { chain ->
                        chain.proceed(
                            chain
                                .request()
                                .newBuilder()
                                .url(server.url("/file"))
                                .build(),
                        )
                    },
                ) { client ->
                    withFetcher(RegistryOptions(timeout = Duration.ofMillis(100)), client = client) { fetcher ->
                        val error =
                            runCatching {
                                fetcher.fetch(
                                    "https://example.test/file",
                                    FetchPurpose.DEPRECATION,
                                )
                            }.exceptionOrNull() as RegistryException
                        assertEquals(RegistryErrorCategory.TIMEOUT, error.category)
                        assertEquals(0, fetcher.inFlightSize)
                        assertTrue(fetcher.fetch("https://example.test/file", FetchPurpose.DEPRECATION).ok)
                        assertEquals(2, server.requestCount)
                    }
                }
            }
        }

    @Test
    fun `future cancellation is isolated and externally owned clients stay open`() {
        MockWebServer().use { server ->
            server.enqueue(
                MockResponse
                    .Builder()
                    .body("{\"version\":\"0.2\",\"end_of_life\":0}")
                    .bodyDelay(250, TimeUnit.MILLISECONDS)
                    .build(),
            )
            server.start()
            withClient(
                Interceptor { chain ->
                    chain.proceed(
                        chain
                            .request()
                            .newBuilder()
                            .url(server.url("/notice"))
                            .build(),
                    )
                },
            ) { client ->
                val registry = Registry(httpClient = client)
                val first = registry.getEndOfLifeDateAsync()
                assertNotNull(server.takeRequest(5, TimeUnit.SECONDS))
                val second = registry.getEndOfLifeDateAsync()
                // Wait until both consumers have entered without depending on scheduling latency.
                Thread.sleep(50)
                assertTrue(first.cancel(true))
                assertEquals(Instant.EPOCH, second.get(5, TimeUnit.SECONDS))
                assertEquals(1, server.requestCount)
                registry.close()
                registry.close()
                assertFalse(client.dispatcher.executorService.isShutdown)
                assertThrows(IllegalStateException::class.java) { registry.getEndOfLifeDateBlocking() }
            }
        }
    }

    @Test
    fun `shutdown cancels unfinished future and scope`() {
        MockWebServer().use { server ->
            server.enqueue(
                MockResponse
                    .Builder()
                    .body("{}")
                    .bodyDelay(500, TimeUnit.MILLISECONDS)
                    .build(),
            )
            server.start()
            withClient(
                Interceptor { chain ->
                    chain.proceed(
                        chain
                            .request()
                            .newBuilder()
                            .url(server.url("/file"))
                            .build(),
                    )
                },
            ) { client ->
                val registry = Registry(httpClient = client)
                val future = registry.getEndOfLifeDateAsync()
                assertNotNull(server.takeRequest(5, TimeUnit.SECONDS))
                registry.close()
                assertThrows(java.util.concurrent.CancellationException::class.java) { future.get(5, TimeUnit.SECONDS) }
            }
        }
    }
}
