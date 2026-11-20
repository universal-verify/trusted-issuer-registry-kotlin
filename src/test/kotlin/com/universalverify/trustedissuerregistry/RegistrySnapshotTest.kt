package com.universalverify.trustedissuerregistry

import com.universalverify.trustedissuerregistry.internal.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.*
import okhttp3.Interceptor
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

private object SnapshotFixtures {
    val data =
        registryJson
            .parseToJsonElement(
                javaClass.getResourceAsStream("/fixtures/snapshot.json")!!.bufferedReader().readText(),
            ).jsonObject
    val clock: Clock = Clock.fixed(Instant.parse(data.getValue("now").jsonPrimitive.content), ZoneOffset.UTC)
    val aki = data.getValue("aki").jsonPrimitive.content
    val records = data.getValue("snapshots").jsonObject

    fun snapshot(name: String): RegistrySnapshot = RegistrySnapshot.fromJson(records.getValue(name).toString())

    fun pem(name: String): String =
        data
            .getValue("certificates")
            .jsonObject
            .getValue(name)
            .jsonPrimitive.content
}

class RegistrySnapshotTest {
    @TestFactory
    fun `snapshot trust decisions match the fixed JS oracle`() =
        SnapshotFixtures.data.getValue("cases").jsonArray.map { entry ->
            val scenario = entry.jsonObject
            DynamicTest.dynamicTest(scenario.getValue("label").jsonPrimitive.content) {
                val requests = AtomicInteger()
                withClient(
                    Interceptor { chain ->
                        assertFalse(
                            chain
                                .request()
                                .url.host
                                .endsWith("jsdelivr.net"),
                            "Snapshot attempted a registry request",
                        )
                        requests.incrementAndGet()
                        response(chain.request(), byteArrayOf(), 404)
                    },
                ) { client ->
                    val options =
                        Fixtures.options(scenario, SnapshotFixtures::pem).copy(
                            registrySnapshot = SnapshotFixtures.snapshot(scenario.getValue("snapshot").jsonPrimitive.content),
                            cacheEnabled = false,
                            cacheTtl = java.time.Duration.ZERO,
                        )
                    Registry.forTesting(options, client, SnapshotFixtures.clock).use { registry ->
                        val pem = scenario["input"]?.jsonPrimitive?.contentOrNull?.let(SnapshotFixtures::pem)
                        val expected = registryJson.decodeFromJsonElement<CertificateTrustResult>(scenario.getValue("expected"))
                        assertEquals(expected, registry.resolveCertificateTrustBlocking(pem, Fixtures.resolutionOptions(scenario)))
                        assertEquals(scenario.getValue("crlRequests").jsonPrimitive.int, requests.get())
                        if (pem != null) {
                            assertEquals(
                                expected,
                                registry.resolveCertificateTrustAsync(parsePemCertificate(pem), Fixtures.resolutionOptions(scenario)).get(),
                            )
                        }
                        assertNull(registry.getEndOfLifeDateBlocking())
                        assertNull(registry.getEndOfLifeDateAsync().get())
                    }
                }
            }
        }

    @Test
    fun `snapshot records preserve signatures and return independent immutable values`() {
        withClient(Interceptor { error("Snapshot must not fetch") }) { client ->
            val input = SnapshotFixtures.snapshot("valid")
            assertEquals("informational", input.version)
            repeat(2) {
                Registry.forTesting(RegistryOptions(registrySnapshot = input), client, SnapshotFixtures.clock).use { registry ->
                    val first = registry.getIssuerFromX509AKIBlocking(SnapshotFixtures.aki)!!
                    val second = registry.getIssuerFromX509AKIAsync(SnapshotFixtures.aki).get()!!
                    assertNotNull(first.signature)
                    assertEquals(first, second)
                    assertNotSame(first, second)
                    assertNotSame(first.certificates, second.certificates)
                    assertThrows(UnsupportedOperationException::class.java) { (first.certificates as MutableList).clear() }
                    assertThrows(
                        UnsupportedOperationException::class.java,
                    ) { (first.certificates.first().trustLists as MutableList).clear() }
                    assertEquals(first, registry.getIssuerFromX509AKIBlocking(SnapshotFixtures.aki))
                    assertNull(registry.getIssuerFromX509AKIBlocking("missing"))
                }
                assertFalse(client.dispatcher.executorService.isShutdown)
            }
        }
    }

    @Test
    fun `certificate-less signed issuer records remain available`() {
        val record =
            SnapshotFixtures.records
                .getValue("tombstone")
                .jsonObject
                .getValue("issuers")
                .jsonArray
                .single()
                .jsonObject
        withClient(Interceptor { error("Tombstones must not fetch") }) { client ->
            Registry
                .forTesting(
                    RegistryOptions(registrySnapshot = SnapshotFixtures.snapshot("tombstone")),
                    client,
                    SnapshotFixtures.clock,
                ).use {
                    val issuer =
                        it.getIssuerFromX509AKIBlocking(
                            record
                                .getValue("issuer_id")
                                .jsonPrimitive.content
                                .removePrefix("x509_aki:"),
                        )!!
                    assertEquals(registryJson.decodeFromJsonElement<Issuer>(record), issuer)
                    assertTrue(issuer.certificates.isEmpty())
                }
        }
    }

    @TestFactory
    fun `malformed snapshot configuration is rejected`() =
        listOf(
            "{",
            "null",
            "[]",
            "{}",
            "{\"issuers\":null}",
            "{\"version\":null,\"issuers\":[]}",
            "{\"version\":3,\"issuers\":[]}",
            "{\"issuers\":[null]}",
        ).plus(
            listOf(
                mapOf("issuer_id" to JsonPrimitive("unsupported:issuer")),
                mapOf("issuer_id" to JsonPrimitive("x509_aki:")),
                mapOf("issuer_id" to JsonPrimitive("x509_aki:abc\n")),
                mapOf("issuer_id" to JsonPrimitive("x509_aki:abc\r\n")),
                mapOf("certificates" to JsonNull),
                mapOf("signature" to JsonNull),
                mapOf("signature" to JsonPrimitive(123)),
                mapOf("signature" to JsonPrimitive("")),
            ).map { changes ->
                val record =
                    SnapshotFixtures.records
                        .getValue("valid")
                        .jsonObject
                        .getValue("issuers")
                        .jsonArray
                        .single()
                        .jsonObject
                JsonObject(mapOf("issuers" to JsonArray(listOf(JsonObject(record + changes))))).toString()
            },
        ).map { json ->
            DynamicTest.dynamicTest(
                json.take(80),
            ) { assertThrows(IllegalArgumentException::class.java) { RegistrySnapshot.fromJson(json) } }
        }

    @Test
    fun `duplicate IDs fail while empty snapshots and absent versions are valid`() {
        val record =
            SnapshotFixtures.records
                .getValue("valid")
                .jsonObject
                .getValue("issuers")
                .jsonArray
                .single()
        val duplicate = JsonObject(mapOf("issuers" to JsonArray(listOf(record, record))))
        assertThrows(IllegalArgumentException::class.java) { RegistrySnapshot.fromJson(duplicate.toString()) }
        assertNull(RegistrySnapshot.fromJson("{\"issuers\":[]}").version)
        val empty = RegistrySnapshot.fromJson("{\"version\":\"\",\"issuers\":[]}")
        assertEquals("", empty.version)
        withClient(Interceptor { error("Empty snapshots must not fetch") }) { client ->
            Registry(RegistryOptions.builder().registrySnapshot(empty).build(), client).use {
                assertNull(it.getIssuerFromX509AKIBlocking(SnapshotFixtures.aki))
                assertNull(it.getEndOfLifeDateBlocking())
            }
        }
    }

    @Test
    fun `invalid snapshot signatures fail direct lookups even with a local issuer`() {
        val options =
            RegistryOptions
                .builder()
                .registrySnapshot(SnapshotFixtures.snapshot("tampered"))
                .addTrustedIssuerCertificate(SnapshotFixtures.pem("issuer"))
                .build()
        withClient(Interceptor { error("Invalid signatures must not fall back to the CDN") }) { client ->
            Registry(options, client).use { registry ->
                val error = assertThrows(RegistryException::class.java) { registry.getIssuerFromX509AKIBlocking(SnapshotFixtures.aki) }
                assertEquals(RegistryErrorCategory.CRYPTOGRAPHIC_ERROR, error.category)
                val async = assertThrows(ExecutionException::class.java) { registry.getIssuerFromX509AKIAsync(SnapshotFixtures.aki).get() }
                assertSame(error, async.cause)
            }
        }
    }

    @Test
    fun `unknown fields are verified before typed conversion`() {
        val record = SnapshotFixtures.data.getValue("unknownFieldsIssuer").jsonObject
        val signingCertificate =
            SnapshotFixtures.data
                .getValue("signingCertificate")
                .jsonPrimitive.content
        withClient(Interceptor { error("Signed fields must not fetch") }) { client ->
            for (tampered in listOf(false, true)) {
                val value = if (tampered) JsonObject(record + ("future" to JsonPrimitive("changed"))) else record
                val input = RegistrySnapshot.fromJson(JsonObject(mapOf("issuers" to JsonArray(listOf(value)))).toString())
                Registry.forTesting(RegistryOptions(registrySnapshot = input), client, SnapshotFixtures.clock, signingCertificate).use {
                    if (tampered) {
                        assertThrows(RegistryException::class.java) { it.getIssuerFromX509AKIBlocking(SnapshotFixtures.aki) }
                    } else {
                        assertEquals(
                            registryJson.decodeFromJsonElement<Issuer>(record),
                            it.getIssuerFromX509AKIBlocking(SnapshotFixtures.aki),
                        )
                    }
                }
            }
        }
    }

    @Test
    fun `concurrent verification survives one caller cancellation and is retained until close`() =
        runBlocking {
            val owner = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            val started = CountDownLatch(1)
            val release = CountDownLatch(1)
            val calls = AtomicInteger()
            val source =
                RegistrySnapshotSource(SnapshotFixtures.snapshot("valid"), owner, PUBLIC_SIGNING_CERT) { record, key ->
                    calls.incrementAndGet()
                    started.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                    decodeVerifiedIssuer(record, key)
                }
            try {
                val cancelled = async(Dispatchers.Default) { source.get(SnapshotFixtures.aki) }
                assertTrue(started.await(5, TimeUnit.SECONDS))
                val others = List(10) { async { source.get(SnapshotFixtures.aki) } }
                cancelled.cancelAndJoin()
                release.countDown()
                val results = others.awaitAll()
                assertTrue(results.all { it == results.first() && it != null })
                assertEquals(results.first(), source.get(SnapshotFixtures.aki))
                assertEquals(1, calls.get())
                source.close()
                assertThrows(IllegalStateException::class.java) { runBlocking { source.get(SnapshotFixtures.aki) } }
            } finally {
                release.countDown()
                source.close()
                owner.cancel()
            }
        }

    @Test
    fun `failed verification is shared and memoized`() =
        runBlocking {
            val owner = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            val calls = AtomicInteger()
            val source =
                RegistrySnapshotSource(SnapshotFixtures.snapshot("tampered"), owner, PUBLIC_SIGNING_CERT) { _, _ ->
                    calls.incrementAndGet()
                    null
                }
            try {
                List(10) {
                    async {
                        assertThrows(RegistryException::class.java) { runBlocking { source.get(SnapshotFixtures.aki) } }
                    }
                }.awaitAll()
                assertEquals(1, calls.get())
            } finally {
                source.close()
                owner.cancel()
            }
        }

    @Test
    fun `null snapshot builder restores live lookups`() {
        val requests = AtomicInteger()
        withClient(
            Interceptor { chain ->
                requests.incrementAndGet()
                response(chain.request(), byteArrayOf(), 404)
            },
        ) { client ->
            val options =
                RegistryOptions
                    .builder()
                    .registrySnapshot(SnapshotFixtures.snapshot("empty"))
                    .registrySnapshot(null)
                    .build()
            Registry(options, client).use {
                assertNull(it.getIssuerFromX509AKIBlocking(SnapshotFixtures.aki))
                assertNull(it.getEndOfLifeDateBlocking())
            }
        }
        assertEquals(2, requests.get())
    }
}
