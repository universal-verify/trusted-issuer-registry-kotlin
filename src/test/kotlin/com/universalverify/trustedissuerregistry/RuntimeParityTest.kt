package com.universalverify.trustedissuerregistry

import com.universalverify.trustedissuerregistry.internal.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import okhttp3.Interceptor
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.security.Security
import java.util.Base64
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

class RuntimeParityTest {
    @TestFactory
    fun `trust decisions match fixed JS oracle`() =
        Fixtures.data.getValue("cases").jsonArray.map { entry ->
            val scenario = entry.jsonObject
            DynamicTest.dynamicTest(scenario.getValue("label").jsonPrimitive.content) {
                val handler =
                    Interceptor { chain ->
                        val request = chain.request()
                        val registry = scenario["registry"]?.jsonPrimitive?.content
                        when {
                            request.url.encodedPath.contains("/issuers/") ->
                                if (registry !=
                                    null
                                ) {
                                    response(request, Fixtures.issuer(registry).toByteArray())
                                } else {
                                    response(request, byteArrayOf(), scenario.getValue("status").jsonPrimitive.int)
                                }
                            scenario.getValue("crl").jsonPrimitive.content == "unavailable" -> response(request, byteArrayOf(), 503)
                            scenario.getValue("crl").jsonPrimitive.content == "malformed" -> response(request, "bad CRL".toByteArray())
                            else ->
                                response(
                                    request,
                                    Fixtures.crl(
                                        scenario
                                            .getValue(
                                                if (request.url.encodedPath.endsWith("second.crl")) "secondCRL" else "crl",
                                            ).jsonPrimitive.content,
                                    ),
                                )
                        }
                    }
                withClient(handler) { client ->
                    Registry.forTesting(Fixtures.options(scenario), client, Fixtures.clock, Fixtures.pem("testSigning")).use { registry ->
                        val input = scenario["input"]?.jsonPrimitive?.contentOrNull?.let { Fixtures.pem(it) }
                        val result = runBlocking { registry.resolveCertificateTrust(input, Fixtures.resolutionOptions(scenario)) }
                        val expected = registryJson.decodeFromJsonElement<CertificateTrustResult>(scenario.getValue("expected"))
                        assertEquals(expected, result)
                        if (input !=
                            null
                        ) {
                            assertEquals(
                                result,
                                runBlocking {
                                    registry.resolveCertificateTrust(
                                        parsePemCertificate(input),
                                        Fixtures.resolutionOptions(scenario),
                                    )
                                },
                            )
                        }
                    }
                }
            }
        }

    @TestFactory
    fun `signature parameters match JS`() =
        Fixtures.data.getValue("signatures").jsonArray.map { entry ->
            val fixture = entry.jsonObject
            DynamicTest.dynamicTest(fixture.toString().take(100)) {
                val hash = HashAlgorithm.entries.first { it.algorithmName == fixture.getValue("hash").jsonPrimitive.content }
                val options =
                    when (fixture.getValue("algorithm").jsonPrimitive.content) {
                        "ecdsa" ->
                            if (fixture["useDefault"]?.jsonPrimitive?.boolean ==
                                true
                            ) {
                                null
                            } else {
                                SignatureVerificationOptions.Ecdsa(hash)
                            }
                        "rsaPSS" -> SignatureVerificationOptions.RsaPss(hash, fixture.getValue("saltLength").jsonPrimitive.int)
                        else -> SignatureVerificationOptions.RsaPkcs1v15(hash)
                    }
                val pem = Fixtures.pem(fixture.getValue("certificate").jsonPrimitive.content)
                val signature = fixture.getValue("signature").jsonPrimitive.content
                assertTrue(verifySignatureWithPem(pem, signature, Fixtures.signatureData, options))
                assertFalse(verifySignatureWithPem(pem, signature, Fixtures.signatureData + 0, options))
            }
        }

    @TestFactory
    fun `canonical bytes match JS`() =
        Fixtures.data.getValue("canonical").jsonArray.map { entry ->
            val fixture = entry.jsonObject
            DynamicTest.dynamicTest(fixture.getValue("input").jsonPrimitive.content) {
                fixture["expectedBytes"]?.let {
                    val value = registryJson.parseToJsonElement(fixture.getValue("input").jsonPrimitive.content)
                    assertArrayEquals(Base64.getDecoder().decode(it.jsonPrimitive.content), encodeUtf8(CanonicalJson.stringify(value)))
                }
                assertEquals(
                    fixture.getValue("expected").jsonPrimitive.content,
                    CanonicalJson.stringify(registryJson.parseToJsonElement(fixture.getValue("input").jsonPrimitive.content)),
                )
            }
        }

    @Test
    fun `production signing certificate verifies real fixture and rejects tampering`() {
        val bytes = Fixtures.actualIssuerJson.toByteArray()
        assertNotNull(decodeVerifiedIssuer(bytes))
        val value = registryJson.parseToJsonElement(Fixtures.actualIssuerJson).jsonObject
        val altered = JsonObject(value + ("display" to JsonObject(mapOf("name" to JsonPrimitive("Tampered")))))
        assertNull(decodeVerifiedIssuer(altered.toString().toByteArray()))
        assertEquals(
            RegistryErrorCategory.MALFORMED_RESPONSE,
            assertThrows(RegistryException::class.java) {
                decodeVerifiedIssuer("{".toByteArray())
            }.category,
        )
    }

    @Test
    fun `certificate helpers preserve encoding and do not change providers`() {
        val providers = Security.getProviders().map { it.name }
        val issuer = parsePemCertificate(Fixtures.pem("issuer"))
        val leaf = parsePemCertificate(Fixtures.pem("leaf"))
        assertEquals(Fixtures.pem("leaf"), certificateToPem(leaf))
        assertTrue(verifyCertificateSignature(leaf, issuer))
        assertTrue(verifyCertificateSignature(Fixtures.pem("leaf"), issuer))
        assertTrue(verifyCertificateSignature(leaf, Fixtures.pem("issuer")))
        assertFalse(verifyCertificateSignature(leaf, parsePemCertificate(Fixtures.pem("wrongName"))))
        assertTrue(verifyCertificateSignature(leaf, parsePemCertificate(Fixtures.pem("expiredIssuer"))))
        assertEquals(providers, Security.getProviders().map { it.name })
    }

    @Test
    fun `PSS-only keys retain identifiers and support nonstandard salt lengths`() {
        val pssOnly = Fixtures.pem("pssOnly")
        assertEquals(pssOnly, certificateToPem(parsePemCertificate(pssOnly)))
        Fixtures.data
            .getValue("signatures")
            .jsonArray
            .map { it.jsonObject }
            .filter { it["certificate"]?.jsonPrimitive?.content == "RSA-PSS-SHA-256" }
            .forEach { fixture ->
                assertTrue(
                    verifySignatureWithPem(
                        pssOnly,
                        fixture.getValue("signature").jsonPrimitive.content,
                        Fixtures.signatureData,
                        SignatureVerificationOptions.RsaPss(HashAlgorithm.SHA256, fixture.getValue("saltLength").jsonPrimitive.int),
                    ),
                )
            }
        assertThrows(RegistryException::class.java) {
            verifySignatureWithPem(pssOnly, "AA==", Fixtures.signatureData, SignatureVerificationOptions.RsaPkcs1v15(HashAlgorithm.SHA256))
        }
    }

    @Test
    fun `malformed DER and unsupported options fail without alternatives`() {
        assertThrows(RegistryException::class.java) { parsePemCertificate("bad certificate") }
        assertThrows(IllegalArgumentException::class.java) {
            Registry(RegistryOptions.builder().addTrustedIssuerCertificate("bad certificate").build())
        }
        assertThrows(IllegalArgumentException::class.java) {
            Registry(RegistryOptions(listOf(UserTrustedIssuerCertificate(Fixtures.pem("noSKI")))))
        }
        assertThrows(
            RegistryException::class.java,
        ) { verifySignatureWithPem(Fixtures.pem("RSA-PSS-SHA-256"), "AA==", Fixtures.signatureData) }
        val valid =
            Base64.getDecoder().decode(
                Fixtures.data
                    .getValue("signatures")
                    .jsonArray
                    .first()
                    .jsonObject
                    .getValue("signature")
                    .jsonPrimitive.content,
            )
        for (bytes in listOf(byteArrayOf(), valid.dropLast(1).toByteArray(), valid + 0, byteArrayOf(0x30, 0))) {
            assertThrows(RegistryException::class.java) {
                verifySignatureWithPem(Fixtures.pem("ec-P-256"), Base64.getEncoder().encodeToString(bytes), Fixtures.signatureData)
            }
        }
    }

    @Test
    fun `Java facades and option snapshots use the same implementation`() {
        val list = mutableListOf(UserTrustedIssuerCertificate(Fixtures.pem("issuer")))
        Registry(RegistryOptions(list)).use { registry ->
            list.clear()
            val result = registry.resolveCertificateTrustBlocking(Fixtures.pem("leaf"))
            assertTrue(result.trusted)
            assertEquals(result, registry.resolveCertificateTrustAsync(Fixtures.pem("leaf")).get())
            assertThrows(UnsupportedOperationException::class.java) { (result.issuer!!.certificates as MutableList).clear() }
            assertFalse(registry.resolveCertificateTrustBlocking().trusted)
        }
    }

    @Test
    fun `Java futures preserve operational exceptions and HTTP status`() {
        withClient(Interceptor { chain -> response(chain.request(), byteArrayOf(), 503) }) { client ->
            Registry(httpClient = client).use { registry ->
                val lookup = registry.getIssuerFromX509AKIAsync("unavailable")
                val error = assertThrows(ExecutionException::class.java) { lookup.get(5, TimeUnit.SECONDS) }.cause as RegistryException
                assertEquals(RegistryErrorCategory.HTTP_ERROR, error.category)
                assertEquals(503, error.httpStatus)
                val malformed = registry.resolveCertificateTrustAsync("invalid PEM")
                val parseError =
                    assertThrows(
                        ExecutionException::class.java,
                    ) { malformed.get(5, TimeUnit.SECONDS) }.cause as RegistryException
                assertEquals(RegistryErrorCategory.MALFORMED_CERTIFICATE, parseError.category)
            }
        }
    }
}
