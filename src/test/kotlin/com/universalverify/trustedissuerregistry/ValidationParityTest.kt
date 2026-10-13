package com.universalverify.trustedissuerregistry

import com.universalverify.trustedissuerregistry.internal.namesEqual
import com.universalverify.trustedissuerregistry.internal.registryJson
import kotlinx.serialization.json.*
import okhttp3.Interceptor
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.x500.X500Name
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.util.Base64

/** Signed JS-oracle regressions for name matching, CRL extensions, and PSS schemas. */
class ValidationParityTest {
    private val fixtures =
        registryJson
            .parseToJsonElement(
                javaClass.getResourceAsStream("/fixtures/validation.json")!!.bufferedReader().use { it.readText() },
            ).jsonObject

    private fun pem(name: String): String =
        fixtures
            .getValue("certificates")
            .jsonObject
            .getValue(name)
            .jsonPrimitive.content

    @TestFactory
    fun `trust validation matches JS including positive controls`() =
        fixtures.getValue("cases").jsonArray.map { entry ->
            val scenario = entry.jsonObject
            DynamicTest.dynamicTest(scenario.getValue("label").jsonPrimitive.content) {
                val crl =
                    Base64.getDecoder().decode(
                        fixtures
                            .getValue("crls")
                            .jsonObject
                            .getValue(scenario.getValue("crl").jsonPrimitive.content)
                            .jsonPrimitive.content,
                    )
                withClient(Interceptor { chain -> response(chain.request(), crl) }) { client ->
                    val options =
                        RegistryOptions(
                            listOf(UserTrustedIssuerCertificate(pem(scenario.getValue("issuer").jsonPrimitive.content))),
                            Fixtures.wire(scenario.getValue("mode").jsonPrimitive.content),
                        )
                    Registry.forTesting(options, client, Fixtures.clock).use { registry ->
                        val certificate = pem(scenario.getValue("input").jsonPrimitive.content)
                        val expected = registryJson.decodeFromJsonElement<CertificateTrustResult>(scenario.getValue("expected"))
                        assertEquals(expected, registry.resolveCertificateTrustBlocking(certificate))
                        assertEquals(expected, registry.resolveCertificateTrustAsync(parsePemCertificate(certificate)).get())
                    }
                }
            }
        }

    @TestFactory
    fun `certificate signature validation matches JS`() =
        fixtures.getValue("certificateSignatures").jsonArray.map { entry ->
            val scenario = entry.jsonObject
            DynamicTest.dynamicTest(scenario.getValue("input").jsonPrimitive.content) {
                val certificate = pem(scenario.getValue("input").jsonPrimitive.content)
                val issuer = pem(scenario.getValue("issuer").jsonPrimitive.content)
                val expected = scenario.getValue("expected").jsonPrimitive.boolean
                assertEquals(expected, verifyCertificateSignature(certificate, issuer))
                assertEquals(expected, verifyCertificateSignature(parsePemCertificate(certificate), parsePemCertificate(issuer)))
            }
        }

    @TestFactory
    fun `ordered name attributes and string normalization match JS`() =
        fixtures.getValue("nameComparisons").jsonArray.map { entry ->
            val scenario = entry.jsonObject
            DynamicTest.dynamicTest(scenario.getValue("label").jsonPrimitive.content) {
                fun name(field: String): X500Name =
                    X500Name.getInstance(
                        ASN1Primitive.fromByteArray(Base64.getDecoder().decode(scenario.getValue(field).jsonPrimitive.content)),
                    )
                assertEquals(scenario.getValue("expected").jsonPrimitive.boolean, namesEqual(name("left"), name("right")))
            }
        }
}
