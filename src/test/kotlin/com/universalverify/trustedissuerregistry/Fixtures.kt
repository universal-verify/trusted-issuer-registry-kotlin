package com.universalverify.trustedissuerregistry

import com.universalverify.trustedissuerregistry.internal.registryJson
import kotlinx.serialization.json.*
import okhttp3.*
import okhttp3.ResponseBody.Companion.toResponseBody
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

internal object Fixtures {
    val data =
        registryJson
            .parseToJsonElement(
                javaClass.getResourceAsStream("/fixtures/runtime.json")!!.bufferedReader().readText(),
            ).jsonObject
    val clock: Clock = Clock.fixed(Instant.parse(data.getValue("now").jsonPrimitive.content), ZoneOffset.UTC)

    fun pem(name: String) =
        data
            .getValue("certificates")
            .jsonObject
            .getValue(name)
            .jsonPrimitive.content

    fun crl(name: String): ByteArray =
        Base64.getDecoder().decode(
            data
                .getValue("crls")
                .jsonObject
                .getValue(name)
                .jsonPrimitive.content,
        )

    fun issuer(name: String) =
        data
            .getValue("registryIssuers")
            .jsonObject
            .getValue(name)
            .toString()

    val actualIssuerJson get() = data.getValue("actualIssuerJSON").jsonPrimitive.content
    val signatureData get() = Base64.getDecoder().decode(data.getValue("signatureData").jsonPrimitive.content)

    inline fun <reified T> wire(value: String): T where T : Enum<T>, T : WireValue = enumValues<T>().first { it.wireValue == value }

    fun options(scenario: JsonObject): RegistryOptions {
        val custom =
            scenario.getValue("custom").jsonArray.map { entry ->
                if (entry is JsonPrimitive) {
                    UserTrustedIssuerCertificate(pem(entry.content))
                } else {
                    val value = entry.jsonObject
                    val metadata = value["entity_metadata"]?.jsonObject
                    val display = value["display"]?.jsonObject
                    UserTrustedIssuerCertificate(
                        pem(value.getValue("data").jsonPrimitive.content),
                        trustScopes = value["trust_scopes"]?.jsonArray?.map { wire<TrustScope>(it.jsonPrimitive.content) }.orEmpty(),
                        entityType = value["entity_type"]?.jsonPrimitive?.content?.let { wire<EntityType>(it) } ?: EntityType.OTHER,
                        entityMetadata =
                            EntityMetadata(
                                metadata?.get("country")?.jsonPrimitive?.content,
                                metadata?.get("region")?.jsonPrimitive?.content,
                            ),
                        display =
                            IssuerDisplayOverrides(
                                display?.get("name")?.jsonPrimitive?.content,
                                display?.get("logo")?.jsonPrimitive?.content,
                                display?.get("description")?.jsonPrimitive?.content,
                            ),
                    )
                }
            }
        return RegistryOptions(custom, wire(scenario.getValue("mode").jsonPrimitive.content))
    }

    fun resolutionOptions(scenario: JsonObject) =
        ResolveCertificateTrustOptions(
            scenario.getValue("trustLists").jsonArray.map { wire<TrustList>(it.jsonPrimitive.content) },
            scenario["scope"]?.jsonPrimitive?.content?.let { wire<TrustScope>(it) },
        )
}

internal fun response(
    request: Request,
    body: ByteArray,
    status: Int = 200,
): Response =
    Response
        .Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(status)
        .message("Fixture")
        .body(body.toResponseBody())
        .build()

internal inline fun <T> withClient(
    interceptor: Interceptor,
    block: (OkHttpClient) -> T,
): T {
    val client = OkHttpClient.Builder().addInterceptor(interceptor).build()
    return try {
        block(client)
    } finally {
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
    }
}
