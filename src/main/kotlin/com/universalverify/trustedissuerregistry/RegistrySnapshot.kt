package com.universalverify.trustedissuerregistry

import com.universalverify.trustedissuerregistry.internal.registryJson
import kotlinx.serialization.json.*
import java.util.Collections

/**
 * Immutable signed issuer records loaded from the JavaScript registry's `build/registry.json` format.
 * Signatures are verified when an issuer is first requested by a [Registry], before model conversion.
 */
public class RegistrySnapshot private constructor(
    /** Informational registry release version; it does not select or change the registry protocol. */
    public val version: String?,
    @get:JvmSynthetic internal val issuers: Map<String, JsonObject>,
) {
    public companion object {
        /**
         * Parses and structurally validates a snapshot, preserving unknown signed fields.
         * An empty issuer array is valid. Malformed JSON, records, or duplicate IDs throw [IllegalArgumentException].
         */
        @JvmStatic
        public fun fromJson(json: String): RegistrySnapshot {
            val value =
                try {
                    registryJson.parseToJsonElement(json) as? JsonObject
                        ?: throw IllegalArgumentException("Registry snapshot must be an object")
                } catch (error: Exception) {
                    throw IllegalArgumentException("Malformed registry snapshot JSON", error)
                }
            val version = value["version"]
            require(version == null || version is JsonPrimitive && version.isString) {
                "Registry snapshot version must be a string when present"
            }
            val records = value["issuers"] as? JsonArray
            require(records != null) { "Registry snapshot must contain an issuers array" }
            val issuers = linkedMapOf<String, JsonObject>()
            for (record in records) {
                val issuer = record as? JsonObject
                val identifier = issuer?.get("issuer_id") as? JsonPrimitive
                val match = identifier?.takeIf { it.isString }?.content?.let { ISSUER_ID.matchEntire(it) }
                val signature = issuer?.get("signature") as? JsonPrimitive
                require(
                    issuer != null &&
                        match != null &&
                        issuer["certificates"] is JsonArray &&
                        signature?.isString == true &&
                        signature.content.isNotEmpty(),
                ) {
                    "Registry snapshot entries must be signed X.509 issuer records with a certificates array"
                }
                val aki = match.groupValues[1]
                require(aki !in issuers) { "Duplicate registry snapshot issuer: ${issuer["issuer_id"]}" }
                issuers[aki] = issuer
            }
            return RegistrySnapshot(version?.jsonPrimitive?.content, Collections.unmodifiableMap(issuers))
        }

        private val ISSUER_ID = Regex("^x509_aki:([A-Za-z0-9_-]+)$")
    }
}
