package com.universalverify.trustedissuerregistry.internal

import com.universalverify.trustedissuerregistry.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.JsonObject

/** Verification belongs to the registry lifecycle, independently of HTTP cache settings. */
internal class RegistrySnapshotSource(
    snapshot: RegistrySnapshot,
    private val scope: CoroutineScope,
    private val signingCertificate: String,
    private val verifyIssuer: (JsonObject, String) -> Issuer? = ::decodeVerifiedIssuer,
) {
    private val lock = Any()
    private var issuers = snapshot.issuers
    private val verified = mutableMapOf<String, Deferred<Issuer>>()
    private var closed = false

    suspend fun get(aki: String): Issuer? {
        val result =
            synchronized(lock) {
                check(!closed) { "Registry is closed" }
                val issuer = issuers[aki] ?: return null
                verified.getOrPut(aki) {
                    // Starting on await keeps cryptography outside the state lock.
                    scope.async(start = CoroutineStart.LAZY) {
                        verifyIssuer(issuer, signingCertificate)
                            ?: throw RegistryException(
                                RegistryErrorCategory.CRYPTOGRAPHIC_ERROR,
                                "Invalid registry snapshot signature for ${issuer["issuer_id"]}",
                            )
                    }
                }
            }
        return snapshot(result.await())
    }

    fun close() {
        synchronized(lock) {
            closed = true
            verified.values.forEach { it.cancel() }
            verified.clear()
            issuers = emptyMap()
        }
    }
}
