package com.universalverify.consumer

import com.universalverify.trustedissuerregistry.Registry
import com.universalverify.trustedissuerregistry.RegistryOptions
import com.universalverify.trustedissuerregistry.RegistrySnapshot
import com.universalverify.trustedissuerregistry.UntrustedReason
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    Registry().use { registry ->
        val result = registry.resolveCertificateTrust()
        check(!result.trusted && result.untrustedReasons == listOf(UntrustedReason.CERTIFICATE_MISSING))
    }
    val issuer = checkNotNull(object {}.javaClass.getResourceAsStream("/registry-issuer.json")).bufferedReader().use { it.readText() }
    val snapshot = RegistrySnapshot.fromJson("{\"issuers\":[$issuer]}")
    val aki = checkNotNull(Regex("\"issuer_id\"\\s*:\\s*\"x509_aki:([A-Za-z0-9_-]+)\"").find(issuer)).groupValues[1]
    Registry(RegistryOptions(registrySnapshot = snapshot)).use { registry ->
        check(registry.getIssuerFromX509AKI(aki)?.signature != null)
        check(registry.getIssuerFromX509AKI("missing") == null)
        check(registry.getEndOfLifeDate() == null)
    }
    println("Published Kotlin consumer passed")
}
