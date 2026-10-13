package com.universalverify.consumer

import com.universalverify.trustedissuerregistry.Registry
import com.universalverify.trustedissuerregistry.UntrustedReason
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    Registry().use { registry ->
        val result = registry.resolveCertificateTrust()
        check(!result.trusted && result.untrustedReasons == listOf(UntrustedReason.CERTIFICATE_MISSING))
    }
    println("Published Kotlin consumer passed")
}
