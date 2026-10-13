package com.universalverify.trustedissuerregistry.internal

import kotlinx.serialization.json.Json
import java.util.Collections

internal const val MINOR_VERSION = "0.2"
internal const val REGISTRY_URL_BASE = "https://cdn.jsdelivr.net/npm/trusted-issuer-registry@$MINOR_VERSION"
internal val registryJson =
    Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }

internal fun <T> freeze(values: Collection<T>): List<T> = Collections.unmodifiableList(ArrayList(values))

internal const val PUBLIC_SIGNING_CERT = """-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIULVFa5+g4perqTRJKDErRMXThCmAwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYVW5pdmVyc2FsIFZlcmlmeSBSb290IENBMB4XDTI2MTAwMjEz
MzAyNFoXDTM2MDkyOTEzMzAyNFowIzEhMB8GA1UEAwwYVW5pdmVyc2FsIFZlcmlm
eSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfrzJarNNsjnyngbJ
ZSzXI5gM6x/36RRJ+/v3tle4jaVZ3hXI/lg4Qq/NPOzwxrEZQSOHebOBzg5C9msL
G+73zKNTMFEwHQYDVR0OBBYEFEr6yqRcHLSe64ERXXvnADhfgzkuMB8GA1UdIwQY
MBaAFEr6yqRcHLSe64ERXXvnADhfgzkuMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDRwAwRAIgLgTLhVKk/yv7aLvy2XNV224q4iFRL+26F/G3/MKF9dkCIGa4
jw4Og3tKk0nt09p7ZWpg4dOMYxnGL5L8kWM7UDIF
-----END CERTIFICATE-----"""
