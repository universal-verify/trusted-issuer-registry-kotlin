package com.universalverify.trustedissuerregistry

/** Stable categories of exceptional SDK failures, distinct from normal trust failure reasons. */
public enum class RegistryErrorCategory {
    MALFORMED_CERTIFICATE,
    MALFORMED_RESPONSE,
    UNSUPPORTED_ALGORITHM,
    CRYPTOGRAPHIC_ERROR,
    NETWORK_ERROR,
    HTTP_ERROR,
    TIMEOUT,
}

/** An operational failure. Coroutine/future cancellation is never wrapped in this exception. */
public class RegistryException
    @JvmOverloads
    constructor(
        public val category: RegistryErrorCategory,
        message: String,
        cause: Throwable? = null,
        public val httpStatus: Int? = null,
    ) : RuntimeException(message, cause)
