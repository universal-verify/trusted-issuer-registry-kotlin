# Changelog

SDK releases are versioned independently of registry data releases.

## 0.1.0

Initial Kotlin and Java SDK, supporting Java 17+ servers and Android API 26+.

- Signed issuer lookups from jsDelivr registry version `0.2`, with configurable trust lists/scopes and user-provided issuer certificates.
- Kotlin suspend methods and Java blocking/`CompletableFuture` methods.
- Optional CRL revocation checks with `SKIP`, `BEST_EFFORT`, and `REQUIRED` modes.
- PEM certificate helpers and ECDSA/RSA signature verification, including RSA PKCS#1 v1.5 and RSA-PSS.
- Response caching, shared downloads, per-caller timeouts/cancellation, and application-supplied HTTP clients.
