# Changelog

SDK releases are versioned independently of registry data releases.

## 0.2.0

- Added `RegistrySnapshot.fromJson`, `RegistryOptions.registrySnapshot`, and a Java builder method for offline signed registry lookups using the JS registry's snapshot format.
- Snapshots retain registry trust lists/scopes, user-certificate merging, and optional CRL checks. Snapshot mode skips registry/deprecation requests, returns null for end-of-life dates, and never falls back to the CDN.
- Upgrading Kotlin consumers should recompile: adding the snapshot option changes `RegistryOptions`' generated constructor and copy signatures. Registry protocol version remains `0.2`.

## 0.1.0

Initial Kotlin and Java SDK, supporting Java 17+ servers and Android API 26+.

- Signed issuer lookups from jsDelivr registry version `0.2`, with configurable trust lists/scopes and user-provided issuer certificates.
- Kotlin suspend methods and Java blocking/`CompletableFuture` methods.
- Optional CRL revocation checks with `SKIP`, `BEST_EFFORT`, and `REQUIRED` modes.
- PEM certificate helpers and ECDSA/RSA signature verification, including RSA PKCS#1 v1.5 and RSA-PSS.
- Response caching, shared downloads, per-caller timeouts/cancellation, and application-supplied HTTP clients.
