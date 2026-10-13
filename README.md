# Trusted Issuer Registry for Kotlin and Java

A Kotlin/JVM library for looking up trusted issuers and verifying whether they issued an X.509 certificate.

Use registry issuers, your own trusted issuer certificates, or both. The library checks signatures, validity dates, optional trust scopes, and CRL revocation status, returning issuer details and trust results.

Supports **Java 17+ servers and Android API 26+**, with Kotlin suspend methods and Java blocking/future methods.

## Registry Overview

The [Trusted Issuer Registry](https://github.com/universal-verify/trusted-issuer-registry) aggregates issuer information from authoritative trust lists:

- **[AAMVA DTS](https://www.aamva.org/identity/mobile-driver-license-digital-trust-service)** — American Association of Motor Vehicle Administrators' Digital Trust Service.
- **[UV](https://github.com/universal-verify/trust-list)** — Universal Verify's compilation of Apple-recommended issuers for digital credential verification.

Issuer records contain certificates, source trust lists, trust scopes, and display metadata. Records are cryptographically signed and distributed through jsDelivr. This library verifies their signatures before using them.

Lookups use the latest published patch of registry version `0.2`, so issuer updates do not require a Kotlin SDK upgrade, subject to the library's cache and [CDN caching](https://github.com/jsdelivr/jsdelivr#caching).

## Trust Model

- **Signed data:** issuer records are signed with a NIST P-256 key and verified using the registry's signing certificate embedded in the library.
- **Explicit trust:** choose which registry trust lists and scopes your application accepts, or provide issuer certificates that your application already trusts.
- **Certificate checks:** issuer-name matching, signatures, and validity dates are checked; revocation checking is configurable.
- **Auditable sources:** registry changes and upstream inclusion policies are available in the registry repository's public history.

Trust results describe the certificate's issuer. Your application also verifies the credential or document's own signature and protocol. The library checks the issuer-certificate relationship; it does not build a general PKIX chain or use the OS trust store.

Shared governance and risk documentation is maintained with the registry:

- [Trust Policy](https://github.com/universal-verify/trusted-issuer-registry/blob/main/TRUST_POLICY.md) — criteria for upstream trust-list inclusion and removal.
- [Trust and Risk Model](https://github.com/universal-verify/trusted-issuer-registry/blob/main/TRUST_AND_RISK_MODEL.md) — threat model, signing-key management, and change control.

## Quick Start

Add the SDK to a Gradle project:

```kotlin
repositories { mavenCentral() }

dependencies {
    implementation("com.universalverify:trusted-issuer-registry:0.1.0")
}
```

Or with Maven:

```xml
<dependency>
  <groupId>com.universalverify</groupId>
  <artifactId>trusted-issuer-registry</artifactId>
  <version>0.1.0</version>
</dependency>
```

The examples target SDK `0.1.0`; Maven Central publication is a separate [release step](RELEASING.md).

Resolve trust for a PEM certificate from an existing Kotlin coroutine:

```kotlin
import com.universalverify.trustedissuerregistry.*

suspend fun checkCertificate(certificatePem: String) {
    Registry().use { registry ->
        val result = registry.resolveCertificateTrust(
            certificatePem,
            ResolveCertificateTrustOptions(
                trustLists = listOf(TrustList.UV, TrustList.AAMVA_DTS),
            ),
        )

        if (result.trusted) {
            println("Trusted issuer: ${result.issuer?.display?.name}")
            println("Entity type: ${result.issuer?.entityType?.wireValue}")
        } else {
            println("Certificate not trusted: ${result.untrustedReasons}")
        }
    }
}
```

**Select trust lists explicitly to query the registry.** An empty `trustLists` list, including the default, uses only user-provided issuers and makes no registry request. CRL requests can still occur when revocation checking is enabled.

Reuse a `Registry` instance for application components that perform multiple lookups. See [Java call styles](#java-call-styles) and [lifecycle](#lifecycle-and-http-client) below.

## API Reference

### Constants and Enums

Protocol enums expose `wireValue`, for example `TrustList.AAMVA_DTS.wireValue == "aamva_dts"`.

#### `TrustList`

Registry trust lists accepted by `ResolveCertificateTrustOptions`:

| Constant | Wire value | Description |
| --- | --- | --- |
| `UV` | `uv` | Issuers trusted by Universal Verify |
| `AAMVA_DTS` | `aamva_dts` | Issuers trusted by the AAMVA Digital Trust Service |

#### `TrustScope`

| Constant | Wire value | Description |
| --- | --- | --- |
| `GOVERNMENT_ISSUED_ID` | `government_issued_id` | Government-issued identity documents |
| `DOCUMENT_SIGNING` | `document_signing` | Documents signed by the issuer |

#### `RevocationCheckMode`

| Constant | Wire value | Behavior |
| --- | --- | --- |
| `SKIP` | `skip` | Do not check revocation; the default |
| `BEST_EFFORT` | `best_effort` | Reject confirmed revocation; permit undetermined status |
| `REQUIRED` | `required` | Reject confirmed revocation and undetermined status |

Missing, unavailable, invalid, wrongly scoped, or unverifiable CRLs leave status undetermined. Unrecognized critical CRL extensions also leave status undetermined. A verified stale CRL can establish revocation, but cannot establish non-revocation. Non-revocation requires complete reason coverage. Delta CRLs and `removeFromCRL` cannot establish non-revocation alone; delegated and indirect CRLs are unsupported. CRLs are checked only against issuers that verify the input certificate's signature.

#### `UntrustedReason`

Stable typed reasons returned at the root and on each issuer certificate. Their wire values are lowercase versions of the constant names, such as `certificate_expired`.

| Constant | Meaning |
| --- | --- |
| `CERTIFICATE_MISSING` | No certificate was supplied |
| `CERTIFICATE_AKI_MISSING` | Certificate has no usable Authority Key Identifier |
| `CERTIFICATE_NOT_YET_VALID` | Input certificate is not yet valid |
| `CERTIFICATE_EXPIRED` | Input certificate has expired |
| `CERTIFICATE_REVOKED` | Revocation was confirmed by CRL |
| `REVOCATION_STATUS_UNDETERMINED` | Required revocation status could not be established |
| `ISSUER_FETCH_FAILED` | Registry lookup failed and no user-provided certificate established trust |
| `ISSUER_CERTIFICATE_NOT_FOUND` | No issuer certificate was found to verify the input |
| `CERTIFICATE_SIGNATURE_VERIFICATION_FAILED` | Issuer-name matching or signature verification failed |
| `ISSUER_CERTIFICATE_NOT_YET_VALID` | Issuer certificate is not yet valid |
| `ISSUER_CERTIFICATE_EXPIRED` | Issuer certificate has expired |
| `ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS` | Issuer certificate belongs to none of the requested lists |
| `ISSUER_MISSING_REQUIRED_TRUST_SCOPE` | Issuer lacks the requested scope |

### Registry

#### `Registry(options = RegistryOptions(), httpClient = null)`

Creates a thread-safe client. Kotlin callers use default arguments; Java callers can use the no-argument constructor, overloads, and option builders.

**`RegistryOptions`:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `trustedIssuerCertificates` | `List<UserTrustedIssuerCertificate>` | `emptyList()` | Explicitly trusted issuer certificates |
| `revocationCheckMode` | `RevocationCheckMode` | `SKIP` | CRL checking policy |
| `timeout` | `java.time.Duration` | `Duration.ofSeconds(10)` | Per-caller download deadline, including the response body |
| `cacheEnabled` | `Boolean` | `true` | Cache issuer, deprecation, and CRL responses in memory |
| `cacheTtl` | `java.time.Duration` | `Duration.ofHours(24)` | Maximum cache lifetime |

Timeout must be positive; cache lifetime must be nonnegative. Zero TTL retains no responses. The timeout applies to each issuer, deprecation, or CRL download, not the entire trust resolution.

**User-provided issuers:**

For certificates without metadata overrides:

```kotlin
val registry = Registry(
    RegistryOptions(
        trustedIssuerCertificates = listOf(UserTrustedIssuerCertificate(issuerPem)),
    ),
)
```

`UserTrustedIssuerCertificate` accepts these properties:

| Property | Type | Default or description |
| --- | --- | --- |
| `data` | `String` | Required PEM-encoded issuer certificate |
| `format` | `CertificateFormat` | `PEM`, the only supported format |
| `trustScopes` | `List<TrustScope>` | `emptyList()` |
| `entityType` | `EntityType` | `OTHER` |
| `entityMetadata` | `EntityMetadata` | Optional country/region overrides; defaults come from the certificate subject |
| `display` | `IssuerDisplayOverrides` | Optional name/logo/description overrides |

```kotlin
val registry = Registry(
    RegistryOptions(
        trustedIssuerCertificates = listOf(
            UserTrustedIssuerCertificate(
                data = issuerPem,
                trustScopes = listOf(TrustScope.DOCUMENT_SIGNING),
                entityType = EntityType.EDUCATIONAL_INSTITUTION,
                entityMetadata = EntityMetadata(country = "US"),
                display = IssuerDisplayOverrides(name = "Example University"),
            ),
        ),
        revocationCheckMode = RevocationCheckMode.REQUIRED,
    ),
)
```

Certificates must contain a nonempty Subject Key Identifier (SKI). Entries with the same SKI form one issuer; identical PEM certificates are deduplicated. Metadata overrides certificate-derived defaults, with earlier user entries taking precedence. The default display name comes from the organization or common name, falling back to the issuer ID. Null override properties leave defaults intact.

User-provided certificates receive `CertificateProvenance.USER_PROVIDED`. They bypass registry trust-list filtering while still undergoing signature, validity, optional scope, and optional revocation checks. Java's `RegistryOptions.builder().addTrustedIssuerCertificate(...)` accepts either a PEM string or a `UserTrustedIssuerCertificate`, including both in the same builder.

**Caching:** each instance retains up to 1,024 responses with LRU eviction. Issuers require valid registry signatures; 404s and successful CRL/deprecation downloads are also cached, including malformed CRL/deprecation bodies. Network errors, timeouts, and other HTTP errors are not cached. A future CRL `nextUpdate` can shorten the cache lifetime. Concurrent downloads are shared even with caching disabled; each caller has an independent deadline and cancellation.

#### `Registry.minorVersion`

The registry-data compatibility version, currently `"0.2"`. It is independent of the Kotlin SDK's release version. See [Versioning and Deprecation](#versioning-and-deprecation).

### Registry Methods

Kotlin network methods are `suspend`. Each has Java blocking and `CompletableFuture` variants:

| Kotlin suspend method | Blocking method | Future method |
| --- | --- | --- |
| `resolveCertificateTrust` | `resolveCertificateTrustBlocking` | `resolveCertificateTrustAsync` |
| `getIssuerFromX509AKI` | `getIssuerFromX509AKIBlocking` | `getIssuerFromX509AKIAsync` |
| `getEndOfLifeDate` | `getEndOfLifeDateBlocking` | `getEndOfLifeDateAsync` |

#### `resolveCertificateTrust(certificate, options = ResolveCertificateTrustOptions())`

Determines whether a certificate was issued by a trusted issuer. Accepts a PEM `String?` or a `java.security.cert.X509Certificate`. Omit the certificate, or pass null/empty PEM, to report missing input.

**`ResolveCertificateTrustOptions`:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `trustLists` | `List<TrustList>` | `emptyList()` | Registry lists to accept; empty uses only user-provided issuers |
| `trustScope` | `TrustScope?` | `null` | Required issuer scope; null skips scope checking |

Registry certificates must belong to at least one requested list. Scope restrictions apply to every issuer certificate, including user-provided certificates.

```kotlin
val result = registry.resolveCertificateTrust(
    certificatePem,
    ResolveCertificateTrustOptions(
        trustLists = listOf(TrustList.AAMVA_DTS),
        trustScope = TrustScope.GOVERNMENT_ISSUED_ID,
    ),
)
println(result.trusted)
println(result.untrustedReasons)
println(result.issuer?.certificates)
```

**Returns `CertificateTrustResult`:**

| Property | Type | Description |
| --- | --- | --- |
| `trusted` | `Boolean` | Input certificate passes all requested trust checks |
| `issuer` | `ResolvedIssuer?` | Issuer metadata and results for all issuer certificates; null when no issuer is found |
| `untrustedReasons` | `List<UntrustedReason>` | Input validity failures plus reasons from the selected issuer certificate; empty on success |
| `issuer.certificates[].trusted` | `Boolean` | This issuer certificate passes the checks for the input |
| `issuer.certificates[].revocationStatus` | `RevocationStatus` | `NOT_CHECKED`, `NOT_REVOKED`, or `REVOKED` |
| `issuer.certificates[].untrustedReasons` | `List<UntrustedReason>` | Reasons this issuer certificate cannot establish trust; empty on success |

`NOT_CHECKED` covers skipped checks and undetermined revocation status. Returned lists are independent, unmodifiable snapshots. All issuer certificates are evaluated; the root selects the first trusted certificate, or the first with the fewest failure reasons when none are trusted.

**Trust evaluation and merging:**

- User metadata takes precedence over registry metadata. Scopes and certificates are combined, with user certificates first, followed by unique registry certificates in their original order.
- Identical PEM certificates merge their provenance. `CertificateProvenance` includes `UV`, `AAMVA_DTS`, and `USER_PROVIDED`; it is separate from the registry `TrustList` enum.
- Missing input returns only `CERTIFICATE_MISSING`; missing AKI returns only `CERTIFICATE_AKI_MISSING`. Neither performs a lookup. Not-yet-valid and expired inputs still undergo issuer evaluation.
- Registry lookup failure adds `ISSUER_FETCH_FAILED` only when no user-provided certificate is trusted. Missing issuers and empty certificate lists add `ISSUER_CERTIFICATE_NOT_FOUND`.
- Resolved issuers omit registry signatures: merged metadata and runtime trust results are not covered by that signature. Registry signatures are verified before merging.

#### `getIssuerFromX509AKI(x509aki)`

Looks up issuer metadata without evaluating certificate trust.

- **Input:** unpadded Base64url AKI, without the `x509_aki:` prefix.
- **Returns:** `Issuer?`, null when no issuer is found.

```kotlin
val issuer = registry.getIssuerFromX509AKI("TprRzaFBJ1SLjJsO01tlLCQ4YF0")
```

The registry is always checked, using cached data when available, even with a matching user issuer. A 404 still permits user issuer data to be returned. Other request failures throw. Merge precedence and ordering follow `resolveCertificateTrust`. Unmerged registry results retain their signature; merged results omit it. This method does not add per-certificate trust results.

#### `getEndOfLifeDate()`

Retrieves the applicable registry deprecation notice. Returns `java.time.Instant?`, null for a 404 or when no applicable notice exists. Request failures and malformed responses throw.

```kotlin
val endOfLife = registry.getEndOfLifeDate()
if (endOfLife != null) {
    println("Registry version ends support on: $endOfLife")
}
```

### Java Call Styles

Java callers use the same options, results, and enums. Builders support options with defaults:

```java
import com.universalverify.trustedissuerregistry.*;

ResolveCertificateTrustOptions options = ResolveCertificateTrustOptions.builder()
    .addTrustList(TrustList.UV)
    .addTrustList(TrustList.AAMVA_DTS)
    .build();

try (Registry registry = new Registry()) {
    CertificateTrustResult result = registry.resolveCertificateTrustBlocking(certificatePem, options);
    if (result.getTrusted()) {
        System.out.println("Trusted issuer: " + result.getIssuer().getDisplay().getName());
    } else {
        System.out.println(result.getUntrustedReasons());
    }
}
```

For asynchronous Java code, use the future variant. This example closes a client after its single request:

```java
import com.universalverify.trustedissuerregistry.*;
import java.util.concurrent.CompletableFuture;

Registry registry = new Registry();
ResolveCertificateTrustOptions options = ResolveCertificateTrustOptions.builder()
    .addTrustList(TrustList.UV)
    .build();

CompletableFuture<CertificateTrustResult> future =
    registry.resolveCertificateTrustAsync(certificatePem, options);

future.whenComplete((result, error) -> {
    try {
        if (error != null) {
            System.err.println(error.getMessage());
        } else {
            System.out.println(result.getTrusted());
        }
    } finally {
        registry.close();
    }
});
```

Cancelling the returned future releases that caller's participation in shared downloads. Keep a reused registry open until its operations finish. Suspend methods are hidden from Java source callers. Java's untyped `null` is ambiguous between PEM and parsed-certificate overloads; use the no-argument resolution overload to report missing input.

### Utility Functions

Standalone synchronous helpers require no `Registry` instance. Kotlin imports top-level functions; Java calls static methods on `Certificates`.

| Function | Returns | Description |
| --- | --- | --- |
| `parsePemCertificate(pemString)` | `X509Certificate` | Parse PEM without verifying trust or signatures |
| `certificateToPem(certificate)` | `String` | Encode certificate DER as PEM with 64-character lines |
| `verifyCertificateSignature(certificate, issuerCertificate)` | `Boolean` | Check issuer-name matching and the certificate signature; accepts PEM, parsed, or mixed inputs |
| `verifySignatureWithPem(pemKey, signature, data, options = null)` | `Boolean` | Verify a data signature with the public key from a PEM certificate |

Malformed certificate input throws. Certificate-signature verification returns false when the issuer name or signature does not match. These helpers do not evaluate dates, revocation, trust lists, scopes, or a full chain; a valid self-signature does not establish trust.

```kotlin
val certificate = parsePemCertificate(certificatePem)
val pem = certificateToPem(certificate)
val validCertificate = verifyCertificateSignature(certificatePem, issuerPem)
val validSignature = verifySignatureWithPem(signingCertificatePem, signatureBase64, signedBytes)
val validPss = verifySignatureWithPem(
    rsaCertificatePem,
    rsaSignatureBase64,
    signedBytes,
    SignatureVerificationOptions.RsaPss(HashAlgorithm.SHA256, saltLength = 32),
)
```

For data signatures, `data` is a `ByteArray` containing the exact signed bytes. Signatures use standard Base64; ECDSA signatures must contain DER encoding before Base64 encoding. The EC curve comes from the certificate, while `SignatureVerificationOptions` selects the algorithm and hash:

| Option | Behavior |
| --- | --- |
| Omitted, `null`, or `Ecdsa()` | ECDSA with SHA-256 for P-256, SHA-384 for P-384, or SHA-512 for P-521 |
| `Ecdsa(hash)` | ECDSA with an explicit hash |
| `RsaPkcs1v15(hash)` | RSA PKCS#1 v1.5 with an explicit hash |
| `RsaPss(hash, saltLength)` | RSA-PSS with an explicit hash and salt length in bytes |

The options above are nested types of `SignatureVerificationOptions`. `HashAlgorithm` supports `SHA1`, `SHA256`, `SHA384`, and `SHA512`. RSA requires explicit options; use the parameters specified by the signed data's format. Verification does not retry other algorithms or parameters.

PSS permits any valid salt length, including zero, with matching MGF1 hash and trailer field 1. PSS-only public keys are supported, with declared hash and minimum-salt restrictions enforced. Malformed signature encodings and unsupported options throw; a well-formed signature that does not match returns false.

The SDK does not register or replace global Java security providers.

### Lifecycle and HTTP Client

`Registry` implements `AutoCloseable`. Reuse it to share downloads and caches, then close it when its owning component ends. `close()` is idempotent, cancels operations, clears caches, and releases resources owned by the registry. Kotlin can use `use`; Java can use try-with-resources.

To use an existing HTTP client with your interceptors, proxy, or TLS settings:

```kotlin
val registry = Registry(
    options = RegistryOptions(),
    httpClient = existingOkHttpClient,
)
```

Closing the registry leaves application-supplied client resources open. Timeout and cancellation apply per caller, so another caller sharing the download can continue.

### Errors

Ordinary trust failures are `CertificateTrustResult` values. Operational failures throw `RegistryException`, with a `category`, optional `cause`, and optional `httpStatus`:

| `RegistryErrorCategory` | Meaning |
| --- | --- |
| `MALFORMED_CERTIFICATE` | Certificate parsing or encoding failed |
| `MALFORMED_RESPONSE` | Response data could not be parsed or converted |
| `UNSUPPORTED_ALGORITHM` | Unsupported keys or signature parameters |
| `CRYPTOGRAPHIC_ERROR` | Invalid data-signature encoding or cryptographic processing failure |
| `NETWORK_ERROR` | Download or response-body reading failed |
| `HTTP_ERROR` | Unsuccessful HTTP status other than the handled 404 cases |
| `TIMEOUT` | A caller's download deadline expired |

Invalid configuration throws `IllegalArgumentException`. Coroutine/future cancellation propagates as cancellation. Future failures are available through the future's exception mechanism. Invalid registry signatures produce an absent issuer and are never cached.

## Issuer Data Format

The registry's wire format is defined by [trusted-issuer.schema.json](https://github.com/universal-verify/trusted-issuer-registry/blob/main/trusted-issuer.schema.json). For example:

```json
{
  "issuer_id": "x509_aki:3-BJ8g1-X200DZEo-i9MFTtNh0U",
  "entity_type": "government",
  "entity_metadata": { "country": "US", "region": "AZ" },
  "display": { "name": "Example Issuer" },
  "trust_scopes": ["government_issued_id"],
  "certificates": [
    {
      "data": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
      "format": "pem",
      "trust_lists": ["uv", "aamva_dts"]
    }
  ],
  "signature": "..."
}
```

Kotlin properties use camelCase; serializable issuer/result models retain the registry's JSON names:

| Kotlin property | JSON field | Description |
| --- | --- | --- |
| `issuerId` | `issuer_id` | Issuer identifier, prefixed with `x509_aki:` |
| `entityType` | `entity_type` | Organization type |
| `entityMetadata` | `entity_metadata` | Optional country and region |
| `display` | `display` | Name and optional logo/description |
| `trustScopes` | `trust_scopes` | Issuer scopes |
| `certificates` | `certificates` | Issuer certificates and source provenance |
| `certificates[].trustLists` | `certificates[].trust_lists` | Sources that vouch for each certificate |
| `signature` | `signature` | Present on unmerged registry lookup results |

`EntityType` includes `GOVERNMENT`, `EDUCATIONAL_INSTITUTION`, `COMMERCIAL`, `NON_PROFIT`, `INTERNATIONAL_BODY`, and `OTHER`. Certificate format is `CertificateFormat.PEM`.

Resolved results add `trusted`, `revocationStatus`, and `untrustedReasons` on each certificate; those JSON keys retain camelCase. Kotlin always returns reason lists, including empty lists on success.

## Direct HTTP Access

Issuer records can also be inspected directly:

```sh
curl https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.2/issuers/x509_aki/TprRzaFBJ1SLjJsO01tlLCQ4YF0.json
curl https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.2/deprecation_notice.json
```

The issuer URL format is `https://cdn.jsdelivr.net/npm/trusted-issuer-registry@{minor_version}/issuers/x509_aki/{x509aki}.json`. Direct issuer responses require signature verification before use; `Registry` performs it automatically.

## Versioning and Deprecation

See [CHANGELOG.md](CHANGELOG.md) for SDK release notes.

Kotlin SDK releases are independent of registry-data releases. SDK `0.1.0` uses registry minor version `0.2`. Registry patch releases update issuer data; registry minor releases may change the schema or trust protocol. Older registry lines receive updates until their announced end-of-life date, with deprecation notices published 90 days in advance. Use `getEndOfLifeDate()` to check the version used by the client.

Deprecation notices are unsigned and use Unix seconds. An example for an older registry line:

```json
{
  "version": "0.1",
  "end_of_life": 1761782400
}
```

The library converts an applicable notice's `end_of_life` to an `Instant`.

## Android

Use `minSdk = 26` and a Java 17-capable Kotlin/Android toolchain. JVM and Android consumers use the same SDK JAR; Gradle selects the platform dependencies automatically.

Declare internet permission:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

Use suspend/future APIs, or call blocking methods from a worker thread. Registry requests use HTTPS. Some issuer CRLs use HTTP, which needs the application's appropriate cleartext-network configuration. The SDK supplies R8 rules for its cryptographic provider. See [verification/README.md](verification/README.md) for supported build configurations, minified-release checks, and dependency-size measurements.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development, tests, and API compatibility checks, [VERIFICATION.md](VERIFICATION.md) for verified platform behavior, and [RELEASING.md](RELEASING.md) for publication instructions. Changes to registry trust policies are discussed in the [registry repository](https://github.com/universal-verify/trusted-issuer-registry).

## License

[Mozilla Public License 2.0](LICENSE).
