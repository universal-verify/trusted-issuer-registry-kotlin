# Contributing

Use Java 17+ to run the wrapper. The SDK is compiled with a Java 17 toolchain; install one even when testing newer runtimes.

```sh
./gradlew check
./gradlew ktlintFormat
./gradlew publishMavenPublicationToVerificationRepository
```

`check` runs tests, ktlint, and Kotlin ABI validation. Review public API changes before updating the committed baseline with `./gradlew updateKotlinAbi`. Dependencies are pinned in `gradle/libs.versions.toml`; update lockfiles deliberately using `--write-locks`.

The internal registry, issuer, trust, certificate, CRL, and cached-fetcher helpers follow the JS runtime's organization. Keep protocol behavior recognizable across implementations. Public types use Kotlin conventions and Java-friendly overloads/builders. Keep Bouncy Castle types internal, preserve caller cancellation, and avoid changing global providers or closing application-owned clients.

The signed JSON protocol is specifically `canonical-json@0.2.0`, including UTF-16 ordering, special escaping, number formatting, and boolean-as-object behavior. Verify the parsed tree before typed decoding discards unknown fields. Changing to a generic sorted JSON or full JCS serializer breaks signatures.

PKIjs also interprets implicit CRL reason fields as raw payload bytes. The compatibility reader follows those bytes while keeping the signed certificate/CRL structure intact. Preserve the fixed oracle tests when changing this code; Bouncy Castle's strict typed reason parser alone is insufficient for those fixtures.

Name matching follows PKIjs's ordered, flattened attribute comparisons and string normalization. CRLs with critical extensions outside PKIjs's allowlist cannot establish revocation status. RSA-PSS parameter fields must be explicit context tags in schema order; this applies to signature algorithms and PSS-only key restrictions.

Use ICU collation for name comparisons; the JDK collator disagrees with JavaScript for ignored Unicode characters. The internal adapter selects Android's built-in ICU or the JVM-only ICU4J dependency using their shared API. Each operation creates its own mutable collator. Keep ICU4J out of Android variants, and check signed Unicode name fixtures on both platforms. Decode UniversalString subject attributes as UCS-4 text before deriving issuer metadata; Bouncy Castle's string accessor returns DER hex for that type.

Tests use static JS-generated fixtures and fixed clocks. The fixture README records the source commit. To deliberately regenerate them, install dependencies in the sibling JS checkout and run `node test-support/generate-fixtures.mjs` or `node test-support/generate-validation-fixtures.mjs` for the validation regressions; ordinary builds and CI do not require JS or network registry access.

Run newer runtime tests with installed JDK/JRE toolchain paths:

```sh
./gradlew -PtestJavaVersion=21 test
./gradlew -PtestJavaVersion=25 test
```

Use `-Dorg.gradle.java.installations.paths=...` when the runtimes are outside Gradle's usual discovery locations. The test matrix includes Java 17, 21, and 25. Consumer projects test the actual local publication through Gradle, Maven, and a minified Android application; see [verification/README.md](verification/README.md).

Crypto/CRL changes require positive and negative algorithm/coverage cases. Cache changes require body-download deadlines, shared-consumer isolation, retry cleanup, expiry, and lifecycle checks. Keep tests independent of live CDN state.
