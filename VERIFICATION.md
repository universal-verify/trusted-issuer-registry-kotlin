# Implementation verification

Verified locally against the committed static fixture baseline:

- 221 JVM tests pass on Java 17, 21, and 25, including 138 JS-oracle trust scenarios, 28 data signatures, canonical byte comparisons, PSS-only key restrictions, and cache/cancellation/lifecycle checks. Validation regressions include unknown critical CRL extensions, ordered names, Unicode collation, UniversalString metadata, and malformed PSS field order, with valid-input controls.
- Standard ktlint checks and the committed Kotlin ABI baseline pass.
- Independent Kotlin/Java Gradle and Java Maven projects consume the locally published artifact successfully. Gradle selects the JVM OkHttp and ICU4J dependencies; Maven uses the generated POM.
- The minified Android artifact passes Java/crypto device checks on API 26 and API 37.2, with three executed tests per device, including all 28 JS signature vectors and the 24 validation trust scenarios. CI requires at least three passing tests per device. Its dependency graph selects OkHttp Android and built-in ICU, with no JVM OkHttp or ICU4J artifact.
- The minified APK overhead is recorded in `verification/android-size.json`: 936,939 compressed APK bytes and 1,719,808 uncompressed DEX bytes for the sample consumer, including its static test fixtures.
- A signed Central Portal bundle was built with a temporary test key and each publication signature verified locally. The temporary key and signed development bundle were discarded; release signing uses operator-supplied credentials.

Registry issuer maintenance remains in JS. Kotlin uses the pinned registry minor version 0.2 and public signing certificate. See `CONTRIBUTING.md`, `RELEASING.md`, and `verification/README.md` for reproducible commands.

Additional parser assessment compared ordered and reordered IssuingDistributionPoint fields in 12 signed CRL cases. Bouncy Castle's interpretation preserved revoked/non-revoked results, rejected mismatched CA-only scope, and retained undetermined status for indirect CRLs. PKIjs rejects the reordered encoding. This is a parser-acceptance difference for nonconforming field order; the SDK's CRL handling remains unchanged.
