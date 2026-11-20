# Implementation verification

Verified locally for SDK 0.2.0 against the committed static fixture baseline:

- 258 JVM tests pass on Java 17, 21, and 25, including 152 JS-oracle trust scenarios, 28 data signatures, canonical byte comparisons, PSS-only key restrictions, and cache/cancellation/lifecycle checks. Validation regressions include unknown critical CRL extensions, ordered names, Unicode collation, UniversalString metadata, and malformed PSS field order, with valid-input controls.
- Snapshot coverage includes 14 trust scenarios from JS 0.2.4, malformed/duplicate records, signed records without certificates, unknown signed fields, shared verification and cancellation, local merging/fallback, network suppression, and configured CRL requests. Fixture source commits and the reviewed upstream baseline are recorded separately.
- Standard ktlint checks and the committed Kotlin ABI baseline pass.
- Independent Kotlin/Java Gradle and Java Maven projects consume the locally published artifact successfully. Gradle selects the JVM OkHttp and ICU4J dependencies; Maven uses the generated POM.
- The minified Android artifact passes Java/crypto device checks on API 26 and API 37.2, with three executed tests per device, including snapshot calls, tampered-signature rejection, all 28 JS signature vectors, and the 24 validation trust scenarios. CI requires at least three passing tests per device. Its dependency graph selects OkHttp Android and built-in ICU, with no JVM OkHttp or ICU4J artifact.
- The minified APK overhead is recorded in `verification/android-size.json`: 945,646 compressed APK bytes and 1,726,156 uncompressed DEX bytes for the sample consumer, including its static test fixtures.
- All 17 offline release-automation tests pass. SDK 0.1.0's signed Central Portal bundle was previously built with a temporary test key and each publication signature verified locally; that temporary key and bundle were discarded. SDK 0.2.0 has been published only to the local verification repository; release signing and Central publication use operator-supplied credentials.

Registry issuer maintenance remains in JS. Kotlin uses the pinned registry minor version 0.2 and public signing certificate. See `CONTRIBUTING.md`, `MAINTAINERS.md`, `RELEASING.md`, and `verification/README.md` for the parity review process and reproducible commands.

Additional parser assessment compared ordered and reordered IssuingDistributionPoint fields in 12 signed CRL cases. Bouncy Castle's interpretation preserved revoked/non-revoked results, rejected mismatched CA-only scope, and retained undetermined status for indirect CRLs. PKIjs rejects the reordered encoding. This is a parser-acceptance difference for nonconforming field order; the SDK's CRL handling remains unchanged.
