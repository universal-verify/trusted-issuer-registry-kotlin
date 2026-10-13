# Published artifact verification

These independent projects consume the SDK from `build/repository`; they do not include its source project.

From the repository root:

```sh
./gradlew check publishMavenPublicationToVerificationRepository
./gradlew -p verification/jvm-gradle run kotlinSmoke verifyJvmVariant
mvn -f verification/jvm-maven/pom.xml compile exec:java
./gradlew -p verification/android assembleRelease verifyAndroidVariant connectedReleaseAndroidTest
python3 verification/check-device-results.py
```

The Java smoke program exercises certificate helpers, local trust, registry signature verification, lookup and deprecation caching, blocking/future methods, and HTTP-client ownership. All response data is static; no CDN access is required.

Variant checks require ICU4J in JVM consumer runtime dependencies and exclude it from Android dependencies. Android uses the framework ICU implementation through the same internal adapter. The signed Unicode fixtures and UniversalString metadata checks run inside the minified Android APK.

Android tests target the minified release APK. A Java-only instrumentation driver invokes checks compiled and optimized inside that APK; this isolates the driver from the app's optimized Kotlin dependencies. The report check requires three passing tests per device, including the JS-derived validation regressions. CI runs them on API 26 and API 37.2. `verification/android` needs Android platform 37.2 and a Java 17-capable Android build. The SDK itself supports devices from API 26.

The Android dependency-size measurement compares APKs built with and without the SDK. The baseline build is selected with `-PwithoutSdk`; omit the shared Java smoke source for that build. The measurement script records compressed APK size and uncompressed DEX bytes, including retained crypto and networking dependencies.

## Recorded measurement

The minified consumer adds 936,939 compressed APK bytes (about 915 KiB) and 1,719,808 uncompressed DEX bytes versus the empty consumer. This includes retained SDK, Kotlin, networking, serialization, and crypto code, plus the sample's static test fixtures; it varies with the APIs an application keeps. See [android-size.json](android-size.json) for exact values.
