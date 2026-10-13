# Releasing

The SDK version is independent of the registry protocol minor version. Update the SDK version in `build.gradle.kts`, its consumer fixtures, and installation examples. Update the pinned registry version/signing certificate only when intentionally migrating the registry protocol.

Before release:

1. Run `./gradlew check` and review any ABI changes.
2. Run the Java 17/21/25 matrix.
3. Publish locally and run the Gradle and Maven consumer projects.
4. Run the Android minified-release device tests on API 26 and the current stable platform. Run `python3 verification/check-device-results.py` to require actual executed tests. Review the dependency-size measurement.
5. Confirm `com.universalverify` namespace ownership in Central Portal and release credentials/signing-key availability.

The build creates the SDK, source, and generated API-documentation JARs, a Maven POM, and Gradle metadata. JVM/Android variants refer to the same SDK JAR, with different OkHttp dependencies. Maven consumers use the JVM dependency.

Set `SIGNING_KEY` to the armored private PGP key and `SIGNING_PASSWORD` to its passphrase using the release environment's secret management. Then assemble the signed Maven-layout bundle:

```sh
./gradlew --no-configuration-cache clean check bundleForCentral
```

The bundle is written to `build/central/trusted-issuer-registry-0.1.0-central.zip`. The task requires signatures for all primary publication files. Upload it using [Central Portal's bundle workflow](https://central.sonatype.org/publish/publish-portal-upload/), review validation, and publish the release. The bundle task itself performs no upload.

For another Maven repository, `-PpublishUrl=...` configures a `release` repository using `MAVEN_USERNAME` and `MAVEN_PASSWORD`; use the corresponding Gradle publication task. Central Portal uses the signed bundle workflow above.

CI builds/checks the SDK and consumers. It does not publish releases, update issuer data, or store private signing material.
