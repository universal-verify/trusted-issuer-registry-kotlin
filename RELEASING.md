# Releasing

The SDK version is independent of the registry protocol minor version. Update the pinned registry version/signing certificate only when intentionally migrating the registry protocol.

## One-time setup

Verify the `com.universalverify` namespace in Central Portal and make the release PGP public key available on a supported keyserver. Configure these GitHub Actions secrets at repository level or organization level with access granted to this repository:

| Secret | Value |
| --- | --- |
| `SIGNING_KEY` | Full ASCII-armored private PGP release key |
| `SIGNING_PASSWORD` | Its passphrase |
| `CENTRAL_USERNAME` | Central Portal user-token username |
| `CENTRAL_PASSWORD` | Central Portal user-token password |

Use a [Central Portal user token](https://central.sonatype.org/publish/generate-portal-token/) for publishing credentials. The PGP release key is separate from the registry's certificate-signing key.

## Publish a release

1. Update the SDK version in `build.gradle.kts`, its consumer fixtures, installation examples, and `CHANGELOG.md`.
2. Commit and push the release changes. For the first release, include `.github/workflows/release.yml` and `.github/scripts/` in that commit.
3. Wait for **SDK checks** to pass on the commit you will release. This includes Java 17/21/25, published-artifact Gradle/Maven consumers, and the minified Android tests on API 26 and API 37.2. Review ABI changes and the dependency-size measurement.
4. Tag that commit with the SDK version, such as `0.1.0`, and publish its GitHub release.
5. Follow the **Publish Maven Central** workflow in Actions until it succeeds.

Publishing a GitHub release triggers publication; pushing a tag, saving a draft, or editing release notes does not. The tag must match the generated SDK version. An optional `v` prefix is accepted. Published prereleases such as `0.2.0-rc.1` also publish that exact SDK version to Central; snapshot versions are rejected.

The release workflow checks out the released commit, verifies its publication coordinates and version, and requires successful SDK checks on that same commit. If checks are still running, it waits up to 20 minutes. It then builds and signs the bundle, saves it as a workflow artifact, uploads it through the [Central Portal Publisher API](https://central.sonatype.org/publish/publish-portal-api/), and waits up to 30 minutes for `PUBLISHED`. An accepted upload alone does not mark the workflow successful.

Build signing uses the signing secrets only during the build step, with the Gradle daemon and configuration cache disabled. Central credentials are supplied only to the upload step. The normal SDK checks workflow does not receive publishing credentials.

If validation fails, review the workflow output and Central Portal. The deployment ID is recorded in the job log and summary. If an upload response is lost or publication times out, check Central Portal before retrying: the deployment may already be processing or published. Published versions cannot be overwritten; further SDK changes require a new version. To retry after resolving a failure, rerun the release workflow from its Actions run.

## Build a bundle manually

The build creates the SDK, source, and generated API-documentation JARs, a Maven POM, and Gradle metadata. JVM/Android variants refer to the same SDK JAR, with different OkHttp dependencies. Maven consumers use the JVM dependency.

Set `SIGNING_KEY` to the armored private PGP key and `SIGNING_PASSWORD` to its passphrase using the release environment's secret management. Then assemble the signed Maven-layout bundle:

```sh
./gradlew --no-daemon --no-configuration-cache clean check bundleForCentral
```

The bundle is written to `build/central/trusted-issuer-registry-<version>-central.zip`. The task requires signatures for all primary publication files. You can upload it using [Central Portal's bundle workflow](https://central.sonatype.org/publish/publish-portal-upload/), review validation, and publish the release. The Gradle bundle task itself performs no upload.

For another Maven repository, `-PpublishUrl=...` configures a `release` repository using `MAVEN_USERNAME` and `MAVEN_PASSWORD`; use the corresponding Gradle publication task.

Release automation has offline regression tests, also run by SDK checks:

```sh
python3 -B -m unittest discover -s .github/scripts -p 'test_*.py'
```
