# Maintaining JS feature parity

The JavaScript library owns registry data, signing, snapshot generation, and publication. This repository owns the Kotlin/Java SDK. Ordinary issuer updates flow through the pinned registry CDN version and do not require SDK releases.

## Last reviewed upstream baseline

| Item | Reviewed value |
| --- | --- |
| JavaScript release | `0.2.4` |
| JavaScript commit | `1731acd4970e6663cec97a349c34ff4010476051` |
| Review date | 2026-11-20 |
| Registry protocol | `0.2` |

The changes since JS `0.2.2` add offline registry snapshots. Other changes update issuer data, publication tooling, and development dependencies. The snapshot implementation and fixed oracle cases cover this runtime addition. Kotlin representation differences and accepted parser differences remain documented in the README and VERIFICATION.md.

This reviewed baseline is separate from fixture provenance. Existing fixtures retain the commit that actually generated them; reviewing newer code does not change their source history.

## Review each JS release

1. Compare the new release with the reviewed commit. Inspect runtime modules in `scripts/`, API declarations in `types/`, schema changes, tests, and runtime dependency changes. Classify issuer data, registry maintenance scripts, and development tooling separately from SDK behavior.
2. Port runtime changes through the existing registry, issuer, trust, certificate, CRL, and fetcher helpers. Preserve defaults, signature checks over the original parsed JSON, reason ordering, merging, cancellation, and Java/Android behavior. Add Kotlin and Java APIs using this repository's conventions.
3. Add small, fixed JS-derived fixtures and expected results for changed behavior. Record the exact upstream commit in each new fixture set. Use fixed clocks and local HTTP fixtures; regular Kotlin builds and CI must not need the JS checkout or live CDN.
4. Run JVM parity tests, formatting, API checks, and published-artifact consumers. Include the new API in the shared Java/Android consumer and Kotlin consumer. Run the existing Java 17/21/25 and minified Android matrix before release.
5. Update this reviewed baseline, user-visible SDK changelog, and relevant API documentation. Review the API dump and release version deliberately; Kotlin default constructors and data-class copy methods can change binary compatibility when options are added.

Development-only fixture generators live in `test-support/` and may use the adjacent JS checkout. Run `node test-support/generate-snapshot-fixtures.mjs` to regenerate snapshot cases after reviewing upstream. See `src/test/resources/fixtures/README.md` for the other fixture generators. Keep all generated fixtures committed and retain their recorded provenance.

The SDK accepts the JS-generated snapshot JSON directly. Applications choose how to download, bundle, and refresh it. No separate Kotlin issuer import, signing, or daily update pipeline is needed.
