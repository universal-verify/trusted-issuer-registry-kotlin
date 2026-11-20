# SDK maintenance

Read CONTRIBUTING.md and MAINTAINERS.md before changing SDK behavior. MAINTAINERS.md records the last reviewed JavaScript release and the feature-parity review process.

- Preserve JS runtime behavior using conventional Kotlin APIs and Java-friendly builders/facades.
- Keep fixture source commits accurate and separate from the latest reviewed upstream commit.
- Add fixed JS-derived parity cases for behavioral changes. Ordinary builds and CI use committed fixtures without the JS checkout or live registry access.
- Registry data maintenance, signing, and snapshot generation belong to the JS repository. Kotlin consumes its signed records and snapshots.
