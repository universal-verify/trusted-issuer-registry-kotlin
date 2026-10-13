The fixed runtime certificates, signatures, and CRLs were generated using the JavaScript SDK at commit `0c080652d11dbbf16490c40d7ba1f54051c972c1`. The validation fixtures use commit `c236f226a916de51d2fb93b89e08660d018f2620`; each JSON fixture records its source commit.

`node test-support/generate-fixtures.mjs` explicitly regenerates the runtime development fixtures using the sibling JS checkout. `node test-support/generate-validation-fixtures.mjs` regenerates `validation.json`, covering unknown critical CRL extensions, ordered distinguished-name comparisons, Unicode collation, UniversalString issuer metadata, and RSA-PSS parameter schemas in certificates, CRLs, and PSS-only keys. It includes positive controls, 24 trust scenarios, 15 certificate-signature results, and 17 name comparisons.

Kotlin builds and CI never run either generator or require that checkout. No private keys are stored. The verification clock is fixed at 2026-10-08T00:00:00Z.
