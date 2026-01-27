# SBOM (Software Bill of Materials)

QryptCoin Core aims to ship an SBOM alongside releases and for CI verification. An SBOM helps auditors and downstream users
understand which third-party components are present and which versions are in use.

## CI

GitHub Actions generates SBOM artifacts on pull requests and on pushes to the default branch:

- CycloneDX JSON: `sbom.cdx.json`
- SPDX JSON: `sbom.spdx.json`

See `.github/workflows/sbom.yml`.

## Local generation

If you have Syft installed:

```bash
syft dir:. -o cyclonedx-json=sbom.cdx.json
syft dir:. -o spdx-json=sbom.spdx.json
```

Alternatively, using the Syft container:

```bash
docker run --rm -v "$PWD:/src" -w /src anchore/syft:latest dir:/src -o cyclonedx-json=sbom.cdx.json
docker run --rm -v "$PWD:/src" -w /src anchore/syft:latest dir:/src -o spdx-json=sbom.spdx.json
```

Notes:

- This repo vendors some dependencies under `vendor/` and `third_party/` for deterministic builds.
- SBOM outputs are not committed to the repository; they are produced as CI artifacts (and can be attached to releases).

