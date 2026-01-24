# Release Process (Maintainers)

This document describes a repeatable workflow for producing release artifacts and publishing integrity metadata.

Release artifacts are distributed with:

- `SHA256SUMS` (checksums)
- `SHA256SUMS.asc` (detached OpenPGP signature over `SHA256SUMS`)

Verification instructions for users live in `docs/verify.md`.

## Release signing key

Maintain a dedicated OpenPGP key for release signing.

Publish:

- The signing key fingerprint (in the release notes and on the project website).
- An ASCII-armored public key export (recommended to attach as `qryptcoin-release-key.asc` to every release).

## Linux / Unix (recommended)

Run releases from a clean working directory (fresh clone, or `git clean -fdx`) to avoid accidentally including local build outputs in published artifacts.

From the repository root:

```bash
./scripts/release/make-linux-release.sh Release build TGZ dist
```

This produces, in `dist/`:

- a `.tar.gz` (or `.tgz`) package built via CPack
- `SHA256SUMS`
- `SHA256SUMS.asc` (if `gpg` is available)

If you have multiple signing keys, set `QRY_RELEASE_GPG_KEY` to a fingerprint or key ID before running the script:

```bash
export QRY_RELEASE_GPG_KEY="<fingerprint-or-key-id>"
```

## Re-sign checksums (when artifacts already exist)

If you already have release artifacts in `dist/` and you want to regenerate checksums and a signature:

```bash
./scripts/release/sign-checksums.sh dist
```

## What to publish (GitHub Releases)

Attach:

- the packaged artifacts (for example `qryptcoin-<version>-linux-x86_64.tar.gz`)
- `SHA256SUMS`
- `SHA256SUMS.asc`
- `qryptcoin-release-key.asc` (public key export), if you are not hosting the key elsewhere

In release notes, include:

- the signing key fingerprint
- a short pointer to `docs/verify.md`
