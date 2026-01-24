# Verifying Downloads

Official release artifacts are published alongside:

- `SHA256SUMS` (checksums)
- `SHA256SUMS.asc` (a detached OpenPGP signature over `SHA256SUMS`)

This lets you verify both integrity (the file you downloaded is unchanged) and authenticity (the checksums were signed by the QryptCoin release key).

## 1) Verify Checksums

From the directory containing the downloaded artifact and `SHA256SUMS`:

```bash
sha256sum --check SHA256SUMS
```

You should see `OK` for the file you downloaded.

### Windows (PowerShell)

PowerShell can compute a SHA-256 digest without additional tools:

```powershell
Get-FileHash .\qryptcoin-<artifact>.tar.gz -Algorithm SHA256
```

Compare the printed hash to the corresponding line in `SHA256SUMS`.

## 2) Verify the Signature

Import the published QryptCoin release signing key (example: from a local file you downloaded from the same release page):

```bash
gpg --import qryptcoin-release-key.asc
```

Then verify the signature:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
```

GPG should report a **good signature** from the QryptCoin release key.

## Notes

- Checksums are verified locally; no network access is required.
- For maximum assurance, compare the release key fingerprint you imported against the fingerprint published on the official release page.
