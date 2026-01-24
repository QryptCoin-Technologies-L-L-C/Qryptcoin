#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-dist}"

cd "${ROOT_DIR}/${OUT_DIR}"

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "error: sha256sum not found" >&2
  exit 1
fi

if ! command -v gpg >/dev/null 2>&1; then
  echo "error: gpg not found" >&2
  exit 1
fi

rm -f SHA256SUMS SHA256SUMS.asc

mapfile -t files < <(ls -1 *.tar.gz *.tgz 2>/dev/null || true)
if [[ ${#files[@]} -eq 0 ]]; then
  echo "error: no release artifacts found in ${ROOT_DIR}/${OUT_DIR} (expected *.tar.gz or *.tgz)" >&2
  exit 1
fi

sha256sum "${files[@]}" > SHA256SUMS
gpg_key="${QRY_RELEASE_GPG_KEY:-}"
if [[ -n "${gpg_key}" ]]; then
  gpg --batch --yes --local-user "${gpg_key}" --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
else
  gpg --batch --yes --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
fi

echo "wrote SHA256SUMS"
echo "wrote SHA256SUMS.asc"
