#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_TYPE="${1:-Release}"
BUILD_DIR="${2:-build}"
GENERATOR="${3:-TGZ}"
OUT_DIR="${4:-dist}"

cd "${ROOT_DIR}"

mkdir -p "${OUT_DIR}"

./scripts/build/package.sh "${BUILD_TYPE}" "${BUILD_DIR}" "${GENERATOR}"

mapfile -t packages < <(ls -1t "${BUILD_DIR}"/*.tar.gz "${BUILD_DIR}"/*.tgz 2>/dev/null || true)
if [[ ${#packages[@]} -eq 0 ]]; then
  echo "error: no package produced in ${BUILD_DIR} (expected *.tar.gz or *.tgz)" >&2
  exit 1
fi

pkg="${packages[0]}"
dest="${OUT_DIR}/$(basename "${pkg}")"
cp -f "${pkg}" "${dest}"
echo "wrote ${dest}"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${OUT_DIR}" && sha256sum "$(basename "${dest}")" > SHA256SUMS)
  echo "wrote ${OUT_DIR}/SHA256SUMS"
else
  echo "warning: sha256sum not found; skipping checksum generation" >&2
fi

if command -v gpg >/dev/null 2>&1; then
  gpg_key="${QRY_RELEASE_GPG_KEY:-}"
  (
    cd "${OUT_DIR}"
    if [[ -n "${gpg_key}" ]]; then
      gpg --batch --yes --local-user "${gpg_key}" --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
    else
      gpg --batch --yes --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
    fi
  )
  echo "wrote ${OUT_DIR}/SHA256SUMS.asc"
else
  echo "note: gpg not found; skipping signature generation" >&2
fi
