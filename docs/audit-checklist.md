# Audit Checklist (Pre-Release)

This checklist documents the scans and validation steps used to prepare this repository for a public release. It is not a guarantee of absence of defects.

Notes:

- This checklist focuses on QryptCoin-authored code and documentation. Vendored dependencies under `vendor/` and `third_party/` may contain their own terminology and comments, and are reviewed primarily for integrity and licensing.

## Brand and provenance scrub

- Scan for legacy brand residue and protocol-name carryovers (case-insensitive):

```sh
git grep -n -I -i -E "b[iI]t[cC]o[iI]n|\\bb[tT]c\\b|s[aA]t[oO]s[hH]i|s[eE]g[wW][iI]t|\\bb[iI]p[0-9]*\\b" -- \
  README.md CONTRIBUTING.md SECURITY.md THIRD_PARTY_NOTICES.md CMakeLists.txt docs src include tests scripts
```

- Scan for provenance-style annotations:

```sh
git grep -n -I -i -E "cop(y|ied)[ -]?from|generated[ -]?by" -- \
  README.md CONTRIBUTING.md SECURITY.md THIRD_PARTY_NOTICES.md CMakeLists.txt docs src include tests scripts
```

## Documentation posture

- Scan for staging language and placeholder markers:

```sh
git grep -n -I -i -E "t[oO]d[oO]|w[iI]p|p[rR]e[- ]m[aA]i[nN]n[eE]t|p[rR]o[oO]f[- ]o[fF][- ]c[oO]n[cC]e[pP]t|e[xX]p[eE]r[iI]m[eE]n[tT]a[lL]" -- \
  README.md docs
```

- Scan for release-stage qualifiers:

```sh
git grep -n -I -i -E "(^|[^[:alnum:]_])a[lL]p[hH]a([^[:alnum:]_]|$)|(^|[^[:alnum:]_])b[eE]t[aA]([^[:alnum:]_]|$)" -- README.md docs
```

## Secrets and credentials

- Scan for common secret indicators:

```sh
git grep -n -I -i -E "password|secret|api[_-]?key|token|private[ -]?key|seed[ -]?phrase" -- \
  README.md CONTRIBUTING.md SECURITY.md THIRD_PARTY_NOTICES.md CMakeLists.txt docs src include tests scripts
```

- Scan for embedded private key blocks:

```sh
git grep -n -I -E "BEGIN (RSA|OPENSSH|PRIVATE KEY)|-----BEGIN" -- .
```

## Infrastructure and environment residue

- Scan for hard-coded endpoints and IP address literals:

```sh
git grep -n -I -E "([0-9]{1,3}\\.){3}[0-9]{1,3}|ssh-|scp|rsync|\\.env\\b" -- \
  README.md CONTRIBUTING.md SECURITY.md THIRD_PARTY_NOTICES.md CMakeLists.txt docs src include tests scripts
```

## Build validation

- Configure and build from a clean directory:

```sh
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

On Windows/MSVC, use:

```sh
cmake -S . -B build -A x64
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```
