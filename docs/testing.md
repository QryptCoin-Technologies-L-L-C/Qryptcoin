# Testing

This repository uses CTest to run unit and integration test executables built from `tests/`.

## Build with tests

Tests are enabled by default. To build and run them:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

On multi-config generators (common on Windows/MSVC), select a configuration:

```bash
ctest --test-dir build -C Release --output-on-failure
```

To disable building tests:

```bash
cmake -S . -B build -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

## Running subsets

CTest supports selecting tests by name:

```bash
ctest --test-dir build -R qrypt_unit_ --output-on-failure
ctest --test-dir build -R qrypt_integration_ --output-on-failure
```

## Coverage

Code coverage reporting is supported on Linux via GCC/GCov + `gcovr`.

```bash
cmake -S . -B build-coverage -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS=--coverage \
  -DCMAKE_CXX_FLAGS=--coverage \
  -DCMAKE_EXE_LINKER_FLAGS=--coverage \
  -DCMAKE_SHARED_LINKER_FLAGS=--coverage
cmake --build build-coverage --parallel
ctest --test-dir build-coverage --output-on-failure
gcovr --root . --object-directory build-coverage --print-summary
gcovr --root . --object-directory build-coverage --html-details -o build-coverage/coverage.html
```

CI also publishes a coverage artifact on pull requests (see `.github/workflows/coverage.yml`).

## Notes

- Integration tests use temporary directories for on-disk state and clean them up on success.
- `tests/unit/crypto/pq_kat_tests.cpp` contains deterministic known-answer checks for selected primitives.

## Related

- Contributor workflow: `CONTRIBUTING.md`
- Pre-release scans: `docs/audit-checklist.md`
