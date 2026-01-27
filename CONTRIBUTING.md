# Contributing to QryptCoin

## Development Setup

- CMake (>= 3.25)
- A C++20 compiler (MSVC, Clang, or GCC)
- Ninja recommended (optional)

Configure/build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --config Debug
```

Run tests:

```bash
ctest --test-dir build --output-on-failure
```

See `docs/testing.md` for running subsets and platform notes.

## Coding Guidelines

- Keep changes focused and include tests when practical.
- Run formatting on touched C++ files (`.clang-format` is provided).
- Avoid adding large binaries/build artifacts to Git; use `.gitignore` and GitHub Releases/LFS as appropriate.

## Security Expectations

- **Report vulnerabilities privately**: follow `SECURITY.md` (do not open public issues for security bugs).
- **Assume all network input is hostile**: P2P and RPC payloads must be treated as untrusted.
- **Prefer bounded resource usage**: add decode-time caps, timeouts, and bounded queues for attacker-controlled data.
- **Avoid rolling your own crypto**: reuse existing primitives in this repo; new cryptographic constructions require explicit maintainer review.
- **Consensus-critical changes**: PRs touching validation, chainstate, or serialization must include tests and clear rationale.
- **Security testing**: when relevant, add regression tests and consider fuzz targets (`docs/security/fuzzing.md`).

## Pull Requests

- Describe the problem and the solution clearly.
- Link related issues or discussions.
- Note any security implications and backwards-compatibility concerns.
