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

## Pull Requests

- Describe the problem and the solution clearly.
- Link related issues or discussions.
- Note any security implications and backwards-compatibility concerns.
