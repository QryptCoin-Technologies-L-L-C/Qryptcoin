# Building and Running a Node

This document describes how to build the QryptCoin node daemon (`qryptd`) from source and run it as a fully-validating node. The build also produces local tooling binaries (`qrypt-cli`, `qrypt-payresolver`) for interacting with the node.

## Requirements

- CMake >= 3.22
- A C++20 toolchain
  - Windows: MSVC (Visual Studio 2022 recommended) or Clang/LLVM
  - Linux: Clang or GCC
- Optional (faster builds): Ninja
- Optional (tests): CTest (bundled with CMake)

Cryptographic dependencies are vendored in this repository under `vendor/` and `third_party/`.

### Linux (Ubuntu/Debian)

Install a baseline toolchain:

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build pkg-config
```

## Build

From the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

The resulting binaries will be placed under:

- Single-config generators (common on Linux/Ninja): `build/qryptd`
- Multi-config generators (common on Windows/MSVC): `build/Release/qryptd.exe`

On Windows/MSVC, configure and build with:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release --parallel
```

Additional binaries:

- `qrypt-cli`
- `qrypt-payresolver`

## Run

The node supports multiple networks:

- `mainnet`
- `testnet`
- `regtest`
- `signet`

Example:

```bash
./build/qryptd --network regtest --allow-generate
```

### Peer bootstrapping

The reference node ships with network-scoped DNS seed hostnames (and may include a small set of static seed hosts) for initial peer discovery.

For controlled environments, override bootstrapping by providing one or more peers explicitly:

- CLI: `--connect-peer <host:port>` (repeatable)
- Config file (`qryptcoin.conf`): `connect=<host:port>` (repeatable)
- Seed file (`data/<network>/seeds.json`): JSON array of host strings (uses the network's default P2P port)

By default the node stores runtime data under `data/<network>/`. You can override this with:

```bash
./build/qryptd --network mainnet --data-dir /path/to/data
```

### RPC

`qryptd` exposes a JSON-RPC server intended for local tooling and controlled operator environments.

Common flags (see `./build/qryptd --help` for the full set):

- `--rpc-bind <addr>` (default: `127.0.0.1`)
- `--rpc-port <port>` (default: network-specific)
- `--rpc-user <name>` and `--rpc-pass <secret>` (HTTP basic auth)
- `--rpc-pass-env <ENV_VAR>` (read password from environment)
- `--rpc-allow-ip <addr>` (repeatable allowlist for non-loopback clients)
- `--rpc-read-only` (disable mutating wallet/mining methods)
- `--allow-generate` (enable block generation RPCs on local test networks)

When running in the default local mode, the node writes a per-run cookie token to:

`data/<network>/rpc.cookie`

## Payment Codes (optional tooling)

Payment Codes are reusable identifiers that resolve to fresh one-time addresses without changing consensus rules. See `docs/payment_codes.md` for the format, trust model, and RPC details.

## Tests

Configure a build with tests enabled (default), then:

```bash
cd build
ctest --output-on-failure
```

Unit tests live under `tests/unit/` and integration tests under `tests/integration/`.

## Packaging (optional)

To produce a portable tarball containing the installed binaries:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cd build
cpack -G TGZ
```

### Release checksums and signatures (recommended)

To generate a release tarball plus `SHA256SUMS` and (if `gpg` is available) a detached signature `SHA256SUMS.asc`:

```bash
./scripts/release/make-linux-release.sh Release build TGZ dist
```

If you have multiple signing keys, set `QRY_RELEASE_GPG_KEY` to the fingerprint or key ID you intend to use.

See `docs/verify.md` for verification steps.

On Debian/Ubuntu, you can also produce a `.deb`:

```bash
cd build
cpack -G DEB
```
