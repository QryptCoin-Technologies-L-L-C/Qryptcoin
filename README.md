# QryptCoin Core

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11837/badge)](https://www.bestpractices.dev/projects/11837)

QryptCoin Core is the reference implementation of the QryptCoin protocol, maintained by **QryptCoin Technologies LLC**.

QryptCoin is a peer-to-peer electronic cash system that enables direct value transfer without reliance on centralized intermediaries. The system uses a proof-of-work blockchain to establish a globally ordered ledger of transactions, with ownership represented by unspent transaction outputs (UTXOs).

This repository contains the full node software required to participate in the QryptCoin network by validating blocks, relaying transactions, and enforcing consensus rules.

## Overview

The QryptCoin protocol combines a conservative proof-of-work consensus mechanism with post-quantum digital signatures to provide long-term cryptographic durability.

Key properties:

- Decentralized block production via proof-of-work
- Deterministic transaction validation rules
- Post-quantum transaction authorization
- Explicit witness commitment for malleability resistance
- Fixed and auditable consensus limits

This implementation enforces the consensus rules described in the protocol documentation and the published whitepaper.

## Network Resources

- **Block Explorer**: [explorer.qryptcoin.org](https://explorer.qryptcoin.org)
- **Mempool Explorer**: [mempool.qryptcoin.org](https://mempool.qryptcoin.org)
- **Website**: [qryptcoin.org](https://qryptcoin.org)
- **Telegram**: [Community](https://t.me/+uCf5QzVtJxlkM2Ix)


## Repository contents

This repository includes:

- Core node implementation (`qryptd`)
- Command-line client (`qrypt-cli`)
- Payment Code resolver proxy (`qrypt-payresolver`)
- Consensus and validation logic
- Peer-to-peer networking stack (encrypted transport and message framing)
- Wallet key management and signing logic (node tooling)
- Cryptographic primitives and utilities used by the protocol
- Build system and test framework
- Protocol and build documentation

This repository does not include:

- Block explorers
- Web interfaces or wallet GUIs
- Deployment or hosting configuration
- Monitoring or operational tooling
- Private infrastructure artifacts or environment-specific data

## Documentation

- Whitepaper: `docs/whitepaper.pdf`
- Protocol rules (implementation-grounded): `docs/protocol.md`
- Payment Codes (reusable identifiers): `docs/payment_codes.md`
- Build and run instructions: `docs/build.md`
- Testing: `docs/testing.md`
- Developer guide: `docs/dev.md`
- Verifying downloads: `docs/verify.md`
- Release process (maintainers): `docs/release.md`
- Audit checklist: `docs/audit-checklist.md`

## Building

Build instructions are provided in `docs/build.md`.

Typical build steps (Linux/macOS):

```bash
git clone https://github.com/QryptCoin-Technologies-L-L-C/Qryptcoin.git
cd Qryptcoin
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Windows (MSVC):

```powershell
git clone https://github.com/QryptCoin-Technologies-L-L-C/Qryptcoin.git
cd Qryptcoin
cmake -S . -B build -A x64
cmake --build build --config Release --parallel
```

## Running a node

By default, `qryptd` bootstraps peer discovery using the network's built-in DNS seeds (and optional static seed hosts).

Start a mainnet node:

```bash
./build/qryptd --network mainnet
```

For controlled environments, override bootstrapping by providing one or more peers explicitly:

```bash
./build/qryptd --network mainnet --connect-peer <host:port>
```

Additional peer bootstrapping options are described in `docs/build.md`.

## Tests

```bash
ctest --test-dir build --output-on-failure
```

## License

Source code is licensed under the MIT license: `LICENSE`.

