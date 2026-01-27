# Threat Model (QryptCoin Core)

## Scope

This document describes the threat model for the QryptCoin Core repository, focusing on:

- Full node daemon (`qryptd`)
- Peer-to-peer networking stack (framing, encrypted transport, protocol messages)
- Chainstate storage and validation pipeline
- Wallet tooling in this repo (key storage, signing)
- RPC server surface

Out of scope:

- External services (explorers, websites, hosted infrastructure)
- Third-party wallets and integrations
- Operating system compromise of the host running the node

## Security objectives

- **Consensus safety**: never accept/produce invalid blocks or transactions.
- **Key safety**: protect private keys at rest and in memory as reasonably possible.
- **Network robustness**: remain resilient to malformed input and resource exhaustion attempts.
- **Operator safety**: prevent unsafe default configurations (especially RPC exposure).
- **Supply-chain integrity**: keep builds reproducible and dependencies auditable.

## Assets

- Wallet private keys, seeds, and passphrases
- Funds controlled by the wallet / signing logic
- Chainstate correctness and on-disk data integrity (blocks, UTXO set, snapshots)
- Node availability (CPU, memory, disk, bandwidth)
- Peer connectivity (ability to sync and relay)

## Adversary model

- **Remote network attacker**: sends malformed/hostile P2P traffic or attempts DoS.
- **Malicious peer(s)**: behaves protocol-adjacent but adversarial (stalling, flooding, eclipse attempts).
- **RPC attacker**: unauthenticated or low-privilege access attempting command abuse or input attacks.
- **Supply-chain attacker**: malicious dependency changes, compromised CI, or injected artifacts.
- **Insider / compromised contributor account**: malicious PRs or commits.

## Trust boundaries & assumptions

- P2P traffic is **fully untrusted**.
- RPC traffic is untrusted unless explicitly authenticated and bound/allowed by configuration.
- Local filesystem is trusted only to the extent the host OS is trusted; the node must tolerate partial corruption
  and report errors without undefined behavior.
- Vendored dependencies are treated as externally-audited code and should be minimized and versioned.

## Attack surfaces

### P2P networking

- Message framing and decoding (`src/net/channel.*`, `src/net/messages.*`)
- Handshakes and encrypted/authenticated transport (`src/net/handshake.*`, `src/net/transport_auth.*`)
- Peer management, inbound throttling, ban scoring (`src/net/peer_manager.*`)
- Sync scheduling and stall recovery (`src/node/block_sync.*`)

Threats:

- Memory corruption via malformed payloads
- CPU exhaustion via handshake floods / expensive cryptography
- Memory exhaustion via oversized varint counts / unbounded queues
- Network-level eclipse attempts and peer graph manipulation
- Liveness failures (sync stalls) caused by scheduling deadlocks

### RPC surface

- Authentication/binding and request parsing (`src/node/rpc/http_server.*`, `src/node/rpc/server.*`)
- Potentially dangerous methods (wallet management, mining RPCs, transaction submission)

Threats:

- Unauthorized RPC access (misconfiguration)
- Input validation bugs (JSON parsing, parameter handling)
- Resource abuse via repeated heavy RPC calls

### Wallet & signing

- Wallet file handling and key derivation (`src/wallet/*`, `src/util/*kdf*`, `src/crypto/*`)

Threats:

- Weak passphrase handling, unsafe key material exposure
- Side-channel leaks in cryptographic operations (timing/memory)
- Malformed wallet file causing crashes

### Chainstate & storage

- Block/tx parsing (`src/tx/primitives/serialize.*`)
- On-disk block store and snapshots (`src/node/storage/*`)

Threats:

- Malformed blocks/transactions triggering crashes or excessive allocations
- Disk exhaustion and partial writes
- Snapshot corruption handling

### Supply chain

- CI workflows, dependency updates, and release artifacts

Threats:

- Compromised GitHub Actions or dependency updates
- Unsigned/unauthenticated release artifacts
- Accidental inclusion of secrets or large binaries

## Mitigations (current posture)

- Decode-time DoS caps for protocol messages (see `net/messages.hpp` limits).
- Peer management controls: inbound throttling, subnet caps, ban scoring (`src/net/peer_manager.*`).
- Sync resilience: explicit stall detection, timeout requeue, and recovery logic (`src/node/block_sync.*`).
- RPC auth posture: local bind defaults and auth support (`SECURITY.md`, `src/node/rpc/*`).
- Vendored crypto and PQ primitives are minimized and reviewed for integrity (`vendor/`, `third_party/`).

## Residual risks / roadmap

- Expand fuzzing coverage (message parsing, serialization, RPC parameter parsing).
- Improve automated coverage reporting for critical code paths.
- Maintain SBOM generation for each release and major change set.
- Periodically revisit this threat model alongside major protocol or networking changes.

