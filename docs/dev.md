# Developer Guide

This document is a high-level map of the reference implementation to help contributors navigate the codebase.

## Repository layout

- `src/consensus/`: consensus-critical rules and validation
- `src/tx/`: transaction and block primitives, serialization, and policy
- `src/net/`: peer-to-peer transport, handshake, and message framing
- `src/node/`: node orchestration, chainstate, storage, mining template builder, RPC
- `src/wallet/`: non-custodial wallet engine used by node tooling
- `src/crypto/`: protocol cryptographic primitives and encodings
- `src/util/`: shared utilities (AEAD, KDFs, secure wiping, hex, system)
- `vendor/` and `third_party/`: vendored cryptographic and utility dependencies required to build without network access

The build produces:

- `qryptcore` (static library): core node implementation
- `qryptd` (executable): node daemon entrypoint
- `qrypt-cli` (executable): local JSON-RPC client and node tooling
- `qrypt-payresolver` (executable): Payment Code HTTP resolver proxy (restricted method allowlist)

## Entry points

- Node daemon: `src/node/qryptd.cpp`
- Consensus parameter selection: `src/consensus/params.cpp`
- Block validation: `src/consensus/block_validator.cpp`
- Chainstate / best-chain selection: `src/node/chain_state.cpp`
- Block and transaction relay/sync: `src/node/block_sync.cpp`
- P2P messaging: `src/net/messages.cpp`
- Encrypted transport + authentication: `src/net/encrypted_channel.cpp`, `src/net/transport_auth.cpp`
- Wallet engine: `src/wallet/hd_wallet.cpp`

## Runtime architecture

At a high level, `qryptd`:

1. Selects the network and loads consensus parameters.
2. Initializes on-disk state (block store and UTXO snapshot) via `node::ChainState`.
3. Starts the P2P listener and outbound connections via `net::PeerManager`.
4. Starts block/header synchronization via `node::BlockSyncManager`.
5. Starts the local JSON-RPC server via `rpc::HttpServer` and `rpc::RpcServer` (if enabled).

### Concurrency model (overview)

- `net::PeerManager` runs a listener thread and an idle-sweeper thread.
- `node::BlockSyncManager` runs one worker thread per connected peer session plus a background stall watcher.
- `rpc::HttpServer` runs a single worker thread to accept and serve HTTP requests; `rpc::RpcServer` also runs a background maintenance loop for mempool persistence/expiration when enabled.

All consensus-critical state is anchored by `node::ChainState` and guarded with internal synchronization.

## Consensus vs policy

Consensus rules determine whether blocks and transactions are valid for the network. Policy rules are local admission/relay rules (mempool and transaction relay shaping).

- Consensus validation lives under `src/consensus/` and `src/tx/primitives/`.
- Policy lives under `src/tx/policy/` and node-local mempool logic in `src/node/rpc/server.cpp`.

When changing consensus rules:

- Keep behavior deterministic and test-covered.
- Update `docs/protocol.md` when the rule is consensus-critical.

## Cryptography dependencies

This repository vendors the cryptographic dependencies required for deterministic builds:

- `vendor/liboqs/` (ML-KEM-768 and ML-DSA-65 primitives)
- `third_party/dilithium/` (Dilithium3 reference code for deterministic cross-checks and KATs; not used for on-chain signing/verification)
- `vendor/argon2/` (wallet KDF)
- `third_party/nlohmann/` (JSON)

## Testing and contribution workflow

- Testing instructions: `docs/testing.md`
- Contribution guidelines: `CONTRIBUTING.md`
