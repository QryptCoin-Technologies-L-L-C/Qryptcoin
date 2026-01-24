# QryptCoin Protocol Notes (Consensus and Wire Rules)

This document is an implementation-grounded summary of consensus-critical rules and hard network limits enforced by the reference node. It is intended for external developers, auditors, and researchers.

For a full technical narrative, see `docs/whitepaper.pdf`.

## Scope: consensus vs policy

- **Consensus** rules determine what all validating nodes must accept or reject (block and transaction validity).
- **Policy** rules are local relay/mining preferences (mempool admission, relay shaping). Policy must not affect block validity.

This file calls out both. When a limit is **consensus-critical**, it is labeled as such.

## Units

- **QRY** is the human unit.
- **Mik** is the smallest indivisible unit: `1 QRY = 100,000,000 Miks`.
- Maximum monetary supply is `21,000,000 QRY` (enforced by issuance schedule and range checks).

## Cryptographic primitives

- **Proof-of-work hash**: `SHA256(SHA256(header_80))`
- **`H3(x)`**: SHA3-256
- **`H3^2(x)`**: SHA3-256(SHA3-256(x))
- **Transaction signatures**: ML-DSA-65 only
- **Transport key establishment**: ML-KEM-768
- **Transport AEAD**: ChaCha20-Poly1305

## Transactions

QryptCoin uses an unspent output (UTXO) model: transactions consume previous outputs and create new outputs.

### Serialization (consensus-critical)

Transactions serialize in a v2 encoding with optional segregated witness:

```
version: uint32_le
[marker=0x00 flag=0x01]   // only when witness is present
vin_count: varint
  (prev_txid: 32 bytes || prev_index: uint32_le || unlocking_descriptor: varbytes || sequence: uint32_le) repeated
vout_count: varint
  (value: uint64_le || locking_descriptor: varbytes) repeated
[witness]                 // only when witness is present
lock_time: uint32_le
```

Where `varbytes` means `varint(length) || length bytes`.

Per-input witness serialization is:

```
witness_item_count: varint
  (item_len: varint || item_bytes) repeated
```

Consensus caps:

- `witness_item_count <= 64` for every input.

### Identifiers (consensus-critical)

Let `SER_base(tx)` be the transaction serialization excluding witness, and `SER_full(tx)` include witness.

- `txid  = H3(SER_base(tx))`
- `wtxid = H3(SER_full(tx))`

### Outputs: pay-to-quantum-hash (P2QH) (consensus-critical)

Outputs commit to a 32-byte witness program:

- `program = H3(reveal_bytes)` (32 bytes)

The locking descriptor for a P2QH output is:

```
OP_1 || PUSH_32 || program
```

Address encoding uses bech32m witness version 1, with network-specific HRP.

### Authorization witness (consensus-critical)

To spend a P2QH output, an input must satisfy:

- `unlocking_descriptor` MUST be empty.
- `witness_stack` MUST contain exactly two items:
  1) `reveal_bytes` (REVEAL_V1)
  2) `signature` (ML-DSA-65 over the per-input sighash)

### Canonical public-key reveal: REVEAL_V1 (consensus-critical)

`reveal_bytes` MUST be encoded exactly as:

```
u8   version   = 0x01
u8   algo_id   = 0x01   (ML-DSA-65 only)
u8   params_id = 0x01   (Dilithium3 fixed)
u16  reserved  = 0x0000 (LE; must be zero)
u16  pk_len    = 1952   (LE)
u8[] pk_bytes  = pk_len bytes
```

Rules:

- `reserved != 0` is invalid.
- `pk_len != 1952` is invalid.
- Trailing bytes are not permitted (total length must be exactly `7 + 1952`).

### Domain-separated sighash: QRY-SIGHASH-V1 (consensus-critical)

Each input signs a fixed-mode sighash with tag `QRY-SIGHASH-V1` (literal ASCII bytes).

Let:

- `PrevoutsHash = H3(outpoint_0 || ... || outpoint_{n-1})` where `outpoint = txid || uint32_le(index)`
- `SeqHash = H3(sequence_0 || ... || sequence_{n-1})` where `sequence` is `uint32_le`
- `OutputsHash = H3(value_0 || script_0 || ... || value_{m-1} || script_{m-1})` where
  - `value` is `uint64_le`
  - `script` is `varint(len(locking_descriptor)) || locking_descriptor`

Then input `i` signs:

```
H3(
  "QRY-SIGHASH-V1" ||
  version ||
  PrevoutsHash ||
  SeqHash ||
  outpoint_i ||
  varint(len(locking_descriptor_spent)) || locking_descriptor_spent ||
  value_spent ||
  sequence_i ||
  OutputsHash ||
  lock_time
)
```

No optional sighash modes are defined in v1.

### Locktime and sequence rules (consensus-critical)

- Absolute `lock_time` is supported.
- Relative sequence locks are supported for **height-based** locks only.
- Relative time-based sequence locks are rejected.

### One-time public keys (consensus-critical)

Authorization is one-time at the public-key level.

1) For every transaction input, parse `reveal_bytes` and extract `pk_bytes`.
2) Compute `pk_hash = H3(pk_bytes)` (32 bytes).
3) Maintain a consensus-critical set containing all `pk_hash` values revealed in the **active chain**.
4) A block is invalid if any input reveals a `pk_hash` already present in the set.

Additional rules:

- Reuse of the same public key within a single transaction is invalid.
- The revealed-key set is updated during block connect/disconnect (reorg-safe) alongside UTXO updates.
- The reference node persists this state to disk as a snapshot (`*.pubkeys`) and tip metadata (`*.pubkeys.meta`) and can rebuild it deterministically from blocks.

### Coinbase maturity (consensus-critical)

Outputs created by the coinbase transaction are spendable only after **100** additional blocks.

## Blocks

### Block header (consensus-critical)

The wire header is fixed at 80 bytes:

```
version: uint32_le
prev_block_hash: 32 bytes
merkle_root: 32 bytes          // over txids
timestamp: uint32_le
difficulty_bits: uint32_le     // compact target encoding
nonce: uint32_le
```

### Merkle roots (consensus-critical)

- The header `merkle_root` commits to `txid` leaves.
- Internal nodes hash as `H3^2(left || right)`.
- If a level has an odd number of nodes, the last hash is duplicated.

### Witness commitment (consensus-critical)

For every block (including genesis), the coinbase transaction's first input field `unlocking_descriptor` MUST be exactly:

```
varint(height)
|| uint64_le(extra_nonce)
|| {'Q','R','Y','W',0x01}
|| 32-byte witness_merkle_root
```

Parsing rules (strict):

- The `unlocking_descriptor` MUST start with the canonical varint encoding of the block height.
- The total size MUST match the layout above exactly (no trailing bytes).
- The tag MUST match exactly.
- The committed witness merkle root MUST equal the computed value.

Consensus caps:

- Coinbase `unlocking_descriptor` length MUST be `<= 100` bytes.

Witness merkle root computation:

- Leaves are `wtxid` values, except the coinbase leaf is treated as 32 bytes of zero.
- Internal nodes use `H3^2(left || right)`.

### Block weight and size (consensus-critical)

Block weight is computed as:

```
weight = 4 * base_bytes + witness_bytes
```

Consensus limits (enforced independently):

- Maximum block weight: **8,000,000**
- Maximum fully-serialized block size (base + witness): **1,048,576 bytes**

### Timestamp validity (consensus-critical)

Let `MTP` be the median of the previous 11 block timestamps (or fewer near genesis). Blocks must satisfy:

- `timestamp > MTP`
- `timestamp <= local_time + 2 hours`

### Difficulty adjustment (consensus-critical)

- Target block spacing: 600 seconds
- Adjustment interval: 2016 blocks
- Compact target encoding follows the mantissa/exponent format used by the implementation.

## Fees and mempool policy (policy)

- Fee rate unit: **Miks/vB** (Miks per virtual byte).
- Default minimum relay fee: **1.0 Miks/vB** (policy; not consensus).

## P2P wire limits

### Frame payload cap (hard limit)

The transport uses framed messages. The maximum frame payload is:

- **1,048,640 bytes** (`1,048,576 + 64`)

### Message decode caps (hard limits)

To prevent unbounded allocations during decode:

- Max inventory entries: 50,000
- Max getdata entries: 50,000
- Max locator hashes: 64
- Max headers results: 2,000
- Max `network_id` length in version message: 64 bytes

### Handshake message sizes (hard limits)

The encrypted transport handshake uses fixed-size payloads under the selected suites:

- ML-KEM-768 public key: 1184 bytes
- ML-KEM-768 ciphertext: 1088 bytes
- ML-DSA-65 public key: 1952 bytes
- ML-DSA-65 signature: 3309 bytes

Therefore:

- HandshakeInit payload: `1184 + 1952 = 3136` bytes
- HandshakeResponse payload: `1088 + 1952 + 3309 = 6349` bytes
- HandshakeFinalize payload: `3309` bytes

After the handshake, application messages are protected with ChaCha20-Poly1305 inside encrypted frames.

## Wallet mnemonic requirements (node tooling)

Wallets use **24-word English mnemonics only**:

- Mnemonics that are not exactly 24 words are rejected.
- The embedded mnemonic wordlist contains exactly 2048 lowercase ASCII words and is used without modification.
- Seed derivation uses PBKDF2-HMAC-SHA512 with 2048 iterations to produce a 64-byte seed.
- The 64-byte seed is mapped to a 32-byte master seed via `H3(seed64)`.

Deterministic per-index ML-DSA key generation uses:

```
drbg_seed_i = H3("QRY-MLDSA-KEYGEN-V1" || master_seed32 || LE32(i))
```

The key generation DRBG is implemented as a SHAKE256 XOF feeding the ML-DSA key generator through a deterministic `randombytes` hook (no system RNG input).

