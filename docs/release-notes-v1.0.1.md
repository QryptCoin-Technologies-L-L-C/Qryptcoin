# QryptCoin Core v1.0.1 (Security / Reliability Patch)

Release date: 2026-02-02

## Critical fix: wallet "missing UTXO" send failures

This release fixes a critical wallet bug where the wallet could track stale or phantom UTXOs as spendable, leading to failed sends with:

`transaction rejected: missing UTXO`

### What changed

- Wallet UTXOs now have a lifecycle state (`available` / `pending` / `spent` / `orphaned`) instead of a single irreversible `spent` boolean.
- When creating a send, inputs and change are marked `pending` (reversible). They are only finalized when the transaction is confirmed in a block.
- If a transaction is evicted from the mempool, the wallet rolls back the pending spend and removes any unconfirmed change output (preventing phantom UTXOs).
- RPC send handlers now proactively prune wallet UTXOs against the chain + mempool view before coin selection so invalid inputs are never selected.

### User recovery (if you are already affected)

Run:

- `qrypt-cli resyncwallet`

This purges the wallet's cached UTXO set and rescans the chain to rebuild it from the node's UTXO view.

If you need to limit rescan time, you can specify a height:

- `qrypt-cli resyncwallet --start-height=<N>`

## Compatibility / upgrade notes

- **Wallet file format:** v1.0.1 writes wallet format **v8**. Once opened/saved by v1.0.1, the wallet file may not be readable by older wallet binaries.
- This release does **not** change consensus rules. It is safe to roll out to nodes gradually.

