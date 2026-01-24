# Payment Codes (PAYCODE_V1) - Reusable Identifiers with One-Time Addresses

QryptCoin consensus enforces one-time public keys: a public key revealed in a spend may not be revealed again on the active chain. As a result, reusing the same on-chain receive address for multiple payments can strand funds (multiple outputs would commit to the same public key, but only one spend can reveal it).

Payment Codes solve this at the wallet layer by introducing a reusable, publishable identifier that resolves (interactively) to a fresh one-time address per payment request. Consensus rules remain unchanged.

## Scope and invariants

- Payment Codes are not a new output type and do not change consensus.
- Each payment still uses the standard P2QH template:
  - `program = H3(REVEAL_V1_bytes)` (32 bytes)
  - `scriptPubKey = OP_1 || PUSH_32 || program`
- The one-time public key rule remains enforced by consensus; Payment Codes only reduce accidental address reuse by making "reusable address" semantics explicit in the wallet UX.

## PAYCODE_V1 (binary format)

`PAYCODE_V1` is a fixed 80-byte structure:

```
6  bytes  magic                 = "QRYPC1"
1  byte   version               = 0x01
4  bytes  network_id            = uint32_le
1  byte   kdf_id                = 0x01  (SHA3-256 based derivation)
32 bytes  scan_pubkey           = 32-byte identifier (reserved for future scanning protocols)
32 bytes  spend_root_commitment = 32-byte commitment to the wallet's receive derivation root
4  bytes  checksum              = first4( H3(all prior bytes) )
```

Canonical rules:

- `magic` MUST match exactly.
- `version` MUST be `0x01`.
- `network_id` MUST match the active network.
- `kdf_id` MUST be `0x01`.
- `checksum` MUST match `first4(SHA3-256(payload[0..75]))`.
- No trailing bytes are permitted (exact length 80 bytes).

## Human encoding (canonical)

Payment Codes are encoded as a network-scoped ASCII string:

```
<hrp> "pay1" <base32(payload80)>
```

Where:

- `<hrp>` is the network address HRP (e.g. `qry`, `tqry`, `rqry`, `sqry`).
- `base32` uses the lowercase RFC-4648 character set with no padding.
- The payload is always 80 bytes, so the base32 portion is always 128 characters.
- Mixed-case encodings are rejected; only lowercase is accepted.

Examples (prefix only):

- Mainnet: `qrypay1...`
- Testnet: `tqrypay1...`
- Regtest: `rqrypay1...`
- Signet: `sqrypay1...`

## Interactive resolution (production-safe)

Payment Codes are resolved to a one-time address via an interactive step:

1. Recipient publishes a Payment Code (static, safe to reuse).
2. Sender resolves the Payment Code using a resolver endpoint controlled by the recipient (or a trusted delegate).
3. Resolver returns a fresh one-time P2QH address.
4. Sender creates a normal transaction paying that one-time address.

This design avoids introducing new cryptography into consensus and does not require any non-standard witness attachments.

### Trust model

- The resolver can return any valid address; senders must treat resolution as an address-assignment service (similar to receiving an invoice).
- `PAYCODE_V1` does not authenticate a resolver endpoint or response. The reference resolver (`qrypt-payresolver`) is plain HTTP and responses are not independently signed.
- Transport security (e.g., running behind an HTTPS reverse proxy) does not change the fundamental trust assumption that the resolver can redirect payments. Until authenticated resolver transport and/or signed responses exist, recommended deployments are:
  - Localhost-only resolver on the same machine as the recipient wallet node.
  - An authenticated secure channel such as an SSH tunnel or VPN to a trusted resolver.

### Freshness and replay controls

To reduce accidental replay/caching issues and to make resolver behavior auditable, `resolvepaymentcode` supports an explicit challenge and an explicit validity window:

- The client supplies `challenge_b64` (base64 of exactly 16 bytes).
- The server echoes `challenge_b64` and returns `issued_height` and `expiry_height`.
- The CLI verifies the challenge matches and refuses to send if the response is expired relative to the local node height.

These controls do not provide authenticity against a malicious resolver; they only help ensure the client is acting on a fresh, non-accidentally-replayed resolution.

The reference CLI (`qrypt-cli sendto`) defaults to `--resolver-policy=local-only` and refuses non-local resolvers unless explicitly enabled.

## Reference RPC surface

Wallet RPCs:

- `getpaymentcode`: returns the wallet's canonical Payment Code string for the active network.
- `validatepaymentcode <code>`: parses and validates a Payment Code; returns decoded fields.
- `resolvepaymentcode <code>`: verifies the code matches the loaded wallet and returns a fresh one-time address, along with challenge/expiry metadata.

These RPCs are intended for local use. Public exposure should be done via a minimal gateway that only forwards `resolvepaymentcode` and does not expose any spend or wallet-mutation methods.

## Operational scenarios

### What if the resolver is down?

- The sender cannot obtain a fresh one-time address and should not send funds.
- Retry later, or use a trusted local resolver path (localhost / authenticated tunnel) where available.

### What if the resolved address expires?

- Expiry is a sender-side safety check (not a consensus rule).
- The CLI refuses to send when the resolution is expired; re-run the resolve step to obtain a fresh address.

### What if the recipient wallet crashes after issuing an address?

- The wallet persists the issued address reservation before returning it, so it will not be reissued after restart.
- Funds sent to a previously issued one-time address remain spendable by the recipient wallet (the key material is retained).

### What if someone reuses a one-time address on a donation page?

- Multiple payments can still arrive to the same one-time address, but only one spend can reveal the committed public key under consensus rules.
- Use Payment Codes for any reusable public identifier; treat one-time addresses as single-use.
