# Networking Module

## Responsibilities
- TCP transport with length-prefixed message framing (`net/socket.*`, `net/channel.*`).
- Kyber-768 + Dilithium-authenticated encrypted transport (`net/encrypted_channel.*`, `net/transport_auth.*`).
- Inventory/version/ping/pong and handshake messages (`net/messages.*`).
- Peer manager that orchestrates connection state, pre-handshake gating/throttles, and relay shaping (`net/peer_manager.*`).

## Message Framing

Every payload rides inside a fixed 10-byte header followed by `payload_length` bytes.
All multi-byte fields are little-endian.

```
struct FrameHeader {
  uint32 magic;          // per-network message_start (e.g. "QRY!")
  uint16 command;        // message type enum
  uint32 payload_length; // bytes following header
}
payload bytes...
```

## Encryption Modes

- **Encrypted (default)**: peers run a Kyber + Dilithium handshake, then wrap every message in
  `Command::kEncryptedFrame` using ChaCha20-Poly1305. The frame header remains plaintext; the inner command and payload
  are encrypted.
- **Plaintext (debug/regtest)**: peers skip the encrypted handshake and exchange raw messages unencrypted.

Operators should enforce `--require-encryption` / `--require-authenticated-transport` on real networks.

### Handshake overview

- `HandshakeInit`: initiator sends `kyber_public_key || identity_public_key`.
- `HandshakeResponse`: responder sends `kyber_ciphertext || identity_public_key || signature`.
- `HandshakeFinalize`: initiator sends `signature`.

Both sides compute a transcript hash that commits to negotiated protocol parameters (protocol version + services bits),
both identity public keys, and the Kyber exchange. The responder signs this transcript in `HandshakeResponse`, and the
initiator signs it in `HandshakeFinalize`.

Session keys are derived from `shared_secret || transcript_hash || info` using SHA3-256 with domain-separated `info`
strings (`"qrypt-send"` / `"qrypt-recv"`).

Trust is enforced by `--require-authenticated-transport` (persistent identity + peer key pinning; TOFU by default).
TOFU remains vulnerable on first contact unless operators pin trusted peer keys out-of-band.

### Persistence

- `data/<network>/p2p_identity.dilithium`: node identity keypair (created on first run).
- `data/<network>/p2p_peer_pins.txt`: TOFU pins learned from successful handshakes.
- `data/<network>/p2p_seed_pins.txt`: optional pre-configured pins for bootstrap peers (reduces TOFU window).

## Directory Layout
- `net/messages.*` - raw message structures + encode/decode helpers.
- `net/channel.*` - frame parser + writer (plaintext + encrypted variants).
- `net/encrypted_channel.*` - Kyber encaps/decap, transcript signatures, AEAD framing.
- `net/peer_session.*` - version/verack + handshake negotiation.
- `net/peer_manager.*` - accept/connect, caps/throttles, peer bookkeeping.
