#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "crypto/hash.hpp"
#include "crypto/pq_engine.hpp"

namespace qryptcoin::net {

crypto::Sha3_256Hash ComputeTransportAuthTranscriptHash(
    std::uint32_t protocol_version,
    std::uint64_t initiator_services,
    std::uint64_t responder_services,
    std::uint8_t initiator_preferred_mode,
    std::uint8_t responder_preferred_mode,
    bool initiator_requires_encryption,
    bool responder_requires_encryption,
    std::span<const std::uint8_t> initiator_identity_pubkey,
    std::span<const std::uint8_t> responder_identity_pubkey,
    std::span<const std::uint8_t> initiator_kyber_pubkey,
    std::span<const std::uint8_t> responder_kyber_ciphertext);

// Loads (or creates) the node's long-term transport identity used for signing
// handshake transcripts. The identity is persisted inside `data_dir`.
//
// If `data_dir` is empty, an ephemeral in-memory identity is generated.
bool LoadOrCreateTransportIdentity(const std::filesystem::path& data_dir,
                                   std::shared_ptr<crypto::QPqDilithiumKey>* out,
                                   std::string* error = nullptr);

// Enforces a trust-on-first-use (TOFU) policy for a peer identity key.
// When the peer has no existing pin and `allow_tofu` is true, the key is
// persisted and the function returns true with `pinned_new=true`.
//
// When a pin exists and the key differs, the function returns false.
bool EnforcePeerIdentityPin(const std::filesystem::path& data_dir,
                            const std::string& peer_key_id,
                            std::span<const std::uint8_t> peer_public_key,
                            bool allow_tofu,
                            bool* pinned_new,
                            std::string* error = nullptr);

// Optional seed-node pinning for the first outbound connections:
// `data_dir/p2p_seed_pins.txt` may predefine trusted identity keys for bootstrap
// peers (for example static seeds). When an entry exists for either
// `peer_key_id` or `peer_host`, the identity key must match.
bool EnforceSeedIdentityPin(const std::filesystem::path& data_dir,
                            const std::string& peer_key_id,
                            const std::string& peer_host,
                            std::span<const std::uint8_t> peer_public_key,
                            bool* had_pin,
                            std::string* error = nullptr);

// Track peers that have previously negotiated encrypted transport successfully.
// When a peer is in this set, subsequent plaintext negotiations are rejected
// for outbound connections to resist downgrade attacks.
bool EnforcePeerEncryptionHistory(const std::filesystem::path& data_dir,
                                  const std::string& peer_key_id,
                                  bool negotiated_encryption,
                                  std::string* error = nullptr);

}  // namespace qryptcoin::net
