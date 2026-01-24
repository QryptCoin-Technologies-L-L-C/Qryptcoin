#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "primitives/hash.hpp"

namespace qryptcoin::consensus {

// Witness commitment format v1 (consensus-critical):
//
// For every block, the coinbase input's unlocking_descriptor MUST be exactly:
//   [varint(height)] [uint64 extra_nonce LE] [tag] [32-byte witness_merkle_root]
//
// Note: v1 intentionally locks the coinbase unlocking_descriptor to this exact
// layout (no trailing bytes / extra fields). Coinbase extensibility therefore
// requires a future consensus upgrade (e.g. a new tag version and parsing rules).
//
// The witness merkle root is computed over per-tx wtxids (hash of the full
// transaction serialization including witness), with the special case that the
// coinbase wtxid is treated as 32 bytes of zero. This binds witness data to block
// validity and prevents "same header hash, different body" malleability classes.
//
// The tag is versioned to allow future commitment extensions without ambiguous
// parsing.
inline constexpr std::array<std::uint8_t, 5> kWitnessCommitmentTag{
    {'Q', 'R', 'Y', 'W', 0x01}};

inline constexpr std::size_t kCoinbaseExtraNonceSize = sizeof(std::uint64_t);
inline constexpr std::size_t kWitnessCommitmentRootSize = primitives::Hash256{}.size();
inline constexpr std::size_t kWitnessCommitmentSize =
    kWitnessCommitmentTag.size() + kWitnessCommitmentRootSize;

}  // namespace qryptcoin::consensus
