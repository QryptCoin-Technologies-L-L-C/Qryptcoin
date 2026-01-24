#include "consensus/block_hash.hpp"

#include <vector>

#include "crypto/hash.hpp"
#include "primitives/serialize.hpp"

namespace qryptcoin::consensus {

primitives::Hash256 ComputeBlockHash(const primitives::CBlockHeader& header) {
  std::vector<std::uint8_t> buffer;
  buffer.reserve(80);
  // 80-byte header format:
  // 4-byte version, 32-byte prev hash, 32-byte Merkle root,
  // 4-byte timestamp, 4-byte nBits, 4-byte nonce.
  primitives::serialize::WriteUint32(&buffer, header.version);
  buffer.insert(buffer.end(), header.previous_block_hash.begin(),
                header.previous_block_hash.end());
  buffer.insert(buffer.end(), header.merkle_root.begin(),
                header.merkle_root.end());
  primitives::serialize::WriteUint32(
      &buffer, static_cast<std::uint32_t>(header.timestamp));
  primitives::serialize::WriteUint32(&buffer, header.difficulty_bits);
  primitives::serialize::WriteUint32(
      &buffer, static_cast<std::uint32_t>(header.nonce));

  const auto hash = crypto::DoubleSha256(buffer);
  primitives::Hash256 result{};
  std::copy(hash.begin(), hash.end(), result.begin());
  return result;
}

}  // namespace qryptcoin::consensus
