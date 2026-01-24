#include "node/mining_extranonce.hpp"

#include <cstdint>

#include "primitives/serialize.hpp"
#include "primitives/transaction.hpp"

namespace qryptcoin::node {

std::optional<std::size_t> FindCoinbaseExtraNonceOffset(
    const primitives::CBlock& block) {
  if (block.transactions.empty()) {
    return std::nullopt;
  }
  const auto& coinbase = block.transactions.front();
  if (coinbase.vin.size() != 1) {
    return std::nullopt;
  }
  const auto& input = coinbase.vin.front();
  const auto& desc = input.unlocking_descriptor;
  constexpr std::size_t kExtraSize = sizeof(std::uint64_t);
  std::size_t cursor = 0;
  std::uint64_t encoded_height = 0;
  if (!primitives::serialize::ReadVarInt(desc, &cursor, &encoded_height)) {
    return std::nullopt;
  }
  if (cursor + kExtraSize > desc.size()) {
    return std::nullopt;
  }
  return cursor;
}

void SetCoinbaseExtraNonce(primitives::CBlock* block, std::size_t offset,
                           std::uint64_t extra_nonce) {
  if (!block || block->transactions.empty()) return;
  auto& coinbase = block->transactions.front();
  if (coinbase.vin.empty()) return;
  auto& input = coinbase.vin.front();
  auto& desc = input.unlocking_descriptor;
  constexpr std::size_t kExtraSize = sizeof(std::uint64_t);
  if (offset + kExtraSize > desc.size()) {
    return;
  }
  for (std::size_t i = 0; i < kExtraSize; ++i) {
    desc[offset + i] = static_cast<std::uint8_t>((extra_nonce >> (8 * i)) & 0xFFu);
  }
}

}  // namespace qryptcoin::node
