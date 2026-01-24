#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "config/network.hpp"
#include "primitives/amount.hpp"
#include "primitives/block.hpp"
#include "primitives/hash.hpp"

namespace qryptcoin::consensus {

struct DeploymentParams {
  const char* name{nullptr};
  int bit{0};
  std::uint32_t start_time{0};   // UNIX timestamp when signaling can start.
  std::uint32_t timeout{0};      // UNIX timestamp after which deployment fails.
  std::uint32_t window_size{0};  // Number of blocks per signaling window.
  std::uint32_t threshold{0};    // Blocks in window required to lock in.
};

struct ChainParams {
  config::NetworkType network{config::NetworkType::kMainnet};
  std::string network_id;
  std::string hrp;
  std::uint32_t target_block_time_seconds{0};
  std::uint32_t p2p_default_port{0};
  std::uint32_t rpc_default_port{0};
  primitives::Amount max_supply_miks{0};
  primitives::Amount initial_subsidy_miks{0};
  std::uint32_t halving_interval_blocks{0};
  std::uint32_t coinbase_maturity{0};
  std::string pow_function;
  // Consensus cap on the number of bytes in a fully-serialized block
  // (header + transactions, including witness when present). This must
  // be compatible with the P2P transport frame limits.
  std::uint32_t max_block_serialized_bytes{0};
  std::uint32_t difficulty_adjustment_interval{0};
  // Height at which difficulty retargeting begins. Before this height,
  // nodes require blocks to use `pow_limit_bits`. Set to 0 to enable
  // retargeting from genesis.
  std::uint32_t difficulty_adjustment_activation_height{0};
  // Height at which the witness commitment becomes mandatory.
  std::uint32_t witness_commitment_activation_height{0};
  std::uint32_t pow_limit_bits{0};
  std::uint32_t genesis_bits{0};
  std::uint32_t genesis_time{0};
  std::uint32_t genesis_nonce{0};
  std::string genesis_message;
  primitives::CBlock genesis_block;
  primitives::Hash256 genesis_hash;
  std::vector<DeploymentParams> deployments;
};

const ChainParams& Params(config::NetworkType type);

}  // namespace qryptcoin::consensus
