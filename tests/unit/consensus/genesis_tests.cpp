#include <filesystem>
#include <iostream>
#include <span>
#include <string>

#include "config/network.hpp"
#include "consensus/params.hpp"
#include "node/chain_state.hpp"
#include "util/hex.hpp"

int main() {
  using namespace qryptcoin;
  config::SelectNetwork(config::NetworkType::kMainnet);
  const auto& params = consensus::Params(config::NetworkType::kMainnet);
  const std::string expected_hash = "0005e7b27df8abff6982375f8d1523a5a7c4b34d37e0349dfc5d66ddb98806fb";
  const std::string expected_merkle = "3889dc912e3d2c3ada9b81d1b8374b6bbace274c98da9a142ecc5517b2217ffc";

  auto hash_hex =
      util::HexEncode(std::span<const std::uint8_t>(params.genesis_hash.data(), params.genesis_hash.size()));
  auto merkle_hex = util::HexEncode(std::span<const std::uint8_t>(params.genesis_block.header.merkle_root.data(),
                                                                  params.genesis_block.header.merkle_root.size()));

  std::cerr << "Computed genesis hash=" << hash_hex << " merkle=" << merkle_hex << "\n";
  if (hash_hex != expected_hash) {
    std::cerr << "Genesis hash mismatch: expected " << expected_hash << "\n";
    return EXIT_FAILURE;
  }
  if (merkle_hex != expected_merkle) {
    std::cerr << "Genesis merkle root mismatch: expected " << expected_merkle << "\n";
    return EXIT_FAILURE;
  }

  auto temp_root = std::filesystem::temp_directory_path() / "qryptcoin-genesis-test";
  std::filesystem::remove_all(temp_root);
  std::filesystem::create_directories(temp_root);

  node::ChainState chain((temp_root / "blocks.dat").string(), (temp_root / "utxo.dat").string());
  std::string error;
  if (!chain.Initialize(&error)) {
    std::cerr << "Chain init failed: " << error << "\n";
    return EXIT_FAILURE;
  }
  if (chain.BlockCount() != 1) {
    std::cerr << "Expected exactly one block after genesis bootstrap\n";
    return EXIT_FAILURE;
  }
  const auto* tip = chain.Tip();
  if (!tip) {
    std::cerr << "Missing chain tip after genesis bootstrap\n";
    return EXIT_FAILURE;
  }
  auto tip_hash =
      util::HexEncode(std::span<const std::uint8_t>(tip->hash.data(), tip->hash.size()));
  if (tip_hash != expected_hash) {
    std::cerr << "Genesis block hash mismatch in chain state\n";
    return EXIT_FAILURE;
  }

  std::filesystem::remove_all(temp_root);
  return EXIT_SUCCESS;
}
