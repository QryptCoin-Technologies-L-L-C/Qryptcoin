#include <cstdlib>
#include <iostream>

#include "consensus/block_weight.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/pq_engine.hpp"
#include "primitives/txid.hpp"

using namespace qryptcoin;

primitives::CTransaction MakeAnchorTx(const crypto::QPqDilithiumKey& dilithium) {
  primitives::CTransaction tx;
  tx.version = 1;
  tx.vin.resize(1);
  tx.vout.resize(1);
  tx.vout[0].value = 1;
  tx.vout[0].locking_descriptor.clear();
  tx.vin[0].prevout = primitives::COutPoint::Null();
  tx.vin[0].sequence = 0xFFFFFFFF;
  auto reveal = crypto::BuildP2QHReveal(dilithium.PublicKey());
  tx.vin[0].witness_stack.push_back({reveal});
  tx.vin[0].witness_stack.push_back(
      {std::vector<std::uint8_t>(crypto::DilithiumSignatureSize(), 0xBB)});
  return tx;
}

int main() {
  try {
    // Witness should not affect txid.
    primitives::CTransaction base;
    base.vin.resize(1);
    base.vout.resize(1);
    base.vout[0].value = 1;
    base.vin[0].prevout = primitives::COutPoint::Null();
    base.vin[0].sequence = 0xFFFFFFFF;
    auto with_witness = base;
    with_witness.vin[0].witness_stack.push_back({std::vector<std::uint8_t>{0x01, 0x02}});
    const auto txid_base = primitives::ComputeTxId(base);
    const auto txid_witness = primitives::ComputeTxId(with_witness);
    if (txid_base != txid_witness) {
      std::cerr << "Txid changed when witness changed\n";
      return EXIT_FAILURE;
    }

    // Adaptive block weight for Dilithium-only blocks.
    crypto::QPqDilithiumKey dilithium = crypto::QPqDilithiumKey::Generate();

    primitives::CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vout.resize(1);
    coinbase.vin[0].prevout = primitives::COutPoint::Null();
    coinbase.vout[0].value = 50;

    primitives::CBlock dil_block;
    dil_block.transactions = {coinbase,
                              MakeAnchorTx(dilithium),
                              MakeAnchorTx(dilithium)};
    auto dil_weight = consensus::CalculateBlockWeight(dil_block);
    auto dil_limit = consensus::AdaptiveBlockWeightLimit(dil_weight);
    if (dil_limit < 8'000'000 || dil_weight.weight > dil_limit) {
      std::cerr << "Dilithium-dominant block not granted max elasticity\n";
      return EXIT_FAILURE;
    }

    // With a single signature scheme there is no SPHINCS-only or
    // hybrid path to compare against; remaining elasticity tests are
    // no longer applicable.
  } catch (const std::exception& ex) {
    std::cerr << "weight_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << "weight_tests unknown exception\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
