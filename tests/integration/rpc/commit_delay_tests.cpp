#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "config/network.hpp"
#include "crypto/p2qh_address.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/pq_engine.hpp"
#include "crypto/hash.hpp"
#include "nlohmann/json.hpp"
#include "node/chain_state.hpp"
#include "primitives/serialize.hpp"
#include "rpc/server.hpp"
#include "script/p2qh.hpp"

using namespace qryptcoin;

namespace {

constexpr std::uint32_t kCommitDelayFlag = 0x80000000u;

primitives::CTransaction MakeStandardTx(std::uint8_t tag, std::uint32_t version) {
  auto key = crypto::QPqDilithiumKey::Generate();
  const auto reveal = crypto::BuildP2QHReveal(key.PublicKey());
  const auto descriptor = crypto::DescriptorFromReveal(reveal);

  primitives::CTransaction tx;
  tx.version = version;
  tx.lock_time = 0;
  tx.vin.resize(1);
  tx.vout.resize(1);

  tx.vin[0].prevout.txid.fill(tag);
  tx.vin[0].prevout.index = 0;
  tx.vin[0].unlocking_descriptor.clear();
  tx.vin[0].sequence = 0xFFFFFFFFu;

  primitives::WitnessStackItem reveal_item;
  reveal_item.data = reveal;
  primitives::WitnessStackItem sig_item;
  sig_item.data.assign(crypto::DilithiumSignatureSize(), tag);
  tx.vin[0].witness_stack = {reveal_item, sig_item};

  script::ScriptPubKey script_pub = script::CreateP2QHScript(descriptor);
  tx.vout[0].value = 1;
  tx.vout[0].locking_descriptor = script_pub.data;

  return tx;
}

primitives::Hash256 ComputeCommitment(const primitives::CTransaction& tx) {
  std::vector<std::uint8_t> raw;
  primitives::serialize::SerializeTransaction(tx, &raw, /*include_witness=*/true);
  const auto digest = crypto::Sha3_256(raw);
  primitives::Hash256 out{};
  std::copy(digest.begin(), digest.end(), out.begin());
  return out;
}

}  // namespace

int main() {
  try {
    config::SelectNetwork(config::NetworkType::kRegtest);
    const auto& cfg = config::GetNetworkConfig();

    std::filesystem::create_directories("testdata");
    node::ChainState chain("testdata/commit-delay-blocks.dat", "testdata/commit-delay-utxo.dat");

    auto mining_key = crypto::QPqDilithiumKey::Generate();
    const auto mining_reveal = crypto::BuildP2QHReveal(mining_key.PublicKey());
    const auto mining_desc = crypto::DescriptorFromReveal(mining_reveal);
    const std::string mining_address = crypto::EncodeP2QHAddress(mining_desc, cfg.bech32_hrp);

    rpc::RpcServer server(/*wallet=*/nullptr,
                          /*wallet_enabled=*/false,
                          chain,
                          /*peers=*/nullptr,
                          /*sync=*/nullptr,
                          /*addrman=*/nullptr,
                          /*dns_seeds=*/nullptr,
                          /*is_seed_node=*/false,
                          /*default_mining_address=*/mining_address,
                          /*allow_generate=*/true,
                          /*read_only=*/false,
                          /*mempool_limit_bytes=*/10'000'000);

    // Mine two blocks so a 1-block delay can be satisfied.
    for (int i = 0; i < 2; ++i) {
      nlohmann::json req = {
          {"jsonrpc", "2.0"},
          {"id", i + 1},
          {"method", "generate"},
          {"params", {{"blocks", 1}}},
      };
      const auto resp = server.Handle(req);
      if (resp.contains("error")) {
        std::cerr << "generate failed: " << resp.dump() << "\n";
        return EXIT_FAILURE;
      }
    }

    // Create a commit-delay transaction with a 1-block delay.
    primitives::CTransaction tx = MakeStandardTx(/*tag=*/0x55, /*version=*/kCommitDelayFlag | 1u);
    const auto commitment = ComputeCommitment(tx);

    // Without a prior commitment announcement, the mempool must reject it.
    if (server.AddToMempoolForTest(tx, /*feerate_miks_per_vb=*/1.0)) {
      std::cerr << "expected commit-delay tx to be rejected without a commitment\n";
      return EXIT_FAILURE;
    }

    // Announce the commitment now; since it was first seen at height >= 1,
    // it should still require a delay before being accepted.
    server.NotifyTransactionCommitmentFromNetwork(commitment, /*peer_id=*/0);
    if (server.AddToMempoolForTest(tx, /*feerate_miks_per_vb=*/1.0)) {
      std::cerr << "expected commit-delay tx to be rejected before delay elapses\n";
      return EXIT_FAILURE;
    }

    // Mine one more block to satisfy the delay.
    nlohmann::json req = {
        {"jsonrpc", "2.0"},
        {"id", 99},
        {"method", "generate"},
        {"params", {{"blocks", 1}}},
    };
    const auto resp = server.Handle(req);
    if (resp.contains("error")) {
      std::cerr << "generate failed: " << resp.dump() << "\n";
      return EXIT_FAILURE;
    }

    if (!server.AddToMempoolForTest(tx, /*feerate_miks_per_vb=*/1.0)) {
      std::cerr << "expected commit-delay tx to be accepted after delay\n";
      return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    std::cerr << "commit_delay_tests: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
}

