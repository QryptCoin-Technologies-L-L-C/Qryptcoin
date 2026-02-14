#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <span>

#include "config/network.hpp"
#include "consensus/monetary.hpp"
#include "nlohmann/json.hpp"
#include "node/chain_state.hpp"
#include "rpc/server.hpp"
#include "tx/primitives/txid.hpp"
#include "util/hex.hpp"
#include "wallet/hd_wallet.hpp"

int main() {
  try {
    using namespace qryptcoin;
    config::SelectNetwork(config::NetworkType::kRegtest);

    const std::filesystem::path test_root = "testdata_mempool_spent_utxo";
    std::error_code cleanup_ec;
    std::filesystem::remove_all(test_root, cleanup_ec);
    std::filesystem::create_directories(test_root);

    struct ScopedCleanup {
      std::filesystem::path root;
      ~ScopedCleanup() {
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
      }
    } cleanup{test_root};

    const auto wallet_path = (test_root / "wallet.dat").string();
    const auto blocks_path = (test_root / "blocks.dat").string();
    const auto utxo_path = (test_root / "utxo.dat").string();

    node::ChainState chain(blocks_path, utxo_path);
    std::string error;
    if (!chain.Initialize(&error)) {
      std::cerr << "Chain init failed: " << error << "\n";
      return EXIT_FAILURE;
    }

    auto wallet = wallet::HDWallet::Create(wallet_path, "pass",
                                           crypto::SignatureAlgorithm::kDilithium);
    if (!wallet) {
      std::cerr << "Failed to create wallet\n";
      return EXIT_FAILURE;
    }
    auto* wallet_ptr = wallet.get();

    rpc::RpcServer server(std::move(wallet),
                          /*wallet_enabled=*/true,
                          chain,
                          /*peers=*/nullptr,
                          /*sync=*/nullptr,
                          /*addrman=*/nullptr,
                          /*dns_seeds=*/nullptr,
                          /*is_seed_node=*/false,
                          /*default_mining_address=*/"",
                          /*allow_generate=*/true,
                          /*read_only=*/false,
                          /*mempool_limit_bytes=*/5 * 1024 * 1024);

    auto get_address = [&](const char* id) -> std::string {
      nlohmann::json req{{"jsonrpc", "2.0"},
                         {"id", id},
                         {"method", "getnewaddress"},
                         {"params", nlohmann::json::object()}};
      auto resp = server.Handle(req);
      if (resp.contains("error")) {
        throw std::runtime_error("getnewaddress error: " + resp["error"].dump());
      }
      return resp["result"]["address"].get<std::string>();
    };

    const auto addr1 = get_address("1");
    const auto addr2 = get_address("2");

    // Mine enough blocks so at least one coinbase UTXO is spendable.
    const std::uint64_t blocks_needed =
        static_cast<std::uint64_t>(consensus::kCoinbaseMaturity) + 1ULL;
    nlohmann::json req_gen{{"jsonrpc", "2.0"},
                           {"id", "3"},
                           {"method", "generatetoaddress"},
                           {"params", nlohmann::json::array({blocks_needed, addr1})}};
    auto resp_gen = server.Handle(req_gen);
    if (resp_gen.contains("error")) {
      std::cerr << "generatetoaddress error: " << resp_gen["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    // Create a confirmed spend that produces a non-coinbase change output
    // that the wallet will prefer spending next.
    nlohmann::json req_send1{{"jsonrpc", "2.0"},
                             {"id", "4"},
                             {"method", "sendtoaddress"},
                             {"params",
                              {{"address", addr2},
                               {"amount", "10.00000000"},
                               {"fee_rate", 1}}}};
    auto resp_send1 = server.Handle(req_send1);
    if (resp_send1.contains("error")) {
      std::cerr << "sendtoaddress (setup) error: " << resp_send1["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    // Confirm the transaction so its change output becomes available.
    nlohmann::json req_mine{{"jsonrpc", "2.0"},
                            {"id", "5"},
                            {"method", "generatetoaddress"},
                            {"params", nlohmann::json::array({1, addr1})}};
    auto resp_mine = server.Handle(req_mine);
    if (resp_mine.contains("error")) {
      std::cerr << "generatetoaddress (confirm) error: " << resp_mine["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    primitives::COutPoint change_outpoint{};
    primitives::Amount change_value = 0;
    bool found_change = false;
    for (const auto& utxo : wallet_ptr->TrackedUtxos()) {
      if (utxo.spent || utxo.orphaned) {
        continue;
      }
      if (!utxo.is_change || utxo.coinbase || utxo.watch_only) {
        continue;
      }
      if (!found_change || utxo.txout.value > change_value) {
        change_outpoint = utxo.outpoint;
        change_value = utxo.txout.value;
        found_change = true;
      }
    }
    if (!found_change) {
      std::cerr << "Failed to locate confirmed change UTXO\n";
      return EXIT_FAILURE;
    }
    if (change_value <= 15 * primitives::kMiksPerQRY) {
      std::cerr << "Unexpectedly small change output value\n";
      return EXIT_FAILURE;
    }

    // Create a mempool transaction that spends the change output, but do not
    // commit it to the wallet (simulates an interrupted commit or a legacy wallet).
    std::vector<std::pair<std::string, primitives::Amount>> outputs = {
        {addr2, 15 * primitives::kMiksPerQRY}};
    std::string create_error;
    auto created = wallet_ptr->CreateTransaction(outputs, /*fee_rate=*/1, &create_error);
    if (!created) {
      std::cerr << "CreateTransaction failed: " << create_error << "\n";
      return EXIT_FAILURE;
    }
    const auto mempool_txid = primitives::ComputeTxId(created->tx);
    const bool mempool_ok = server.AddToMempoolForTest(created->tx, /*feerate_miks_per_vb=*/1.0);
    if (!mempool_ok) {
      std::cerr << "Failed to add setup transaction to mempool\n";
      return EXIT_FAILURE;
    }

    // Sending should still succeed (the wallet has other UTXOs), but the
    // node should reconcile the mempool-spent change UTXO by marking it pending.
    nlohmann::json req_send2{{"jsonrpc", "2.0"},
                             {"id", "6"},
                             {"method", "sendtoaddress"},
                             {"params",
                              {{"address", addr2},
                               {"amount", "1.00000000"},
                               {"fee_rate", 1}}}};
    auto resp_send2 = server.Handle(req_send2);
    if (resp_send2.contains("error")) {
      std::cerr << "sendtoaddress error: " << resp_send2["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    nlohmann::json req_list{{"jsonrpc", "2.0"},
                            {"id", "7"},
                            {"method", "listutxos"},
                            {"params", nlohmann::json::object()}};
    auto resp_list = server.Handle(req_list);
    if (resp_list.contains("error")) {
      std::cerr << "listutxos error: " << resp_list["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    const auto target_txid_hex = util::HexEncode(
        std::span<const std::uint8_t>(change_outpoint.txid.data(), change_outpoint.txid.size()));
    const auto mempool_txid_hex = util::HexEncode(
        std::span<const std::uint8_t>(mempool_txid.data(), mempool_txid.size()));
    bool matched = false;
    for (const auto& entry : resp_list["result"]) {
      if (!entry.is_object()) {
        continue;
      }
      if (entry.value("txid", "") != target_txid_hex ||
          entry.value("vout", 0) != static_cast<int>(change_outpoint.index)) {
        continue;
      }
      matched = true;
      if (entry.value("state", "") != "pending") {
        std::cerr << "Expected change UTXO to be pending: " << entry.dump() << "\n";
        return EXIT_FAILURE;
      }
      if (entry.value("pending_txid", "") != mempool_txid_hex) {
        std::cerr << "Expected pending_txid to match mempool spender: " << entry.dump() << "\n";
        return EXIT_FAILURE;
      }
      break;
    }
    if (!matched) {
      std::cerr << "Did not find expected change UTXO in listutxos output\n";
      return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    std::cerr << "mempool_spent_utxo_sync_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
}
