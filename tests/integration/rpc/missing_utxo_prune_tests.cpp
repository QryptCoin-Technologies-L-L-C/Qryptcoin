#include <cstdlib>
#include <filesystem>
#include <iostream>

#include "config/network.hpp"
#include "consensus/monetary.hpp"
#include "nlohmann/json.hpp"
#include "node/chain_state.hpp"
#include "rpc/server.hpp"
#include "wallet/hd_wallet.hpp"

int main() {
  try {
    using namespace qryptcoin;
    config::SelectNetwork(config::NetworkType::kRegtest);

    const std::filesystem::path test_root = "testdata_missing_utxo";
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

    nlohmann::json req_addr{{"jsonrpc", "2.0"},
                            {"id", "1"},
                            {"method", "getnewaddress"},
                            {"params", nlohmann::json::object()}};
    auto resp_addr = server.Handle(req_addr);
    if (resp_addr.contains("error")) {
      std::cerr << "getnewaddress error: " << resp_addr["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    const auto addr = resp_addr["result"]["address"].get<std::string>();

    // Mine enough blocks so at least one coinbase UTXO is spendable.
    const std::uint64_t blocks_needed =
        static_cast<std::uint64_t>(consensus::kCoinbaseMaturity) + 1ULL;
    nlohmann::json req_gen{{"jsonrpc", "2.0"},
                           {"id", "2"},
                           {"method", "generatetoaddress"},
                           {"params", nlohmann::json::array({blocks_needed, addr})}};
    auto resp_gen = server.Handle(req_gen);
    if (resp_gen.contains("error")) {
      std::cerr << "generatetoaddress error: " << resp_gen["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    // Inject a phantom wallet UTXO with a larger value than the real mined
    // outputs so the wallet would select it without pruning.
    auto script = wallet_ptr->ScriptForAddress(addr);
    if (!script) {
      std::cerr << "ScriptForAddress failed\n";
      return EXIT_FAILURE;
    }
    auto key_index_opt = wallet_ptr->KeyIndexForAddress(addr);
    if (!key_index_opt.has_value()) {
      std::cerr << "KeyIndexForAddress failed\n";
      return EXIT_FAILURE;
    }

    primitives::COutPoint phantom_outpoint;
    phantom_outpoint.txid.fill(0xAB);
    phantom_outpoint.index = 0;
    primitives::CTxOut phantom_txout;
    phantom_txout.value = 100 * primitives::kMiksPerQRY;
    phantom_txout.locking_descriptor = *script;
    wallet::WalletUTXO phantom;
    phantom.outpoint = phantom_outpoint;
    phantom.txout = phantom_txout;
    phantom.key_index = *key_index_opt;
    phantom.algorithm = crypto::SignatureAlgorithm::kDilithium;
    wallet_ptr->AddUTXO(phantom);
    wallet_ptr->Save();

    // Attempting to send should succeed: the RPC handler must prune the phantom
    // UTXO (mark orphaned) before coin selection so mempool validation does not
    // fail with "missing UTXO".
    nlohmann::json req_send{{"jsonrpc", "2.0"},
                            {"id", "3"},
                            {"method", "sendtoaddress"},
                            {"params",
                             {{"address", addr},
                              {"amount", "1.00000000"}}}};
    auto resp_send = server.Handle(req_send);
    if (resp_send.contains("error")) {
      std::cerr << "sendtoaddress error: " << resp_send["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    nlohmann::json req_list{{"jsonrpc", "2.0"},
                            {"id", "4"},
                            {"method", "listutxos"},
                            {"params", nlohmann::json::object()}};
    auto resp_list = server.Handle(req_list);
    if (resp_list.contains("error")) {
      std::cerr << "listutxos error: " << resp_list["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    std::string phantom_txid_hex;
    phantom_txid_hex.reserve(64);
    for (std::size_t i = 0; i < phantom_outpoint.txid.size(); ++i) {
      phantom_txid_hex += "ab";
    }

    const auto utxos = resp_list["result"];
    bool saw_phantom = false;
    for (const auto& entry : utxos) {
      if (!entry.is_object()) {
        continue;
      }
      if (entry.value("txid", "") == phantom_txid_hex &&
          entry.value("vout", 0) == 0) {
        saw_phantom = true;
        if (entry.value("state", "") != "orphaned") {
          std::cerr << "Phantom UTXO was not marked orphaned: " << entry.dump() << "\n";
          return EXIT_FAILURE;
        }
      }
    }
    if (!saw_phantom) {
      std::cerr << "Expected phantom UTXO entry to remain tracked\n";
      return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    std::cerr << "missing_utxo_prune_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
}
