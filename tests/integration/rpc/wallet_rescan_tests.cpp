#include <cstdlib>
#include <filesystem>
#include <iostream>

#include "nlohmann/json.hpp"
#include "rpc/server.hpp"
#include "node/chain_state.hpp"

int main() {
  try {
    using namespace qryptcoin;
    const std::filesystem::path test_root = "testdata_rescan";
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

    rpc::RpcServer server(/*wallet=*/nullptr,
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
                          /*mempool_limit_bytes=*/1 * 1024 * 1024);

    nlohmann::json req_unloaded{{"jsonrpc", "2.0"},
                                {"id", "0"},
                                {"method", "getwalletinfo"},
                                {"params", nlohmann::json::object()}};
    auto resp_unloaded = server.Handle(req_unloaded);
    if (!resp_unloaded.contains("error") ||
        resp_unloaded["error"]["message"].get<std::string>() != "wallet not loaded") {
      std::cerr << "Expected getwalletinfo to report wallet not loaded, got "
                << resp_unloaded.dump() << "\n";
      return EXIT_FAILURE;
    }

    // Bind the wallet to the path via RPC so metadata and rescan logic are
    // exercised through the same surface as qryptd.
    nlohmann::json req_create{
        {"jsonrpc", "2.0"},
        {"id", "1"},
        {"method", "createwallet"},
        {"params",
         {{"wallet_name", "RescanWallet"},
          {"wallet_path", wallet_path},
          {"passphrase", "pass"}}}};
    auto resp_create = server.Handle(req_create);
    if (resp_create.contains("error")) {
      std::cerr << "createwallet error: " << resp_create["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    // Derive a fresh address and mine a single block to it.
    nlohmann::json req_addr{
        {"jsonrpc", "2.0"},
        {"id", "2"},
        {"method", "getnewaddress"},
        {"params", nlohmann::json::object()}};
    auto resp_addr = server.Handle(req_addr);
    if (resp_addr.contains("error")) {
      std::cerr << "getnewaddress error: " << resp_addr["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    const auto addr = resp_addr["result"]["address"].get<std::string>();

    nlohmann::json req_gen{
        {"jsonrpc", "2.0"},
        {"id", "3"},
        {"method", "generatetoaddress"},
        {"params", nlohmann::json::array({1, addr})}};
    auto resp_gen = server.Handle(req_gen);
    if (resp_gen.contains("error")) {
      std::cerr << "generatetoaddress error: " << resp_gen["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    // Balance and transaction list should reflect a mined coinbase output.
    nlohmann::json req_info{
        {"jsonrpc", "2.0"},
        {"id", "4"},
        {"method", "getwalletinfo"},
        {"params", nlohmann::json::object()}};
    auto resp_info = server.Handle(req_info);
    if (resp_info.contains("error")) {
      std::cerr << "getwalletinfo error: " << resp_info["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    const auto balance_before_str =
        resp_info["result"]["balance"].get<std::string>();
    const double balance_before = std::stod(balance_before_str);
    if (balance_before <= 0.0) {
      std::cerr << "Expected positive balance after mining, got "
                << balance_before << "\n";
      return EXIT_FAILURE;
    }

    nlohmann::json req_txs{
        {"jsonrpc", "2.0"},
        {"id", "5"},
        {"method", "listtransactions"},
        {"params", nlohmann::json::object()}};
    auto resp_txs = server.Handle(req_txs);
    if (resp_txs.contains("error")) {
      std::cerr << "listtransactions error: " << resp_txs["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    const auto tx_array = resp_txs["result"];
    if (!tx_array.is_array() || tx_array.empty()) {
      std::cerr << "Expected at least one transaction after mining\n";
      return EXIT_FAILURE;
    }
    const auto last_tx = tx_array.back();
    if (!last_tx.value("incoming", false) ||
        !last_tx.value("coinbase", false)) {
      std::cerr << "Last transaction is not marked as incoming coinbase\n";
      return EXIT_FAILURE;
    }

    // Simulate a restart: rebuild chain state from disk and reload the wallet.
    node::ChainState chain2(blocks_path, utxo_path);
    if (!chain2.Initialize(&error)) {
      std::cerr << "Chain re-init failed: " << error << "\n";
      return EXIT_FAILURE;
    }

    rpc::RpcServer server2(/*wallet=*/nullptr,
                           /*wallet_enabled=*/true,
                           chain2,
                           /*peers=*/nullptr,
                           /*sync=*/nullptr,
                           /*addrman=*/nullptr,
                           /*dns_seeds=*/nullptr,
                           /*is_seed_node=*/false,
                           /*default_mining_address=*/"",
                           /*allow_generate=*/true,
                           /*read_only=*/false,
                           /*mempool_limit_bytes=*/1 * 1024 * 1024);

    // Exercise the loadwallet + rescan path, which should pick up the
    // coinbase output even if the in-memory state starts empty.
    nlohmann::json req_load{
        {"jsonrpc", "2.0"},
        {"id", "6"},
        {"method", "loadwallet"},
        {"params", {{"path", wallet_path}, {"passphrase", "pass"}}}};
    auto resp_load = server2.Handle(req_load);
    if (resp_load.contains("error")) {
      std::cerr << "loadwallet error: " << resp_load["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    nlohmann::json req_info2{
        {"jsonrpc", "2.0"},
        {"id", "7"},
        {"method", "getwalletinfo"},
        {"params", nlohmann::json::object()}};
    auto resp_info2 = server2.Handle(req_info2);
    if (resp_info2.contains("error")) {
      std::cerr << "getwalletinfo (after restart) error: "
                << resp_info2["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    const auto balance_after_str =
        resp_info2["result"]["balance"].get<std::string>();
    const double balance_after = std::stod(balance_after_str);
    if (balance_after < balance_before - 1e-8) {
      std::cerr << "Balance decreased across restart: before="
                << balance_before << " after=" << balance_after << "\n";
      return EXIT_FAILURE;
    }

    nlohmann::json req_txs2{
        {"jsonrpc", "2.0"},
        {"id", "8"},
        {"method", "listtransactions"},
        {"params", nlohmann::json::object()}};
    auto resp_txs2 = server2.Handle(req_txs2);
    if (resp_txs2.contains("error")) {
      std::cerr << "listtransactions (after restart) error: "
                << resp_txs2["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    const auto tx_array2 = resp_txs2["result"];
    if (!tx_array2.is_array() || tx_array2.empty()) {
      std::cerr << "No transactions after restart\n";
      return EXIT_FAILURE;
    }
    const auto last_tx2 = tx_array2.back();
    if (!last_tx2.value("incoming", false) ||
        !last_tx2.value("coinbase", false)) {
      std::cerr << "Coinbase transaction lost or misclassified after restart\n";
      return EXIT_FAILURE;
    }

  } catch (const std::exception& ex) {
    std::cerr << "wallet_rescan_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
