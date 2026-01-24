#include <cstdlib>
#include <filesystem>
#include <iostream>

#include "nlohmann/json.hpp"
#include "node/chain_state.hpp"
#include "rpc/server.hpp"

int main() {
  try {
    using namespace qryptcoin;

    std::filesystem::create_directories("testdata");
    node::ChainState chain("testdata/disabled-wallet-blocks.dat",
                           "testdata/disabled-wallet-utxo.dat");
    std::string error;
    if (!chain.Initialize(&error)) {
      std::cerr << "Chain init failed: " << error << "\n";
      return EXIT_FAILURE;
    }

    rpc::RpcServer server(/*wallet=*/nullptr,
                          /*wallet_enabled=*/false,
                          chain,
                          /*peers=*/nullptr,
                          /*sync=*/nullptr,
                          /*addrman=*/nullptr,
                          /*dns_seeds=*/nullptr,
                          /*is_seed_node=*/false,
                          /*default_mining_address=*/"",
                          /*allow_generate=*/false,
                          /*read_only=*/false,
                          /*mempool_limit_bytes=*/1 * 1024 * 1024);

    nlohmann::json wallet_req{{"jsonrpc", "2.0"},
                              {"id", "1"},
                              {"method", "getwalletinfo"},
                              {"params", nlohmann::json::object()}};
    auto wallet_resp = server.Handle(wallet_req);
    if (!wallet_resp.contains("error")) {
      std::cerr << "Expected getwalletinfo to be disabled when wallet subsystem is disabled\n";
      return EXIT_FAILURE;
    }
    if (wallet_resp["error"]["code"].get<int>() != -32601) {
      std::cerr << "Expected getwalletinfo error code -32601, got "
                << wallet_resp["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    if (wallet_resp["error"]["message"].get<std::string>().find("wallet disabled") ==
        std::string::npos) {
      std::cerr << "Expected wallet disabled message, got "
                << wallet_resp["error"].dump() << "\n";
      return EXIT_FAILURE;
    }

    nlohmann::json bc_req{{"jsonrpc", "2.0"},
                          {"id", "2"},
                          {"method", "getblockchaininfo"},
                          {"params", nlohmann::json::object()}};
    auto bc_resp = server.Handle(bc_req);
    if (bc_resp.contains("error")) {
      std::cerr << "getblockchaininfo error: " << bc_resp["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    if (!bc_resp.contains("result") || !bc_resp["result"].is_object()) {
      std::cerr << "getblockchaininfo result missing\n";
      return EXIT_FAILURE;
    }
    if (!bc_resp["result"].contains("default_policy")) {
      std::cerr << "getblockchaininfo missing default_policy\n";
      return EXIT_FAILURE;
    }

    std::filesystem::remove("testdata/disabled-wallet-blocks.dat");
    std::filesystem::remove("testdata/disabled-wallet-utxo.dat");
  } catch (const std::exception& ex) {
    std::cerr << "wallet_disabled_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
