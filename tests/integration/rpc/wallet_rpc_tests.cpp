#include <cstdlib>
#include <filesystem>
#include <iostream>

#include "nlohmann/json.hpp"
#include "node/chain_state.hpp"
#include "primitives/txid.hpp"
#include "rpc/server.hpp"
#include "util/hex.hpp"
#include "wallet/hd_wallet.hpp"

int main() {
  try {
    using namespace qryptcoin;
    std::filesystem::create_directories("testdata");
    const std::string wallet_path = "testdata/rpc-wallet.dat";
    const std::string backup_path = "testdata/rpc-wallet-backup.dat";
    std::filesystem::remove(wallet_path);
    std::filesystem::remove(backup_path);
    node::ChainState chain("testdata/blocks.dat", "testdata/utxo.dat");
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
                          /*allow_generate=*/false,
                          /*read_only=*/false,
                          1 * 1024 * 1024);  // 1 MB mempool limit for tests.

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

    nlohmann::json req_create{
        {"jsonrpc", "2.0"},
        {"id", "1"},
        {"method", "createwallet"},
        {"params",
         {{"wallet_name", "TestWallet"},
          {"wallet_path", wallet_path},
          {"passphrase", "pass"}}}};
    auto resp_create = server.Handle(req_create);
    if (resp_create.contains("error")) {
      std::cerr << "createwallet error: " << resp_create["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    nlohmann::json req_backup{
        {"jsonrpc", "2.0"},
        {"id", "2"},
        {"method", "backupwallet"},
        {"params", {{"destination", backup_path}}}};
    auto resp_backup = server.Handle(req_backup);
    if (resp_backup.contains("error")) {
      std::cerr << "backupwallet error: " << resp_backup["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    if (!std::filesystem::exists(backup_path)) {
      std::cerr << "Backup file missing\n";
      return EXIT_FAILURE;
    }
    nlohmann::json req_encrypt{
        {"jsonrpc", "2.0"},
        {"id", "3"},
        {"method", "encryptwallet"},
        {"params", {{"passphrase", "newpass"}}}};
    auto resp_encrypt = server.Handle(req_encrypt);
    if (resp_encrypt.contains("error")) {
      std::cerr << "encryptwallet error: " << resp_encrypt["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    nlohmann::json req_load{
        {"jsonrpc", "2.0"},
        {"id", "4"},
        {"method", "loadwallet"},
        {"params", {{"path", wallet_path}, {"passphrase", "newpass"}}}};
    auto resp_load = server.Handle(req_load);
    if (resp_load.contains("error")) {
      std::cerr << "loadwallet error: " << resp_load["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    // Basic mempool fee floor sanity: with an empty mempool the minimum
    // relay feerate should default to a small non-zero value (1 Mik/vB),
    // matching the default relay floor enforced by the node.
    nlohmann::json req_mempool{{"jsonrpc", "2.0"},
                               {"id", "5"},
                               {"method", "getmempoolinfo"},
                               {"params", nlohmann::json::object()}};
    auto resp_mempool = server.Handle(req_mempool);
    if (resp_mempool.contains("error")) {
      std::cerr << "getmempoolinfo error: " << resp_mempool["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    auto floor = resp_mempool["result"]["mempoolminfee"].get<double>();
    if (floor < 1.0 - 1e-9) {
      std::cerr << "mempoolminfee below relay floor: " << floor << "\n";
      return EXIT_FAILURE;
    }
    auto minrelay = resp_mempool["result"]["minrelaytxfee"].get<double>();
    if (minrelay < 1.0 - 1e-9) {
      std::cerr << "minrelaytxfee below relay floor: " << minrelay << "\n";
      return EXIT_FAILURE;
    }
    nlohmann::json req_net{{"jsonrpc", "2.0"},
                           {"id", "5-net"},
                           {"method", "getnetworkinfo"},
                           {"params", nlohmann::json::object()}};
    auto resp_net = server.Handle(req_net);
    if (resp_net.contains("error")) {
      std::cerr << "getnetworkinfo error: " << resp_net["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    auto relayfee = resp_net["result"]["relayfee"].get<double>();
    if (relayfee < 1.0 - 1e-9) {
      std::cerr << "relayfee below relay floor: " << relayfee << "\n";
      return EXIT_FAILURE;
    }
    // estimatesmartfee should never return a value below the mempool floor.
    nlohmann::json req_fee{{"jsonrpc", "2.0"},
                           {"id", "6"},
                           {"method", "estimatesmartfee"},
                           {"params", nlohmann::json::array({3})}};
    auto resp_fee = server.Handle(req_fee);
    if (resp_fee.contains("error")) {
      std::cerr << "estimatesmartfee error: " << resp_fee["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    auto suggested = resp_fee["result"]["feerate"].get<double>();
    if (suggested < floor - 1e-9) {
      std::cerr << "estimatesmartfee returned below floor: fee=" << suggested
                << " floor=" << floor << "\n";
      return EXIT_FAILURE;
    }

    // Basic raw transaction helpers: createrawtransaction, decoderawtransaction,
    // sendrawtransaction, and getrawtransaction should round-trip a simple
    // zero-value tx and be rejected by policy when attempting to broadcast a
    // clearly non-standard transaction.
    nlohmann::json raw_req{
        {"jsonrpc", "2.0"},
        {"id", "7"},
        {"method", "createrawtransaction"},
        {"params",
         {{"inputs", nlohmann::json::array({nlohmann::json::object(
                           {{"txid",
                             "0000000000000000000000000000000000000000000000000000000000000000"},
                            {"vout", 0}})})},
          {"outputs", nlohmann::json::array({nlohmann::json::object(
                            {{"amount", "0.00000000"},
                             {"script_pubkey", "00"}})})}}}};
    auto raw_resp = server.Handle(raw_req);
    if (raw_resp.contains("error")) {
      std::cerr << "createrawtransaction error: " << raw_resp["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    auto raw_hex = raw_resp["result"]["hex"].get<std::string>();
    if (raw_hex.empty()) {
      std::cerr << "createrawtransaction returned empty hex\n";
      return EXIT_FAILURE;
    }

    nlohmann::json decode_req{
        {"jsonrpc", "2.0"},
        {"id", "8"},
        {"method", "decoderawtransaction"},
        {"params", {{"hex", raw_hex}}}};
    auto decode_resp = server.Handle(decode_req);
    if (decode_resp.contains("error")) {
      std::cerr << "decoderawtransaction error: " << decode_resp["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    const auto decoded = decode_resp["result"];
    if (!decoded.is_object() || !decoded.contains("txid")) {
      std::cerr << "decoderawtransaction missing txid field\n";
      return EXIT_FAILURE;
    }

    nlohmann::json send_req{
        {"jsonrpc", "2.0"},
        {"id", "9"},
        {"method", "sendrawtransaction"},
        {"params", {{"hex", raw_hex}}}};
    auto send_resp = server.Handle(send_req);
    if (!send_resp.contains("error")) {
      std::cerr << "sendrawtransaction unexpectedly accepted clearly non-standard tx\n";
      return EXIT_FAILURE;
    }

    // getblockhash should return the tip hash for the requested height.
    const auto* tip = chain.Tip();
    if (!tip) {
      std::cerr << "chain tip missing in wallet_rpc_tests\n";
      return EXIT_FAILURE;
    }
    const std::string tip_hash = tip->hash_hex;
    nlohmann::json getblockhash_req{
        {"jsonrpc", "2.0"},
        {"id", "10"},
        {"method", "getblockhash"},
        {"params", {{"height", static_cast<std::uint64_t>(tip->height)}}}};
    auto getblockhash_resp = server.Handle(getblockhash_req);
    if (getblockhash_resp.contains("error")) {
      std::cerr << "getblockhash error: " << getblockhash_resp["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    const auto got_hash = getblockhash_resp["result"].get<std::string>();
    if (got_hash != tip_hash) {
      std::cerr << "getblockhash mismatch: expected " << tip_hash << " got " << got_hash << "\n";
      return EXIT_FAILURE;
    }

    // getrawtransaction with verbose=true should decode the genesis coinbase
    // transaction and report basic metadata such as txid and confirmations.
    primitives::CBlock tip_block;
    std::string read_error;
    if (!chain.ReadBlock(*tip, &tip_block, &read_error)) {
      std::cerr << "failed to load tip block data: "
                << (read_error.empty() ? "unknown error" : read_error) << "\n";
      return EXIT_FAILURE;
    }
    if (tip_block.transactions.empty()) {
      std::cerr << "genesis block has no transactions\n";
      return EXIT_FAILURE;
    }
    const auto& coinbase = tip_block.transactions.front();
    const auto coinbase_txid = primitives::ComputeTxId(coinbase);
    const std::string coinbase_txid_hex =
        util::HexEncode(std::span<const std::uint8_t>(coinbase_txid.data(), coinbase_txid.size()));

    nlohmann::json getraw_req{
        {"jsonrpc", "2.0"},
        {"id", "11"},
        {"method", "getrawtransaction"},
        {"params", {{"txid", coinbase_txid_hex}, {"verbose", true}}}};
    auto getraw_resp = server.Handle(getraw_req);
    if (getraw_resp.contains("error")) {
      std::cerr << "getrawtransaction error: " << getraw_resp["error"].dump() << "\n";
      return EXIT_FAILURE;
    }
    const auto txobj = getraw_resp["result"];
    if (!txobj.is_object() || txobj.at("txid").get<std::string>() != coinbase_txid_hex) {
      std::cerr << "getrawtransaction returned unexpected txid\n";
      return EXIT_FAILURE;
    }
    if (!txobj.contains("hex") || txobj.at("hex").get<std::string>().empty()) {
      std::cerr << "getrawtransaction missing non-empty hex field\n";
      return EXIT_FAILURE;
    }
    const auto confirmations = txobj.at("confirmations").get<std::int64_t>();
    if (confirmations < 1) {
      std::cerr << "getrawtransaction reports non-positive confirmations: " << confirmations
                << "\n";
      return EXIT_FAILURE;
    }

    std::filesystem::remove(wallet_path);
    std::filesystem::remove(backup_path);
    std::filesystem::remove("testdata/blocks.dat");
    std::filesystem::remove("testdata/utxo.dat");
  } catch (const std::exception& ex) {
    std::cerr << "wallet_rpc_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
