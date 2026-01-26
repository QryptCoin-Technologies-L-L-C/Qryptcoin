#include "rpc/server.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <vector>
#include <cstring>

#include "config/network.hpp"
#include "consensus/block_hash.hpp"
#include "consensus/block_weight.hpp"
#include "consensus/monetary.hpp"
#include "consensus/params.hpp"
#include "consensus/pow.hpp"
#include "consensus/tx_validator.hpp"
#include "consensus/utxo.hpp"
#include "consensus/versionbits.hpp"
#include "consensus/witness_commitment.hpp"
#include "crypto/hash.hpp"
#include "crypto/payment_code.hpp"
#include "crypto/p2qh_address.hpp"
#include "crypto/crypto_suite.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "net/messages.hpp"
#include "net/time_adjuster.hpp"
#include "node/mining_extranonce.hpp"
#include "policy/standardness.hpp"
#include "primitives/amount.hpp"
#include "primitives/merkle.hpp"
#include "primitives/serialize.hpp"
#include "primitives/transaction.hpp"
#include "primitives/txid.hpp"
#include "script/p2qh.hpp"
#include "script/script.hpp"
#include "util/base64.hpp"
#include "util/csprng.hpp"
#include "util/hex.hpp"

namespace qryptcoin::rpc {

namespace {

// Default global rate limits for mining-related RPCs to avoid abuse.
constexpr std::uint32_t kDefaultMaxGetBlockTemplatePerSecond = 5;
constexpr std::uint32_t kDefaultMaxSubmitBlockPerSecond = 10;
// Minimum relay fee rate (policy) in Miks per virtual byte.
// This is the baseline "mempool floor" when the mempool is otherwise empty.
constexpr double kMinRelayFeeMiksPerVb = 1.0;

bool ExtractRevealedPubkeyHashes(const primitives::CTransaction& tx,
                                 std::vector<primitives::Hash256>* out,
                                 std::string* error) {
  if (!out) {
    if (error) *error = "invalid output buffer";
    return false;
  }
  out->clear();
  if (tx.IsCoinbase()) {
    return true;
  }
  std::unordered_set<primitives::Hash256, consensus::Hash256Hasher> seen;
  seen.reserve(tx.vin.size());
  for (const auto& in : tx.vin) {
    if (in.witness_stack.empty()) {
      if (error) *error = "empty witness stack";
      return false;
    }
    const auto& reveal = in.witness_stack.front().data;
    crypto::P2QHRevealData reveal_data{};
    if (!crypto::ParseP2QHReveal(reveal, &reveal_data)) {
      if (error) *error = "invalid descriptor reveal";
      return false;
    }
    const auto digest = crypto::Sha3_256(std::span<const std::uint8_t>(
        reveal_data.mldsa_public_key.data(), reveal_data.mldsa_public_key.size()));
    primitives::Hash256 hash{};
    std::copy(digest.begin(), digest.end(), hash.begin());
    if (!seen.insert(hash).second) {
      if (error) *error = "public key reused within transaction";
      return false;
    }
    out->push_back(hash);
  }
  return true;
}
// Upper bound for relayed/mempool transactions (bytes on the wire). Used as a
// DoS guardrail for sendrawtransaction and P2P relay.
constexpr std::uint64_t kMaxMempoolTxBytes = 1'000'000;

std::atomic<std::uint32_t> g_max_getblocktemplate_per_second{
    kDefaultMaxGetBlockTemplatePerSecond};
std::atomic<std::uint32_t> g_max_submitblock_per_second{
    kDefaultMaxSubmitBlockPerSecond};

std::uint64_t MedianTimePastTip(const node::ChainState& chain) {
  const auto* tip = chain.Tip();
  if (!tip) {
    return 0;
  }
  std::vector<std::uint64_t> times;
  times.reserve(11);
  const auto tip_height = chain.Height();
  const std::size_t count = std::min<std::size_t>(tip_height + 1, 11);
  for (std::size_t i = 0; i < count; ++i) {
    const auto* record = chain.GetByHeight(tip_height - i);
    if (!record) {
      break;
    }
    times.push_back(record->header.timestamp);
  }
  if (times.empty()) {
    return 0;
  }
  std::sort(times.begin(), times.end());
  return times[times.size() / 2];
}

bool DoubleToMoney(double value, primitives::Amount* out) {
  if (!out) return false;
  if (!std::isfinite(value) || value < 0.0) return false;
  const long double max_money = static_cast<long double>(primitives::kMaxMoney);
  if (static_cast<long double>(value) > max_money) return false;
  *out = static_cast<primitives::Amount>(value);
  return true;
}

std::uint64_t QuantizeFeerate(double feerate_miks_per_vb) {
  if (!std::isfinite(feerate_miks_per_vb) || feerate_miks_per_vb <= 0.0) {
    return 0;
  }
  constexpr long double kScale = 1'000'000.0L;
  const long double scaled = static_cast<long double>(feerate_miks_per_vb) * kScale;
  if (scaled <= 0.0L) {
    return 0;
  }
  const long double max_u64 = static_cast<long double>(std::numeric_limits<std::uint64_t>::max());
  if (scaled >= max_u64) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return static_cast<std::uint64_t>(scaled + 0.5L);
}

std::string AlgoToString(crypto::SignatureAlgorithm algo) {
  (void)algo;
  return "DIL";
}

std::string HashToHex(const primitives::Hash256& hash) {
  return util::HexEncode(std::span<const std::uint8_t>(hash.begin(), hash.size()));
}

std::string FormatAmount(primitives::Amount value) {
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(8)
      << static_cast<long double>(value) / static_cast<long double>(primitives::kMiksPerQRY);
  return oss.str();
}

std::string DescriptorToHex(const crypto::P2QHDescriptor& descriptor) {
  const auto serialized = crypto::SerializeP2QHDescriptor(descriptor);
  return util::HexEncode(std::span<const std::uint8_t>(serialized.data(), serialized.size()));
}

std::size_t EstimateWitnessBytes(crypto::SignatureAlgorithm algo) {
  // Approximate witness size as:
  //   reveal(version/algo/params/reserved + PQ pubkeys) +
  //   required PQ signatures.
  (void)algo;
  // version (1) + algo_id (1) + params_id (1) + reserved (2) + pk_len (2) +
  // ML-DSA public key.
  std::size_t reveal = 7 + crypto::DilithiumPublicKeySize();
  std::size_t sigs = crypto::DilithiumSignatureSize();

  // Add a small constant for varint overhead and stack item headers.
  return reveal + sigs + 8;
}

nlohmann::json BuildPqMetadata(const std::optional<crypto::P2QHDescriptor>& descriptor,
                               const primitives::Hash256& program) {
  nlohmann::json pq;
  pq["program"] = HashToHex(program);
  if (descriptor.has_value()) {
    pq["algo"] = AlgoToString(descriptor->algorithm);
  } else {
    pq["algo"] = "unknown";
  }
  return pq;
}

std::string TxIdHex(const primitives::CTransaction& tx) {
  auto txid = primitives::ComputeTxId(tx);
  return HashToHex(txid);
}

std::string SerializeTransactionHex(const primitives::CTransaction& tx) {
  std::vector<std::uint8_t> buffer;
  primitives::serialize::SerializeTransaction(tx, &buffer);
  return util::HexEncode(std::span<const std::uint8_t>(buffer.data(), buffer.size()));
}

std::size_t SerializedBlockSize(const primitives::CBlock& block) {
  std::vector<std::uint8_t> buffer;
  primitives::serialize::SerializeBlock(block, &buffer);
  return buffer.size();
}

primitives::Hash256 ProgramToHash(const std::array<std::uint8_t, script::kP2QHWitnessProgramSize>& program) {
  primitives::Hash256 hash{};
  std::copy(program.begin(), program.end(), hash.begin());
  return hash;
}

std::optional<primitives::Amount> ParseAmount(const nlohmann::json& value) {
  std::string text;
  if (value.is_number()) {
    std::ostringstream oss;
    oss << std::setprecision(16) << value.get<long double>();
    text = oss.str();
  } else if (value.is_string()) {
    text = value.get<std::string>();
  } else {
    return std::nullopt;
  }
  bool seen_decimal = false;
  std::uint64_t integral = 0;
  std::uint64_t fractional = 0;
  int fractional_digits = 0;
  for (char c : text) {
    if (c == '.') {
      if (seen_decimal) return std::nullopt;
      seen_decimal = true;
      continue;
    }
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    std::uint8_t digit = static_cast<std::uint8_t>(c - '0');
    if (!seen_decimal) {
      integral = integral * 10 + digit;
      if (integral > primitives::kMaxMoney / 10) {
        return std::nullopt;
      }
    } else {
      if (fractional_digits >= 8) {
        return std::nullopt;
      }
      fractional = fractional * 10 + digit;
      ++fractional_digits;
    }
  }
  while (fractional_digits < 8) {
    fractional *= 10;
    ++fractional_digits;
  }
  const auto miks = integral * primitives::kMiksPerQRY + fractional;
  if (miks > primitives::kMaxMoney) {
    return std::nullopt;
  }
  return miks;
}

nlohmann::json TxToJson(const primitives::CTransaction& tx, const wallet::HDWallet* wallet) {
  nlohmann::json tx_json;
  tx_json["txid"] = TxIdHex(tx);
  tx_json["version"] = tx.version;
  tx_json["lock_time"] = tx.lock_time;
  tx_json["is_coinbase"] = tx.IsCoinbase();

  nlohmann::json vin = nlohmann::json::array();
  for (const auto& input : tx.vin) {
    nlohmann::json in_json;
    in_json["txid"] = HashToHex(input.prevout.txid);
    in_json["vout"] = input.prevout.index;
    in_json["sequence"] = input.sequence;
    nlohmann::json witness = nlohmann::json::array();
    for (const auto& item : input.witness_stack) {
      witness.push_back(util::HexEncode(std::span<const std::uint8_t>(item.data.data(), item.data.size())));
    }
    in_json["witness"] = witness;
    vin.push_back(in_json);
  }
  tx_json["vin"] = vin;

  nlohmann::json vout = nlohmann::json::array();
  for (std::size_t idx = 0; idx < tx.vout.size(); ++idx) {
    const auto& out = tx.vout[idx];
    nlohmann::json out_json;
    out_json["n"] = idx;
    out_json["value"] = FormatAmount(out.value);
    out_json["script_pubkey"] =
        util::HexEncode(std::span<const std::uint8_t>(out.locking_descriptor.data(), out.locking_descriptor.size()));
    script::ScriptPubKey script_pubkey{out.locking_descriptor};
    std::array<std::uint8_t, script::kP2QHWitnessProgramSize> program{};
    if (script::ExtractWitnessProgram(script_pubkey, &program)) {
      std::optional<crypto::P2QHDescriptor> descriptor;
      if (wallet) {
        descriptor = wallet->DescriptorForProgram(
            std::span<const std::uint8_t>(program.data(), program.size()));
      }
      out_json["pq"] = BuildPqMetadata(descriptor, ProgramToHash(program));
    }
    vout.push_back(out_json);
  }
  tx_json["vout"] = vout;
  return tx_json;
}

bool SumOutputsChecked(const primitives::CTransaction& tx, primitives::Amount* total) {
  if (!total) return false;
  primitives::Amount sum = 0;
  for (const auto& out : tx.vout) {
    if (!primitives::MoneyRange(out.value)) {
      return false;
    }
    primitives::Amount next = 0;
    if (!primitives::CheckedAdd(sum, out.value, &next)) {
      return false;
    }
    sum = next;
  }
  *total = sum;
  return true;
}

bool ComputeTransactionFee(const primitives::CTransaction& tx,
                           const consensus::UTXOSet& view,
                           primitives::Amount* fee_out) {
  primitives::Amount input_sum = 0;
  for (const auto& in : tx.vin) {
    const auto* coin = view.GetCoin(in.prevout);
    if (!coin) {
      return false;
    }
    primitives::Amount next = 0;
    if (!primitives::CheckedAdd(input_sum, coin->out.value, &next)) {
      return false;
    }
    input_sum = next;
  }
  primitives::Amount output_sum = 0;
  if (!SumOutputsChecked(tx, &output_sum)) {
    return false;
  }
  if (output_sum > input_sum) {
    return false;
  }
  if (fee_out) {
    primitives::Amount fee = 0;
    if (!primitives::CheckedSub(input_sum, output_sum, &fee)) {
      return false;
    }
    *fee_out = fee;
  }
  return true;
}

std::uint64_t ComputeTransactionVBytes(const primitives::CTransaction& tx) {
  const auto sizes = primitives::serialize::MeasureTransactionSizes(tx);
  const std::uint64_t base_bytes = static_cast<std::uint64_t>(sizes.base_size);
  const std::uint64_t witness_bytes = static_cast<std::uint64_t>(sizes.witness_size);
  const std::uint64_t weight = base_bytes * 4ULL + witness_bytes;
  return (weight + 3ULL) / 4ULL;
}

// Lightweight RPC exception that carries a structured error code in
// addition to the human-readable message.
struct RpcError : public std::runtime_error {
  int code;
  RpcError(int c, const std::string& msg) : std::runtime_error(msg), code(c) {}
};

[[noreturn]] void ThrowRpcError(int code, const std::string& msg) {
  throw RpcError(code, msg);
}

// Methods that are safe to expose in read-only RPC mode. All other
// methods are treated as potentially mutating and are disabled when
// the daemon is started with --rpc-read-only.
bool IsReadOnlyMethod(const std::string& method) {
  static const std::unordered_set<std::string> kReadOnly{
      "getblockchaininfo",  "getblock",          "getblockhash",
      "getbestblockhash",   "getblockcount",     "getwalletinfo",
      "waitfornewblock",    "waitforblockheight","waitforblock",
      "getpaymentcode",     "validatepaymentcode",
      "listtransactions",   "listutxos",         "listaddresses",
      "listwatchonly",      "getpqinfo",         "getnetworkinfo",
      "getpeerinfo",        "getmininginfo",     "getmempoolinfo",
      "getmininginfo_qry",
      "getrawmempool",      "getmempoolentry",   "createrawtransaction",
      "decoderawtransaction","getrawtransaction","estimatesmartfee",
      "getblocktemplate",   "gethealth",         "getchaintips",
      "getblocktemplate_qry",
      "getaddednodeinfo",   "getseedhealth",     "listdnsseeds"};
  return kReadOnly.find(method) != kReadOnly.end();
}

bool IsWalletMethod(const std::string& method) {
  static const std::unordered_set<std::string> kWalletMethods{
      "getnewaddress",     "sendtoaddress",    "getwalletinfo",
      "getpaymentcode",    "validatepaymentcode", "resolvepaymentcode",
      "listtransactions",  "listutxos",        "listaddresses",
      "forgetaddresses",   "importaddress",    "listwatchonly",
      "removewatchonly",   "getpqinfo",        "createwallet",
      "loadwallet",
      "backupwallet",      "encryptwallet",    "walletlock",
      "walletpassphrase"};
  return kWalletMethods.find(method) != kWalletMethods.end();
}

bool IsWalletBootstrapMethod(const std::string& method) {
  return method == "createwallet" || method == "loadwallet";
}

}  // namespace

void ConfigureMiningRpcRateLimits(std::uint32_t max_getblocktemplate_per_second,
                                  std::uint32_t max_submitblock_per_second) {
  g_max_getblocktemplate_per_second.store(max_getblocktemplate_per_second,
                                          std::memory_order_relaxed);
  g_max_submitblock_per_second.store(max_submitblock_per_second,
                                     std::memory_order_relaxed);
}

RpcServer::RpcServer(std::unique_ptr<wallet::HDWallet> wallet, bool wallet_enabled,
                     node::ChainState& chain, net::PeerManager* peers, node::BlockSyncManager* sync,
                     net::AddrManager* addrman, net::DnsSeedManager* dns_seeds, bool is_seed_node,
                     std::string default_mining_address, bool allow_generate, bool read_only,
                     std::uint64_t mempool_limit_bytes)
    : RpcServer(std::move(wallet), wallet_enabled, chain, peers, sync, addrman, dns_seeds,
                is_seed_node, std::move(default_mining_address), allow_generate, read_only,
                mempool_limit_bytes,
                /*mempool_persist_path=*/"",
                /*mempool_expiry_seconds=*/0,
                /*mempool_rebroadcast_seconds=*/0,
                /*mempool_persist_interval_seconds=*/0) {}

RpcServer::RpcServer(std::unique_ptr<wallet::HDWallet> wallet, bool wallet_enabled,
                     node::ChainState& chain, net::PeerManager* peers, node::BlockSyncManager* sync,
                     net::AddrManager* addrman, net::DnsSeedManager* dns_seeds, bool is_seed_node,
                     std::string default_mining_address, bool allow_generate, bool read_only,
                     std::uint64_t mempool_limit_bytes,
                     std::string mempool_persist_path,
                     std::uint64_t mempool_expiry_seconds,
                     std::uint64_t mempool_rebroadcast_seconds,
                     std::uint64_t mempool_persist_interval_seconds)
      : wallet_(std::move(wallet)),
        wallet_enabled_(wallet_enabled),
        chain_(chain),
        peers_(peers),
        sync_(sync),
        addrman_(addrman),
        dns_seeds_(dns_seeds),
        default_mining_address_(std::move(default_mining_address)),
        allow_generate_(allow_generate),
        read_only_(read_only),
        is_seed_node_(is_seed_node),
        mempool_bytes_(0),
        mempool_limit_bytes_(mempool_limit_bytes),
        mempool_min_fee_miks_per_vb_(kMinRelayFeeMiksPerVb),
        mempool_expiry_(std::chrono::seconds(mempool_expiry_seconds)),
        mempool_rebroadcast_interval_(std::chrono::seconds(mempool_rebroadcast_seconds)),
        mempool_persist_path_(std::move(mempool_persist_path)) {
  if (mempool_persist_interval_seconds > 0) {
    mempool_persist_interval_ = std::chrono::seconds(mempool_persist_interval_seconds);
  }
  if (!mempool_persist_path_.empty()) {
    std::string error;
    if (!LoadMempoolFromDisk(&error)) {
      std::cerr << "[mempool] warn: failed to load persisted mempool: "
                << (!error.empty() ? error : "unknown error") << "\n";
    }
  }

  if (mempool_expiry_.count() > 0 || mempool_rebroadcast_interval_.count() > 0 ||
      !mempool_persist_path_.empty()) {
    mempool_maintenance_thread_ =
        std::jthread([this](std::stop_token stop) { MempoolMaintenanceLoop(stop); });
  }
}

RpcServer::~RpcServer() {
  if (mempool_maintenance_thread_.joinable()) {
    mempool_maintenance_thread_.request_stop();
    mempool_maintenance_thread_.join();
  }
  if (!mempool_persist_path_.empty()) {
    std::string error;
    if (!SaveMempoolToDisk(&error)) {
      std::cerr << "[mempool] warn: failed to persist mempool on shutdown: "
                << (!error.empty() ? error : "unknown error") << "\n";
    }
  }
}

wallet::HDWallet& RpcServer::WalletOrThrow() {
  if (!wallet_enabled_) {
    ThrowRpcError(-32601, "wallet disabled");
  }
  if (!wallet_) {
    ThrowRpcError(-32601, "wallet not loaded");
  }
  return *wallet_;
}

const wallet::HDWallet& RpcServer::WalletOrThrow() const {
  if (!wallet_enabled_) {
    ThrowRpcError(-32601, "wallet disabled");
  }
  if (!wallet_) {
    ThrowRpcError(-32601, "wallet not loaded");
  }
  return *wallet_;
}

nlohmann::json RpcServer::Handle(const nlohmann::json& request) {
  nlohmann::json response;
  response["jsonrpc"] = "2.0";
  if (request.contains("id")) {
    response["id"] = request["id"];
  } else {
    response["id"] = nullptr;
  }
  try {
    const auto method = request.at("method").get<std::string>();
    const nlohmann::json params =
        request.contains("params") ? request.at("params") : nlohmann::json::object();
    // Basic anti-abuse limits for high-cost mining RPCs.
    if (method == "getblocktemplate" || method == "getblocktemplate_qry") {
      static std::mutex rate_mutex;
      static std::chrono::steady_clock::time_point window_start;
      static std::uint32_t count = 0;
      const auto now = std::chrono::steady_clock::now();
      std::lock_guard<std::mutex> lk(rate_mutex);
      if (window_start.time_since_epoch().count() == 0) {
        window_start = now;
        count = 0;
      }
      const auto elapsed =
          std::chrono::duration_cast<std::chrono::seconds>(now - window_start).count();
      if (elapsed >= 1) {
        window_start = now;
        count = 0;
      }
      const auto limit =
          g_max_getblocktemplate_per_second.load(std::memory_order_relaxed);
      if (limit > 0 && count >= limit) {
        ThrowRpcError(-32005, "getblocktemplate rate limit exceeded");
      }
      ++count;
    } else if (method == "submitblock" || method == "submitblock_qry") {
      static std::mutex rate_mutex;
      static std::chrono::steady_clock::time_point window_start;
      static std::uint32_t count = 0;
      const auto now = std::chrono::steady_clock::now();
      std::lock_guard<std::mutex> lk(rate_mutex);
      if (window_start.time_since_epoch().count() == 0) {
        window_start = now;
        count = 0;
      }
      const auto elapsed =
          std::chrono::duration_cast<std::chrono::seconds>(now - window_start).count();
      if (elapsed >= 1) {
        window_start = now;
        count = 0;
      }
      const auto limit =
          g_max_submitblock_per_second.load(std::memory_order_relaxed);
      if (limit > 0 && count >= limit) {
        ThrowRpcError(-32006, "submitblock rate limit exceeded");
      }
      ++count;
    }

    if (IsWalletMethod(method)) {
      if (!WalletEnabled()) {
        ThrowRpcError(-32601, "wallet disabled");
      }
      if (!WalletLoaded() && !IsWalletBootstrapMethod(method)) {
        ThrowRpcError(-32601, "wallet not loaded");
      }
    }

    // Enforce read-only mode: only a small, curated set of methods
    // are permitted when the daemon is started with --rpc-read-only.
    if (read_only_ && !IsReadOnlyMethod(method)) {
      ThrowRpcError(-32001, "RPC method disabled in read-only mode");
    }

    if (method == "getblockchaininfo") {
      response["result"] = HandleGetBlockchainInfo(params);
    } else if (method == "getblock") {
      response["result"] = HandleGetBlock(params);
    } else if (method == "getblockhash") {
      response["result"] = HandleGetBlockHash(params);
    } else if (method == "getbestblockhash") {
      response["result"] = HandleGetBestBlockHash();
    } else if (method == "getblockcount") {
      response["result"] = HandleGetBlockCount();
    } else if (method == "waitfornewblock") {
      response["result"] = HandleWaitForNewBlock(params);
    } else if (method == "waitforblockheight") {
      response["result"] = HandleWaitForBlockHeight(params);
    } else if (method == "waitforblock") {
      response["result"] = HandleWaitForBlock(params);
    } else if (method == "getnewaddress") {
      response["result"] = HandleGetNewAddress(params);
    } else if (method == "getpaymentcode") {
      response["result"] = HandleGetPaymentCode();
    } else if (method == "validatepaymentcode") {
      response["result"] = HandleValidatePaymentCode(params);
    } else if (method == "resolvepaymentcode") {
      response["result"] = HandleResolvePaymentCode(params);
    } else if (method == "sendtoaddress") {
      response["result"] = HandleSendToAddress(params);
    } else if (method == "getwalletinfo") {
      response["result"] = HandleGetWalletInfo();
    } else if (method == "listtransactions") {
      response["result"] = HandleListTransactions(params);
    } else if (method == "listutxos") {
      response["result"] = HandleListUtxos();
    } else if (method == "listaddresses") {
      response["result"] = HandleListAddresses();
    } else if (method == "forgetaddresses") {
      response["result"] = HandleForgetAddresses(params);
    } else if (method == "importaddress") {
      response["result"] = HandleImportAddress(params);
    } else if (method == "listwatchonly") {
      response["result"] = HandleListWatchOnly();
    } else if (method == "removewatchonly") {
      response["result"] = HandleRemoveWatchOnly(params);
    } else if (method == "getpqinfo") {
      response["result"] = HandleGetPqInfo();
    } else if (method == "getnetworkinfo") {
      response["result"] = HandleGetNetworkInfo();
    } else if (method == "getpeerinfo") {
      response["result"] = HandleGetPeerInfo();
    } else if (method == "getchaintips") {
      response["result"] = HandleGetChainTips();
    } else if (method == "getseedhealth") {
      response["result"] = HandleGetSeedHealth();
    } else if (method == "listdnsseeds") {
      response["result"] = HandleListDnsSeeds();
    } else if (method == "refreshdnsseeds") {
      response["result"] = HandleRefreshDnsSeeds();
    } else if (method == "addnode") {
      response["result"] = HandleAddNode(params);
    } else if (method == "disconnectnode") {
      response["result"] = HandleDisconnectNode(params);
    } else if (method == "getaddednodeinfo") {
      response["result"] = HandleGetAddedNodeInfo();
    } else if (method == "setnetworklimits") {
      response["result"] = HandleSetNetworkLimits(params);
    } else if (method == "getmininginfo") {
      response["result"] = HandleGetMiningInfo();
    } else if (method == "getmininginfo_qry") {
      response["result"] = HandleGetMiningInfoQry();
    } else if (method == "getmempoolinfo") {
      response["result"] = HandleGetMempoolInfo();
    } else if (method == "gethealth") {
      response["result"] = HandleGetHealth();
    } else if (method == "getrawmempool") {
      response["result"] = HandleGetRawMempool(params);
    } else if (method == "getmempoolentry") {
      response["result"] = HandleGetMempoolEntry(params);
    } else if (method == "createrawtransaction") {
      response["result"] = HandleCreateRawTransaction(params);
    } else if (method == "decoderawtransaction") {
      response["result"] = HandleDecodeRawTransaction(params);
    } else if (method == "getrawtransaction") {
      response["result"] = HandleGetRawTransaction(params);
    } else if (method == "sendrawtransaction") {
      response["result"] = HandleSendRawTransaction(params);
    } else if (method == "estimatesmartfee") {
      response["result"] = HandleEstimateSmartFee(params);
    } else if (method == "getblocktemplate") {
      response["result"] = HandleGetBlockTemplate(params);
    } else if (method == "getblocktemplate_qry") {
      response["result"] = HandleGetBlockTemplateQry(params);
    } else if (method == "submitblock") {
      response["result"] = HandleSubmitBlock(params);
    } else if (method == "submitblock_qry") {
      response["result"] = HandleSubmitBlockQry(params);
    } else if (method == "generate") {
      response["result"] = HandleGenerate(params, false);
    } else if (method == "generatetoaddress") {
      response["result"] = HandleGenerate(params, true);
    } else if (method == "createwallet") {
      response["result"] = HandleCreateWallet(params);
    } else if (method == "loadwallet") {
      response["result"] = HandleLoadWallet(params);
    } else if (method == "backupwallet") {
      response["result"] = HandleBackupWallet(params);
    } else if (method == "encryptwallet") {
      response["result"] = HandleEncryptWallet(params);
    } else if (method == "walletlock") {
      response["result"] = HandleWalletLock(params);
    } else if (method == "walletpassphrase") {
      response["result"] = HandleWalletPassphrase(params);
    } else {
      response["error"] = {{"code", -32601}, {"message", "unknown method"}};
    }
  } catch (const RpcError& ex) {
    response["error"] = {{"code", ex.code}, {"message", ex.what()}};
  } catch (const std::out_of_range&) {
    response["error"] = {{"code", -32600}, {"message", "invalid request"}};
  } catch (const std::exception& ex) {
    response["error"] = {{"code", -32603}, {"message", ex.what()}};
  }
  return response;
}

nlohmann::json RpcServer::HandleGetBlockchainInfo(const nlohmann::json&) const {
  nlohmann::json result;
  const auto& params = consensus::Params(config::GetNetworkConfig().type);
  result["chain"] = params.network_id;
  result["blocks"] = chain_.Height();
  node::BlockSyncManager::SyncStats sync_stats;
  bool has_sync = sync_ != nullptr;
  if (has_sync) {
    sync_stats = sync_->GetStats();
  }
  result["headers"] = has_sync ? sync_stats.best_header_height : chain_.BlockCount();
  if (const auto* tip = chain_.Tip()) {
    result["bestblockhash"] = tip->hash_hex;
    result["difficulty_bits"] = tip->header.difficulty_bits;
  } else {
    result["bestblockhash"] = "";
    result["difficulty_bits"] = 0;
  }
  result["utxo_entries"] = chain_.UtxoEntries();
  result["initial_block_download"] = has_sync ? !sync_->IsSynced() : false;
  if (has_sync) {
    nlohmann::json sync_json;
    sync_json["pending_blocks"] = sync_stats.pending_blocks;
    sync_json["headers_gap"] = sync_stats.headers_gap;
    sync_json["active_outbound_peers"] = sync_stats.active_outbound_peers;
    sync_json["stalls_detected"] = sync_stats.stalls_detected;
    sync_json["block_stall_recoveries"] = sync_stats.block_stall_recoveries;
    sync_json["inflight_block_timeouts"] = sync_stats.inflight_block_timeouts;
    sync_json["unsolicited_headers_ignored"] = sync_stats.unsolicited_headers_ignored;
    sync_json["getheaders_sent"] = sync_stats.getheaders_sent;
    sync_json["headers_received"] = sync_stats.headers_received;
    sync_json["inventories_received"] = sync_stats.inventories_received;
    sync_json["blocks_connected"] = sync_stats.blocks_connected;
    sync_json["frame_payload_drops"] = sync_stats.frame_payload_drops;
    const auto telem = chain_.GetTelemetry();
    sync_json["orphan_blocks"] = telem.orphan_blocks;
    sync_json["reorg_events"] = telem.reorg_events;
    sync_json["max_reorg_depth"] = telem.max_reorg_depth;
    result["block_sync"] = sync_json;
  }

  // Expose version-bits deployment status for observability. This is
  // purely informational; no consensus behavior depends on it yet.
  nlohmann::json deployments = nlohmann::json::array();
  const auto* tip = chain_.Tip();
  const std::uint32_t tip_height =
      tip ? static_cast<std::uint32_t>(tip->height) : 0;
  consensus::BlockLookupFn lookup = [this](std::uint32_t height,
                                           std::uint32_t* out_time,
                                           std::uint32_t* out_version) -> bool {
    const auto* rec = chain_.GetByHeight(height);
    if (!rec || !rec->in_active_chain) {
      return false;
    }
    if (out_time) {
      *out_time = static_cast<std::uint32_t>(rec->header.timestamp);
    }
    if (out_version) {
      *out_version = rec->header.version;
    }
    return true;
  };
  for (const auto& dep : params.deployments) {
    nlohmann::json entry;
    entry["name"] = dep.name ? dep.name : "";
    entry["bit"] = dep.bit;
    entry["start_time"] = dep.start_time;
    entry["timeout"] = dep.timeout;
    entry["window_size"] = dep.window_size;
    entry["threshold"] = dep.threshold;
    if (tip) {
      const auto status =
          consensus::EvaluateDeployment(dep, params, lookup, tip_height);
      entry["state"] = consensus::DeploymentStateToString(status.state);
      entry["since_height"] = status.since_height;
      nlohmann::json period;
      period["start_height"] = status.period_start_height;
      period["signals"] = status.period_signals;
      period["length"] = status.period_length;
      period["ratio"] = (status.period_length == 0)
                            ? 0.0
                            : static_cast<double>(status.period_signals) /
                                  static_cast<double>(status.period_length);
      entry["period"] = period;
    } else {
      entry["state"] = "defined";
      entry["since_height"] = 0;
      entry["period"] = nlohmann::json::object();
    }
    deployments.push_back(entry);
  }
  result["versionbits"] = deployments;

  const auto default_algo =
      WalletLoaded() ? WalletOrThrow().DefaultAlgorithm() : crypto::SignatureAlgorithm::kDilithium;
  result["default_policy"] = AlgoToString(default_algo);
  nlohmann::json pq;
  pq["default_signature"] = crypto::DefaultSignatureSuite().signature_name;
  pq["handshake_kem"] = crypto::DefaultHandshakeKEM();
  result["pq"] = pq;
  return result;
}

nlohmann::json RpcServer::HandleGetBlockCount() const {
  const auto blocks = chain_.BlockCount();
  if (blocks == 0) {
    return static_cast<std::uint64_t>(0);
  }
  return static_cast<std::uint64_t>(blocks - 1);
}

nlohmann::json RpcServer::HandleWaitForNewBlock(const nlohmann::json& params) const {
  std::uint64_t timeout_ms = 0;
  if (params.is_array() && !params.empty()) {
    timeout_ms = params.at(0).get<std::uint64_t>();
  } else if (params.is_object()) {
    if (params.contains("timeout_ms")) {
      timeout_ms = params.at("timeout_ms").get<std::uint64_t>();
    } else if (params.contains("timeout")) {
      timeout_ms = params.at("timeout").get<std::uint64_t>();
    }
  }

  std::string start_hash;
  if (const auto* tip = chain_.Tip()) {
    start_hash = tip->hash_hex;
  }

  const auto start = std::chrono::steady_clock::now();
  const auto timeout = std::chrono::milliseconds(timeout_ms);
  while (true) {
    const auto* tip = chain_.Tip();
    if (tip) {
      if (start_hash.empty() || tip->hash_hex != start_hash) {
        break;
      }
    }
    if (timeout_ms > 0 && std::chrono::steady_clock::now() - start >= timeout) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }

  nlohmann::json result;
  if (const auto* tip = chain_.Tip()) {
    result["hash"] = tip->hash_hex;
    result["height"] = static_cast<std::uint64_t>(tip->height);
  } else {
    result["hash"] = "";
    result["height"] = static_cast<std::uint64_t>(0);
  }
  return result;
}

nlohmann::json RpcServer::HandleWaitForBlockHeight(const nlohmann::json& params) const {
  std::uint64_t target_height = 0;
  std::uint64_t timeout_ms = 0;

  if (params.is_array()) {
    if (!params.empty()) {
      target_height = params.at(0).get<std::uint64_t>();
    }
    if (params.size() > 1) {
      timeout_ms = params.at(1).get<std::uint64_t>();
    }
  } else if (params.is_object()) {
    if (params.contains("height")) {
      target_height = params.at("height").get<std::uint64_t>();
    }
    if (params.contains("timeout_ms")) {
      timeout_ms = params.at("timeout_ms").get<std::uint64_t>();
    } else if (params.contains("timeout")) {
      timeout_ms = params.at("timeout").get<std::uint64_t>();
    }
  } else {
    throw std::runtime_error("waitforblockheight expects params.height");
  }

  const auto start = std::chrono::steady_clock::now();
  const auto timeout = std::chrono::milliseconds(timeout_ms);
  while (true) {
    const auto* tip = chain_.Tip();
    if (tip && tip->height >= static_cast<std::size_t>(target_height)) {
      break;
    }
    if (timeout_ms > 0 && std::chrono::steady_clock::now() - start >= timeout) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }

  nlohmann::json result;
  if (const auto* tip = chain_.Tip()) {
    result["hash"] = tip->hash_hex;
    result["height"] = static_cast<std::uint64_t>(tip->height);
  } else {
    result["hash"] = "";
    result["height"] = static_cast<std::uint64_t>(0);
  }
  return result;
}

nlohmann::json RpcServer::HandleWaitForBlock(const nlohmann::json& params) const {
  std::string hash_hex;
  std::uint64_t timeout_ms = 0;

  if (params.is_array()) {
    if (!params.empty()) {
      hash_hex = params.at(0).get<std::string>();
    }
    if (params.size() > 1) {
      timeout_ms = params.at(1).get<std::uint64_t>();
    }
  } else if (params.is_object()) {
    if (params.contains("hash")) {
      hash_hex = params.at("hash").get<std::string>();
    }
    if (params.contains("timeout_ms")) {
      timeout_ms = params.at("timeout_ms").get<std::uint64_t>();
    } else if (params.contains("timeout")) {
      timeout_ms = params.at("timeout").get<std::uint64_t>();
    }
  }

  if (hash_hex.empty()) {
    throw std::runtime_error("waitforblock expects params.hash");
  }

  const auto start = std::chrono::steady_clock::now();
  const auto timeout = std::chrono::milliseconds(timeout_ms);
  const node::BlockRecord* record = nullptr;
  while (true) {
    record = chain_.GetByHash(hash_hex);
    if (record && record->in_active_chain) {
      break;
    }
    if (timeout_ms > 0 && std::chrono::steady_clock::now() - start >= timeout) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }

  nlohmann::json result;
  result["hash"] = hash_hex;
  result["found"] = record && record->in_active_chain;
  result["height"] = record ? static_cast<std::uint64_t>(record->height) : static_cast<std::uint64_t>(0);
  return result;
}

nlohmann::json RpcServer::HandleGetBestBlockHash() const {
  const auto* tip = chain_.Tip();
  if (!tip) {
    return "";
  }
  return tip->hash_hex;
}

nlohmann::json RpcServer::HandleGetBlockHash(const nlohmann::json& params) const {
  if (!params.is_object() || !params.contains("height")) {
    throw std::runtime_error("getblockhash expects params.height");
  }
  const auto height = params.at("height").get<std::uint64_t>();
  const auto* record = chain_.GetByHeight(static_cast<std::size_t>(height));
  if (!record) {
    throw std::runtime_error("block not found");
  }
  return record->hash_hex;
}

nlohmann::json RpcServer::HandleGetBlock(const nlohmann::json& params) const {
  const node::BlockRecord* record = nullptr;
  if (params.contains("height")) {
    auto height = params.at("height").get<std::uint64_t>();
    record = chain_.GetByHeight(static_cast<std::size_t>(height));
  } else if (params.contains("hash")) {
    record = chain_.GetByHash(params.at("hash").get<std::string>());
  }
  if (record == nullptr) {
    throw std::runtime_error("block not found");
  }
  primitives::CBlock full_block;
  std::string read_error;
  if (!chain_.ReadBlock(*record, &full_block, &read_error)) {
    throw std::runtime_error(read_error.empty() ? "block data unavailable" : read_error);
  }
  int verbosity = 1;
  if (params.contains("verbosity")) {
    verbosity = params.at("verbosity").get<int>();
  }
  nlohmann::json block;
  block["hash"] = record->hash_hex;
  block["height"] = record->height;
  block["size"] = SerializedBlockSize(full_block);
  block["version"] = record->header.version;
  block["previousblockhash"] = HashToHex(record->header.previous_block_hash);
  block["merkleroot"] = HashToHex(record->header.merkle_root);
  block["timestamp"] = record->header.timestamp;
  block["difficulty_bits"] = record->header.difficulty_bits;
  block["nonce"] = record->header.nonce;
  const auto weight = consensus::CalculateBlockWeight(full_block);
  block["weight"] = weight.weight;
  block["base_size_bytes"] = weight.base_bytes;
  block["witness_size_bytes"] = weight.witness_bytes;
  block["adaptive_weight_limit"] = consensus::AdaptiveBlockWeightLimit(weight);
  if (verbosity > 0) {
    nlohmann::json txs = nlohmann::json::array();
    for (const auto& tx : full_block.transactions) {
      txs.push_back(TxToJson(tx, wallet_.get()));
    }
    block["tx"] = txs;
  }
  return block;
}

// RBF policy tunables.
constexpr std::size_t kMaxRbfConflicts = 5;
constexpr double kRbfMinFeeBoost = 1.10;  // 10% higher total fee.

nlohmann::json RpcServer::HandleGetNewAddress(const nlohmann::json& params) {
  if (params.contains("policy") || params.contains("hybrid_policy")) {
    throw std::runtime_error("address policy selection has been removed; Dilithium3 is mandatory");
  }
  std::lock_guard<std::mutex> lock(wallet_rpc_mutex_);
  auto& wallet = WalletOrThrow();
  auto address = wallet.NewAddress();
  if (address.empty()) {
    const auto err = wallet.last_error();
    ThrowRpcError(-32603, err.empty() ? "failed to allocate address" : err);
  }
  auto descriptor = wallet.DescriptorForAddress(address);
  nlohmann::json result;
  result["address"] = address;
  if (descriptor) {
    result["descriptor_hex"] = DescriptorToHex(*descriptor);
    result["pq"] = BuildPqMetadata(descriptor, descriptor->program);
  }
  return result;
}

nlohmann::json RpcServer::HandleGetPaymentCode() const {
  const auto& wallet = WalletOrThrow();
  nlohmann::json result;
  result["payment_code"] = wallet.PaymentCode();
  result["format"] = "PAYCODE_V1";
  result["encoding"] = "base32";
  return result;
}

nlohmann::json RpcServer::HandleValidatePaymentCode(const nlohmann::json& params) const {
  std::string code;
  if (params.contains("payment_code")) {
    code = params.at("payment_code").get<std::string>();
  } else if (params.contains("code")) {
    code = params.at("code").get<std::string>();
  } else {
    ThrowRpcError(-32602, "missing payment_code");
  }

  crypto::PaymentCodeV1 parsed{};
  std::string decode_error;
  if (!crypto::DecodePaymentCodeV1(code, config::GetNetworkConfig().bech32_hrp, &parsed,
                                   &decode_error)) {
    ThrowRpcError(-32602, decode_error.empty() ? "invalid payment code" : decode_error);
  }

  const auto& cfg = config::GetNetworkConfig();
  const std::uint32_t expected_network_id =
      static_cast<std::uint32_t>(cfg.message_start[0]) |
      (static_cast<std::uint32_t>(cfg.message_start[1]) << 8) |
      (static_cast<std::uint32_t>(cfg.message_start[2]) << 16) |
      (static_cast<std::uint32_t>(cfg.message_start[3]) << 24);
  if (parsed.network_id != expected_network_id) {
    ThrowRpcError(-32602, "payment code network mismatch");
  }

  auto to_hex = [](std::span<const std::uint8_t> bytes) -> std::string {
    return util::HexEncode(bytes);
  };

  nlohmann::json result;
  result["valid"] = true;
  result["network_id_le"] = parsed.network_id;
  result["kdf_id"] = parsed.kdf_id;
  result["scan_pubkey"] = to_hex(parsed.scan_pubkey);
  result["spend_root_commitment"] = to_hex(parsed.spend_root_commitment);
  return result;
}

nlohmann::json RpcServer::HandleResolvePaymentCode(const nlohmann::json& params) {
  std::string code;
  if (params.contains("payment_code")) {
    code = params.at("payment_code").get<std::string>();
  } else if (params.contains("code")) {
    code = params.at("code").get<std::string>();
  } else {
    ThrowRpcError(-32602, "missing payment_code");
  }

  crypto::PaymentCodeV1 parsed{};
  std::string decode_error;
  if (!crypto::DecodePaymentCodeV1(code, config::GetNetworkConfig().bech32_hrp, &parsed,
                                   &decode_error)) {
    ThrowRpcError(-32602, decode_error.empty() ? "invalid payment code encoding" : decode_error);
  }

  const auto& cfg = config::GetNetworkConfig();
  const std::uint32_t expected_network_id =
      static_cast<std::uint32_t>(cfg.message_start[0]) |
      (static_cast<std::uint32_t>(cfg.message_start[1]) << 8) |
      (static_cast<std::uint32_t>(cfg.message_start[2]) << 16) |
      (static_cast<std::uint32_t>(cfg.message_start[3]) << 24);
  if (parsed.network_id != expected_network_id) {
    ThrowRpcError(-32602, "payment code network mismatch");
  }

  std::array<std::uint8_t, 16> challenge_bytes{};
  std::string challenge_b64;
  bool challenge_provided = false;
  if (params.contains("challenge_b64")) {
    if (!params.at("challenge_b64").is_string()) {
      ThrowRpcError(-32602, "invalid challenge length");
    }
    challenge_b64 = params.at("challenge_b64").get<std::string>();
    for (unsigned char c : challenge_b64) {
      if (std::isspace(c)) {
        ThrowRpcError(-32602, "invalid challenge length");
      }
    }
    std::vector<std::uint8_t> decoded;
    if (!util::Base64Decode(challenge_b64, &decoded) || decoded.size() != challenge_bytes.size()) {
      ThrowRpcError(-32602, "invalid challenge length");
    }
    std::copy(decoded.begin(), decoded.end(), challenge_bytes.begin());
    challenge_provided = true;
  }

  std::uint32_t requested_delta = 0;
  if (params.contains("requested_expiry_delta_blocks")) {
    if (!params.at("requested_expiry_delta_blocks").is_number_unsigned() &&
        !params.at("requested_expiry_delta_blocks").is_number_integer()) {
      ThrowRpcError(-32602, "invalid requested_expiry_delta_blocks");
    }
    const auto raw = params.at("requested_expiry_delta_blocks").get<std::uint64_t>();
    requested_delta = raw > std::numeric_limits<std::uint32_t>::max()
                          ? std::numeric_limits<std::uint32_t>::max()
                          : static_cast<std::uint32_t>(raw);
  }

  constexpr std::uint32_t kDefaultExpiryDeltaBlocks = 12;
  constexpr std::uint32_t kMaxExpiryDeltaBlocks = 12;
  std::uint32_t delta = requested_delta == 0 ? kDefaultExpiryDeltaBlocks : requested_delta;
  if (delta > kMaxExpiryDeltaBlocks) {
    delta = kMaxExpiryDeltaBlocks;
  }

  const auto issued_height_u64 = static_cast<std::uint64_t>(chain_.Height());
  const std::uint32_t issued_height =
      issued_height_u64 > std::numeric_limits<std::uint32_t>::max()
          ? std::numeric_limits<std::uint32_t>::max()
          : static_cast<std::uint32_t>(issued_height_u64);
  const std::uint32_t expiry_height =
      issued_height > (std::numeric_limits<std::uint32_t>::max() - delta)
          ? std::numeric_limits<std::uint32_t>::max()
          : static_cast<std::uint32_t>(issued_height + delta);

  if (!challenge_provided) {
    std::string rng_error;
    if (!util::FillSecureRandomBytes(challenge_bytes, &rng_error)) {
      ThrowRpcError(-32603, rng_error.empty() ? "secure randomness unavailable" : rng_error);
    }
    challenge_b64 = util::Base64Encode(challenge_bytes);
  }

  std::lock_guard<std::mutex> lock(wallet_rpc_mutex_);
  auto& wallet = WalletOrThrow();
  if (wallet.IsLocked()) {
    ThrowRpcError(-42002, "wallet locked");
  }

  const auto local_code = wallet.PaymentCode();
  if (code != local_code) {
    ThrowRpcError(-42001, "unknown payment code");
  }

  wallet::PaymentCodeReservation reservation{};
  reservation.issued_height = issued_height;
  reservation.expiry_height = expiry_height;
  std::copy(challenge_bytes.begin(), challenge_bytes.end(), reservation.challenge.begin());
  reservation.status = wallet::PaymentCodeReservationStatus::kReserved;

  std::string address;
  std::string reserve_error;
  if (!wallet.ReservePaymentCodeAddress(reservation, &address, &reserve_error) ||
      address.empty()) {
    if (reserve_error.empty()) {
      reserve_error = wallet.last_error();
    }
    ThrowRpcError(-42003, reserve_error.empty() ? "address pool exhausted" : reserve_error);
  }
  auto descriptor = wallet.DescriptorForAddress(address);
  nlohmann::json result;
  result["payment_code"] = local_code;
  result["address"] = address;
  if (descriptor) {
    result["descriptor_hex"] = DescriptorToHex(*descriptor);
    result["pq"] = BuildPqMetadata(descriptor, descriptor->program);
  }

  result["challenge_b64"] = challenge_b64;
  result["issued_height"] = issued_height;
  result["expiry_height"] = expiry_height;
  result["wallet_persistence"] = wallet.wallet_path().empty() ? "ephemeral" : "persistent";
  result["resolver"] = {
      {"mode", "http-insecure"},
      {"notes",
       "Unauthenticated resolution. Use only trusted local transport or an authenticated secure channel."},
  };

  return result;
}

nlohmann::json RpcServer::HandleGetWalletInfo() const {
  nlohmann::json result;
  const auto& wallet = WalletOrThrow();
  const auto spendable = wallet.GetBalance();
  const auto watch_only = wallet.GetWatchOnlyBalance();
  result["balance"] = FormatAmount(spendable);
  result["pending"] = FormatAmount(0);
  result["total"] = FormatAmount(spendable + watch_only);
  result["watch_only_balance"] = FormatAmount(watch_only);
  result["wallet_default_policy"] = AlgoToString(wallet.DefaultAlgorithm());
  result["locked"] = wallet.IsLocked();
  return result;
}

nlohmann::json RpcServer::HandleListTransactions(const nlohmann::json& params) const {
  int count = 50;
  if (params.contains("count")) {
    count = std::clamp(params.at("count").get<int>(), 1, 500);
  }
  const auto& wallet = WalletOrThrow();
  auto txs = wallet.ListTransactions();
  nlohmann::json result = nlohmann::json::array();
  int start = static_cast<int>(std::max<std::ptrdiff_t>(0, txs.size() - count));
  for (std::size_t i = start; i < txs.size(); ++i) {
      const auto& tx = txs[i];
      nlohmann::json entry;
      entry["txid"] = tx.txid;
      entry["amount"] = FormatAmount(tx.amount);
      entry["incoming"] = tx.incoming;
      entry["label"] = tx.label;
      entry["timestamp"] = tx.timestamp;
      entry["fee"] = FormatAmount(tx.fee);
      entry["confirmations"] = tx.confirmations;
      entry["coinbase"] = tx.coinbase;
      result.push_back(entry);
    }
  return result;
}

nlohmann::json RpcServer::HandleListUtxos() const {
  nlohmann::json result = nlohmann::json::array();
  const auto& wallet = WalletOrThrow();
  const auto& utxos = wallet.TrackedUtxos();
  const auto& cfg = config::GetNetworkConfig();

  for (const auto& utxo : utxos) {
    nlohmann::json entry;
    entry["txid"] = HashToHex(utxo.outpoint.txid);
    entry["vout"] = utxo.outpoint.index;
    entry["amount_miks"] = utxo.txout.value;
    entry["amount"] = FormatAmount(utxo.txout.value);
    entry["algo"] = AlgoToString(utxo.algorithm);
    entry["spent"] = utxo.spent;
    entry["is_change"] = utxo.is_change;
    entry["coinbase"] = utxo.coinbase;
    entry["watch_only"] = utxo.watch_only;

    // Derive address from the witness program if possible.
    std::string address;
    std::array<std::uint8_t, script::kP2QHWitnessProgramSize> program{};
    script::ScriptPubKey script_pub{utxo.txout.locking_descriptor};
    if (script::ExtractWitnessProgram(script_pub, &program)) {
      crypto::P2QHDescriptor desc{};
      std::copy(program.begin(), program.end(), desc.program.begin());
      address = crypto::EncodeP2QHAddress(desc, cfg.bech32_hrp);
    }
    entry["address"] = address;

    // Derive a best-effort maturity flag for coinbase outputs using the
    // consensus UTXO snapshot. Non-coinbase outputs are always treated as
    // mature here; consensus code enforces actual spend rules.
    bool mature = true;
    if (utxo.coinbase) {
      std::uint32_t coin_height = 0;
      bool coinbase_flag = false;
      if (chain_.GetCoinMetadata(utxo.outpoint, &coin_height, &coinbase_flag) &&
          coinbase_flag) {
        const auto tip_height =
            static_cast<std::uint32_t>(chain_.Height());
        const std::uint64_t required =
            static_cast<std::uint64_t>(coin_height) +
            static_cast<std::uint64_t>(consensus::kCoinbaseMaturity);
        mature = static_cast<std::uint64_t>(tip_height) >= required;
      } else {
        mature = false;
      }
    }
    entry["mature"] = mature;

    // Rough witness-size estimate based on PQ algorithm.
    entry["witness_est_bytes"] = EstimateWitnessBytes(utxo.algorithm);

    result.push_back(entry);
  }

  return result;
}

nlohmann::json RpcServer::HandleListAddresses() const {
  const auto& wallet = WalletOrThrow();
  const auto addresses = wallet.ListAddresses();
  nlohmann::json result = nlohmann::json::array();
  for (const auto& address : addresses) {
    nlohmann::json entry;
    entry["address"] = address;
    const auto descriptor = wallet.DescriptorForAddress(address);
    if (descriptor) {
      entry["descriptor_hex"] = DescriptorToHex(*descriptor);
      entry["pq"] = BuildPqMetadata(descriptor, descriptor->program);
    }
    result.push_back(entry);
  }
  return result;
}

nlohmann::json RpcServer::HandleImportAddress(const nlohmann::json& params) {
  if (!params.contains("address") || !params.at("address").is_string()) {
    throw std::runtime_error("address parameter required");
  }
  auto& wallet = WalletOrThrow();
  const auto address = params.at("address").get<std::string>();
  bool added = wallet.AddWatchOnlyAddress(address);
  // Optional fast rescan toggle; default is true so operators get
  // immediate visibility into historical funds for the script.
  bool rescan = true;
  if (params.contains("rescan")) {
    rescan = params.at("rescan").get<bool>();
  }
  if (rescan) {
    RescanWallet(/*start_height=*/0, /*force_start_height=*/true);
  }
  nlohmann::json result;
  result["address"] = address;
  result["added"] = added;
  result["rescan"] = rescan;
  return result;
}

nlohmann::json RpcServer::HandleListWatchOnly() const {
  const auto& wallet = WalletOrThrow();
  const auto addresses = wallet.ListWatchOnlyAddresses();
  nlohmann::json result = nlohmann::json::array();
  for (const auto& address : addresses) {
    nlohmann::json entry;
    entry["address"] = address;
    std::optional<crypto::P2QHDescriptor> opt_descriptor;
    crypto::P2QHDescriptor descriptor{};
    if (crypto::DecodeP2QHAddress(address, config::GetNetworkConfig().bech32_hrp,
                                  &descriptor)) {
      entry["descriptor_hex"] = DescriptorToHex(descriptor);
      opt_descriptor = descriptor;
      entry["pq"] = BuildPqMetadata(opt_descriptor, descriptor.program);
    } else {
      primitives::Hash256 empty{};
      entry["pq"] = BuildPqMetadata(opt_descriptor, empty);
    }
    result.push_back(entry);
  }
  return result;
}

nlohmann::json RpcServer::HandleRemoveWatchOnly(const nlohmann::json& params) {
  if (!params.contains("addresses") || !params.at("addresses").is_array()) {
    throw std::runtime_error("addresses array required");
  }
  auto& wallet = WalletOrThrow();
  const auto& addrs = params.at("addresses");
  nlohmann::json results = nlohmann::json::array();
  for (const auto& value : addrs) {
    if (!value.is_string()) {
      continue;
    }
    const std::string address = value.get<std::string>();
    const bool removed = wallet.RemoveWatchOnlyAddress(address);
    results.push_back({{"address", address}, {"removed", removed}});
  }
  nlohmann::json result;
  result["results"] = results;
  return result;
}

nlohmann::json RpcServer::HandleForgetAddresses(const nlohmann::json& params) {
  if (!params.contains("addresses") || !params.at("addresses").is_array()) {
    throw std::runtime_error("addresses array required");
  }
  auto& wallet = WalletOrThrow();
  const auto& addresses = params.at("addresses");
  nlohmann::json result_entries = nlohmann::json::array();
  for (const auto& value : addresses) {
    if (!value.is_string()) {
      continue;
    }
    const std::string address = value.get<std::string>();
    const bool removed = wallet.ForgetAddress(address);
    result_entries.push_back({{"address", address}, {"removed", removed}});
  }
  nlohmann::json result;
  result["results"] = result_entries;
  return result;
}

nlohmann::json RpcServer::HandleSendToAddress(const nlohmann::json& params) {
  if (!params.contains("address") || !params.contains("amount")) {
    throw std::runtime_error("address and amount are required");
  }
  auto& wallet = WalletOrThrow();
  const auto address = params.at("address").get<std::string>();
  auto amount = ParseAmount(params.at("amount"));
  if (!amount) {
    throw std::runtime_error("invalid amount");
  }
  primitives::Amount fee_rate = 0;
  bool manual_fee = false;
  if (params.contains("fee_rate")) {
    if (!params.at("fee_rate").is_number_integer()) {
      throw std::runtime_error("fee_rate must be an integer");
    }
    fee_rate = params.at("fee_rate").get<std::uint64_t>();
    manual_fee = true;
  }
  if (!primitives::MoneyRange(fee_rate)) {
    throw std::runtime_error("fee_rate out of range");
  }
  if (!manual_fee) {
    // Ask the rolling estimator for a 3-block target. It will fall back to the
    // current mempool floor when there is insufficient data.
    double suggested =
        fee_estimator_.EstimateFeeRate(/*target_blocks=*/3, mempool_min_fee_miks_per_vb_);
    if (suggested <= 0.0) {
      // With no history and no floor, fall back to a tiny but non-zero fee so
      // transactions still relay on quiet networks.
      suggested = mempool_min_fee_miks_per_vb_ > 0.0 ? mempool_min_fee_miks_per_vb_ : 1.0;
    }
    const double ceiled = std::ceil(suggested);
    primitives::Amount converted = 0;
    if (!DoubleToMoney(ceiled, &converted)) {
      throw std::runtime_error("fee_rate out of range");
    }
    fee_rate = converted;
  }
  std::vector<std::pair<std::string, primitives::Amount>> outputs = {{address, *amount}};
  std::string error;
  auto created = wallet.CreateTransaction(outputs, fee_rate, &error);
  if (!created) {
    throw std::runtime_error("tx creation failed: " + error);
  }
  const auto& tx = created->tx;

  std::string reject_reason;
  const bool accepted = AddToMempool(tx, std::nullopt, &reject_reason);
  if (accepted) {
    std::string commit_error;
    if (!wallet.CommitTransaction(*created, &commit_error)) {
      throw std::runtime_error("wallet commit failed: " + commit_error);
    }
    wallet.Save();
    BroadcastTransaction(tx);
  }
  nlohmann::json result;
  result["txid"] = TxIdHex(tx);
  result["hex"] = SerializeTransactionHex(tx);
  result["metadata"] = TxToJson(tx, wallet_.get());
  result["accepted_to_mempool"] = accepted;
  if (!accepted && !reject_reason.empty()) {
    result["rejection_reason"] = reject_reason;
  }
  return result;
}

nlohmann::json RpcServer::HandleGetPqInfo() const {
  const auto& wallet = WalletOrThrow();
  const auto descriptors = wallet.ListDescriptorHexes();
  const auto addresses = wallet.ListAddresses();
  nlohmann::json result;
  result["account_count"] = descriptors.size();
  result["descriptors"] = descriptors;
  result["addresses"] = addresses;
  return result;
}

nlohmann::json RpcServer::HandleGetNetworkInfo() const {
  nlohmann::json result;
  const auto& cfg = config::GetNetworkConfig();
  result["network"] = cfg.network_id;
  result["p2p_port"] = cfg.listen_port;
  result["rpc_port_default"] = cfg.rpc_port;
  result["service_bits"] = cfg.service_bits;
  result["encryption_default"] = cfg.encryption_mode == config::EncryptionMode::kEncrypted;
  // Minimum fee rate the node will relay. Units are Miks per virtual byte (vB).
  result["relayfee"] = kMinRelayFeeMiksPerVb;
  result["time_offset"] = net::GetTimeOffsetSeconds();

  if (addrman_) {
    result["addrman_entries"] =
        static_cast<std::uint64_t>(addrman_->EntryCount());
    const auto seed_stats = addrman_->GetSeedStats();
    result["seeds_dns_lookups"] = seed_stats.dns_lookups;
    result["seeds_dns_addresses"] = seed_stats.dns_addresses;
    result["seeds_dns_failures"] = seed_stats.dns_failures;
    result["seeds_static"] = seed_stats.static_seeds;
  } else {
    result["addrman_entries"] = static_cast<std::uint64_t>(0);
    result["seeds_dns_lookups"] = static_cast<std::uint64_t>(0);
    result["seeds_dns_addresses"] = static_cast<std::uint64_t>(0);
    result["seeds_dns_failures"] = static_cast<std::uint64_t>(0);
    result["seeds_static"] = static_cast<std::uint64_t>(0);
  }

  if (dns_seeds_) {
    const auto seeds = dns_seeds_->SnapshotSeeds();
    std::uint64_t total = 0;
    std::uint64_t resolved = 0;
    std::uint64_t failed = 0;
    std::uint64_t cached_peers = 0;
    total = static_cast<std::uint64_t>(seeds.size());
    for (const auto& s : seeds) {
      cached_peers += static_cast<std::uint64_t>(s.last_addresses.size());
      if (!s.last_addresses.empty()) {
        ++resolved;
      } else if (s.resolve_failures > 0) {
        ++failed;
      }
    }
    result["dns_seeds_total"] = total;
    result["dns_seeds_resolved"] = resolved;
    result["dns_seeds_failed"] = failed;
    result["cached_seed_peers"] = cached_peers;
  } else {
    result["dns_seeds_total"] = static_cast<std::uint64_t>(0);
    result["dns_seeds_resolved"] = static_cast<std::uint64_t>(0);
    result["dns_seeds_failed"] = static_cast<std::uint64_t>(0);
    result["cached_seed_peers"] = static_cast<std::uint64_t>(0);
  }

  // Compatibility alias so operator tools can refer to a single resolved-seeds
  // aggregate.
  result["seeds_resolved"] = result.value("dns_seeds_resolved", 0);

  if (peers_) {
    const auto stats = peers_->GetStats();
    result["peer_count"] = stats.total;
    result["inbound"] = stats.inbound;
    result["outbound"] = stats.outbound;
    result["outbound_target"] = qryptcoin::config::GetNetworkConfig().target_outbound_peers;
    result["listening"] = stats.listening;
    result["inbound_seen"] = stats.inbound_seen;
    result["reachable"] = stats.inbound_seen;
    nlohmann::json dns = nlohmann::json::array();
    for (const auto& host : stats.dns_seeds) {
      dns.push_back(host);
    }
    nlohmann::json statics = nlohmann::json::array();
    for (const auto& host : stats.static_seeds) {
      statics.push_back(host);
    }
    result["dns_seeds"] = dns;
    result["static_seeds"] = statics;
  } else {
    result["peer_count"] = 0;
    result["inbound"] = 0;
    result["outbound"] = 0;
    result["inbound_seen"] = false;
    result["reachable"] = false;
    result["dns_seeds"] = nlohmann::json::array();
    result["static_seeds"] = nlohmann::json::array();
  }

  // Surface a condensed view of block download health so dashboards
  // can reason about stalls without calling getblockchaininfo.
  if (sync_) {
    const auto sync_stats = sync_->GetStats();
    result["stalls_detected"] = sync_stats.stalls_detected;
    result["pending_blocks"] = sync_stats.pending_blocks;
  } else {
    result["stalls_detected"] = static_cast<std::uint64_t>(0);
    result["pending_blocks"] = static_cast<std::uint64_t>(0);
  }

  return result;
}

nlohmann::json RpcServer::HandleGetPeerInfo() const {
  nlohmann::json peers = nlohmann::json::array();
  if (!peers_) {
    return peers;
  }
  const auto infos = peers_->GetPeerInfos();
  std::unordered_map<std::uint64_t, node::BlockSyncManager::PeerSyncStats> sync_stats;
  if (sync_) {
    for (const auto& s : sync_->GetPeerSyncStats()) {
      sync_stats.emplace(s.peer_id, s);
    }
  }
  for (const auto& info : infos) {
    nlohmann::json entry;
    entry["id"] = info.id;
    entry["inbound"] = info.inbound;
    // Mask IPv4 addresses for privacy: zero the last octet if possible.
    std::string addr = info.address;
    auto last_dot = addr.rfind('.');
    if (last_dot != std::string::npos) {
      addr = addr.substr(0, last_dot + 1) + "0";
    }
    entry["address"] = addr;
    auto it = sync_stats.find(info.id);
    if (it != sync_stats.end()) {
      entry["in_flight_count"] = it->second.inflight_blocks;
      entry["stall_count"] = it->second.stall_count;
      entry["last_response_ms"] = it->second.last_response_ms;
    } else {
      entry["in_flight_count"] = 0;
      entry["stall_count"] = 0;
      entry["last_response_ms"] = 0;
    }
    peers.push_back(entry);
  }
  return peers;
}

nlohmann::json RpcServer::HandleGetSeedHealth() const {
  nlohmann::json result;
  result["is_seed_node"] = is_seed_node_;
  if (!is_seed_node_) {
    return result;
  }
  if (peers_) {
    const auto stats = peers_->GetStats();
    result["listening"] = stats.listening;
    result["inbound_seen"] = stats.inbound_seen;
    result["reachable"] = stats.inbound_seen;
    result["inbound"] = static_cast<std::uint64_t>(stats.inbound);
    result["outbound"] = static_cast<std::uint64_t>(stats.outbound);
  } else {
    result["listening"] = false;
    result["reachable"] = false;
    result["inbound_seen"] = false;
    result["inbound"] = static_cast<std::uint64_t>(0);
    result["outbound"] = static_cast<std::uint64_t>(0);
  }
  if (addrman_) {
    result["known_addresses"] =
        static_cast<std::uint64_t>(addrman_->EntryCount());
  } else {
    result["known_addresses"] = static_cast<std::uint64_t>(0);
  }
  if (dns_seeds_) {
    nlohmann::json seeds = nlohmann::json::array();
    for (const auto& s : dns_seeds_->SnapshotSeeds()) {
      nlohmann::json entry;
      entry["host"] = s.host;
      entry["resolve_attempts"] = s.resolve_attempts;
      entry["resolve_failures"] = s.resolve_failures;
      entry["last_resolve_time"] = s.last_resolve_time;
      entry["address_count"] =
          static_cast<std::uint64_t>(s.last_addresses.size());
      seeds.push_back(std::move(entry));
    }
    result["seeds"] = std::move(seeds);
  } else {
    result["seeds"] = nlohmann::json::array();
  }
  return result;
}

nlohmann::json RpcServer::HandleListDnsSeeds() const {
  nlohmann::json result = nlohmann::json::array();
  if (!dns_seeds_) {
    return result;
  }
  for (const auto& s : dns_seeds_->SnapshotSeeds()) {
    nlohmann::json entry;
    entry["host"] = s.host;
    entry["resolve_attempts"] = s.resolve_attempts;
    entry["resolve_failures"] = s.resolve_failures;
    entry["last_resolve_time"] = s.last_resolve_time;
    nlohmann::json addrs = nlohmann::json::array();
    for (const auto& ip : s.last_addresses) {
      addrs.push_back(ip);
    }
    entry["addresses"] = std::move(addrs);
    result.push_back(std::move(entry));
  }
  return result;
}

nlohmann::json RpcServer::HandleRefreshDnsSeeds() {
  if (!dns_seeds_) {
    ThrowRpcError(-32601, "DNS seed manager is not available");
  }
  dns_seeds_->ForceRefresh();
  dns_seeds_->Tick();
  return HandleListDnsSeeds();
}

nlohmann::json RpcServer::HandleGetChainTips() const {
  nlohmann::json result = nlohmann::json::array();
  const auto tips = chain_.GetChainTips();
  for (const auto& tip : tips) {
    nlohmann::json entry;
    entry["hash"] = tip.hash_hex;
    entry["height"] = tip.height;
    entry["in_active_chain"] = tip.in_active_chain;
    entry["branch_length"] = tip.branch_length;
    std::string status = "unknown";
    if (tip.in_active_chain && tip.is_best_tip) {
      status = "active";
    } else if (tip.in_active_chain) {
      status = "active-old-tip";
    } else if (tip.branch_length == 0) {
      status = "valid-fork";
    } else {
      status = "valid-branch";
    }
    entry["status"] = status;
    result.push_back(entry);
  }
  return result;
}

nlohmann::json RpcServer::HandleAddNode(const nlohmann::json& params) {
  if (!peers_) {
    throw std::runtime_error("P2P networking is disabled");
  }
  if (!params.is_object() || !params.contains("address")) {
    throw std::runtime_error("addnode expects params.address");
  }
  auto address = params.at("address").get<std::string>();
  std::string host = address;
  std::uint16_t port =
      static_cast<std::uint16_t>(consensus::Params(config::GetNetworkConfig().type)
                                     .p2p_default_port);
  const auto pos = address.rfind(':');
  if (pos != std::string::npos) {
    host = address.substr(0, pos);
    port = static_cast<std::uint16_t>(std::stoi(address.substr(pos + 1)));
  }
  std::string dial_error;
  if (!peers_->ConnectToPeer(host, port, &dial_error)) {
    if (!dial_error.empty()) {
      throw std::runtime_error("failed to connect to peer: " + dial_error);
    }
    throw std::runtime_error("failed to connect to peer");
  }
  {
    std::lock_guard<std::mutex> lock(added_nodes_mutex_);
    if (std::find(added_nodes_.begin(), added_nodes_.end(), address) == added_nodes_.end()) {
      added_nodes_.push_back(address);
    }
  }
  return true;
}

nlohmann::json RpcServer::HandleDisconnectNode(const nlohmann::json& params) {
  if (!peers_) {
    throw std::runtime_error("P2P networking is disabled");
  }
  if (!params.is_object() || !params.contains("id")) {
    throw std::runtime_error("disconnectnode expects params.id");
  }
  const auto id = params.at("id").get<std::uint64_t>();
  if (!peers_->DisconnectPeer(id)) {
    throw std::runtime_error("peer not found");
  }
  return true;
}

nlohmann::json RpcServer::HandleGetAddedNodeInfo() const {
  nlohmann::json result = nlohmann::json::array();
  std::vector<std::string> nodes;
  {
    std::lock_guard<std::mutex> lock(added_nodes_mutex_);
    nodes = added_nodes_;
  }
  std::vector<net::PeerManager::PeerInfo> infos;
  if (peers_) {
    infos = peers_->GetPeerInfos();
  }
  for (const auto& addr : nodes) {
    nlohmann::json entry;
    entry["address"] = addr;
    bool connected = false;
    for (const auto& info : infos) {
      if (info.address.find(addr) != std::string::npos) {
        connected = true;
        break;
      }
    }
    entry["connected"] = connected;
    result.push_back(entry);
  }
  return result;
}

nlohmann::json RpcServer::HandleSetNetworkLimits(const nlohmann::json& params) {
  if (!sync_) {
    throw std::runtime_error("block sync manager unavailable");
  }
  // Start from the built-in defaults used by BlockSyncManager.
  std::size_t inv = 1000;
  std::size_t getdata = 200;
  std::size_t headers = 50;
  std::size_t blocks = 20;
  std::size_t tx = 200;

  if (params.is_object()) {
    if (params.contains("inv_per_sec")) {
      inv = params.at("inv_per_sec").get<std::size_t>();
    }
    if (params.contains("getdata_per_sec")) {
      getdata = params.at("getdata_per_sec").get<std::size_t>();
    }
    if (params.contains("headers_per_sec")) {
      headers = params.at("headers_per_sec").get<std::size_t>();
    }
    if (params.contains("block_per_sec")) {
      blocks = params.at("block_per_sec").get<std::size_t>();
    }
    if (params.contains("tx_per_sec")) {
      tx = params.at("tx_per_sec").get<std::size_t>();
    }
  }

  sync_->SetRateLimits(inv, getdata, headers, blocks, tx);
  nlohmann::json result;
  result["inv_per_sec"] = inv;
  result["getdata_per_sec"] = getdata;
  result["headers_per_sec"] = headers;
  result["block_per_sec"] = blocks;
  result["tx_per_sec"] = tx;
  return result;
}

nlohmann::json RpcServer::HandleGetMiningInfo() const {
  nlohmann::json result;
  result["blocks"] = chain_.Height();
  const auto* tip = chain_.Tip();
  result["difficulty_bits"] = tip ? tip->header.difficulty_bits : 0;
  result["default_address"] = DefaultMiningAddress();
  result["generate_enabled"] = allow_generate_;
  if (peers_) {
    const auto stats = peers_->GetStats();
    result["peer_count"] = stats.total;
  } else {
    result["peer_count"] = 0;
  }
  return result;
}

nlohmann::json RpcServer::HandleGetMiningInfoQry() const {
  nlohmann::json result;
  const auto& params = consensus::Params(config::GetNetworkConfig().type);
  const auto* tip = chain_.Tip();
  const std::uint32_t bits =
      tip ? tip->header.difficulty_bits : params.pow_limit_bits;
  const auto target = consensus::CompactToTarget(bits);

  std::uint64_t mempool_tx_count = 0;
  {
    std::lock_guard<std::mutex> lock(mempool_mutex_);
    mempool_tx_count = static_cast<std::uint64_t>(mempool_by_txid_.size());
  }

  result["rpc_version"] = 1;
  result["network"] = params.network_id;
  result["height"] = chain_.Height();
  result["best_block_hash"] = tip ? tip->hash_hex : "";
  result["difficulty_bits"] = bits;
  result["target"] =
      util::HexEncode(std::span<const std::uint8_t>(target.data(), target.size()));
  result["mempool_tx_count"] = mempool_tx_count;
  result["min_relay_feerate_miks_per_vb"] = kMinRelayFeeMiksPerVb;
  return result;
}

nlohmann::json RpcServer::HandleGetMempoolInfo() const {
  nlohmann::json result;
  std::lock_guard<std::mutex> lock(mempool_mutex_);
  result["size"] = static_cast<std::uint64_t>(mempool_by_txid_.size());
  result["bytes"] = mempool_bytes_;
  result["limit_bytes"] = mempool_limit_bytes_;
  // Baseline relay minimum (policy). The effective mempool floor is reported
  // separately in mempoolminfee.
  result["minrelaytxfee"] = kMinRelayFeeMiksPerVb;
  result["mempoolminfee"] = mempool_min_fee_miks_per_vb_;
  return result;
}

nlohmann::json RpcServer::HandleGetHealth() const {
  nlohmann::json result;

  // Chain summary.
  const auto& params = consensus::Params(config::GetNetworkConfig().type);
  const auto blocks = chain_.Height();
  const auto* tip = chain_.Tip();
  nlohmann::json chain_json;
  chain_json["chain"] = params.network_id;
  chain_json["blocks"] = blocks;
  chain_json["bestblockhash"] = tip ? tip->hash_hex : "";
  chain_json["difficulty_bits"] =
      tip ? tip->header.difficulty_bits : 0;
  chain_json["tip_timestamp"] =
      tip ? static_cast<std::uint64_t>(tip->header.timestamp) : 0;
  if (tip) {
    const auto now =
        static_cast<std::uint64_t>(std::time(nullptr));
    std::uint64_t tip_time =
        static_cast<std::uint64_t>(tip->header.timestamp);
    std::uint64_t age = now > tip_time ? (now - tip_time) : 0;
    chain_json["tip_age_seconds"] = age;
  } else {
    chain_json["tip_age_seconds"] = nullptr;
  }
  bool has_sync = (sync_ != nullptr);
  bool initial_download = false;
  if (has_sync) {
    initial_download = !sync_->IsSynced();
    chain_json["headers"] = sync_->GetStats().best_header_height;
  } else {
    chain_json["headers"] = blocks;
  }
  chain_json["initial_block_download"] = initial_download;
  // Attach basic telemetry for fork/reorg awareness.
  const auto telemetry = chain_.GetTelemetry();
  nlohmann::json telem_json;
  telem_json["orphan_blocks"] = telemetry.orphan_blocks;
  telem_json["reorg_events"] = telemetry.reorg_events;
  telem_json["max_reorg_depth"] = telemetry.max_reorg_depth;
  telem_json["utxo_snapshot_failures"] = telemetry.utxo_snapshot_failures;
  telem_json["utxo_snapshot_dirty"] = telemetry.utxo_snapshot_dirty;
  chain_json["telemetry"] = telem_json;
  result["chain"] = chain_json;

  // Mempool summary.
  nlohmann::json mempool_json;
  {
    std::lock_guard<std::mutex> lock(mempool_mutex_);
    mempool_json["size"] = mempool_by_txid_.size();
    mempool_json["bytes"] = mempool_bytes_;
    mempool_json["limit_bytes"] = mempool_limit_bytes_;
    mempool_json["mempoolminfee"] = mempool_min_fee_miks_per_vb_;
  }
  result["mempool"] = mempool_json;

  // Peer summary (if networking is enabled).
  nlohmann::json peers_json;
  if (peers_) {
    const auto stats = peers_->GetStats();
    peers_json["total"] = stats.total;
    peers_json["inbound"] = stats.inbound;
    peers_json["outbound"] = stats.outbound;
    peers_json["service_bits"] = stats.service_bits;
  } else {
    peers_json["total"] = 0;
    peers_json["inbound"] = 0;
    peers_json["outbound"] = 0;
    peers_json["service_bits"] = 0;
  }
  result["peers"] = peers_json;

  // High-level status and basic warnings for operators.
  nlohmann::json warnings = nlohmann::json::array();
  const bool ok_chain = (blocks > 0);
  const bool ok_peers = (!peers_ || peers_->GetStats().total > 0);
  const bool ok_mempool = (mempool_limit_bytes_ == 0 ||
                           mempool_bytes_ < mempool_limit_bytes_ * 9 / 10);
  const auto max_reorg_depth = telemetry.max_reorg_depth;
  const auto reorg_events = telemetry.reorg_events;
  if (!ok_chain) {
    warnings.push_back("no blocks connected yet");
  }
  if (!ok_peers && peers_) {
    warnings.push_back("no active peers");
  }
  if (!ok_mempool && mempool_limit_bytes_ != 0) {
    warnings.push_back("mempool usage above 90% of configured limit");
  }
  if (reorg_events > 0 && max_reorg_depth >= 6) {
    warnings.push_back("deep reorg observed; review fork status");
  }
  if (telemetry.utxo_snapshot_dirty) {
    warnings.push_back("utxo snapshot not persisted; check disk space/permissions");
  }
  result["ok"] = warnings.empty();
  result["warnings"] = warnings;

  return result;
}

nlohmann::json RpcServer::HandleGetRawMempool(const nlohmann::json&) const {
  nlohmann::json result = nlohmann::json::array();
  std::lock_guard<std::mutex> lock(mempool_mutex_);
  for (const auto& kv : mempool_by_txid_) {
    result.push_back(HashToHex(kv.first));
  }
  return result;
}

nlohmann::json RpcServer::HandleGetMempoolEntry(const nlohmann::json& params) const {
  if (!params.is_object() || !params.contains("txid")) {
    throw std::runtime_error("getmempoolentry expects params.txid");
  }
  const auto txid_hex = params.at("txid").get<std::string>();
  if (txid_hex.size() != 64) {
    throw std::runtime_error("txid must be 32-byte hex");
  }
  std::vector<std::uint8_t> txid_bytes;
  if (!util::HexDecode(txid_hex, &txid_bytes) ||
      txid_bytes.size() != primitives::Hash256{}.size()) {
    throw std::runtime_error("invalid txid hex");
  }
  primitives::Hash256 target{};
  std::copy(txid_bytes.begin(), txid_bytes.end(), target.begin());

  std::lock_guard<std::mutex> lock(mempool_mutex_);
  auto it = mempool_by_txid_.find(target);
  if (it != mempool_by_txid_.end()) {
    const auto& entry = it->second;
    nlohmann::json result;
    result["size_bytes"] = entry.size_bytes;
    result["vbytes"] = entry.vbytes;
    result["fee_miks"] = entry.fee_miks;
    result["feerate_miks_per_vb"] = entry.feerate_miks_per_vb;
    result["entry_height"] = entry.entry_height;
    result["time_first_seen"] = entry.time_first_seen;
    return result;
  }
  throw std::runtime_error("tx not in mempool");
}

nlohmann::json RpcServer::HandleCreateRawTransaction(const nlohmann::json& params) const {
  if (!params.is_object()) {
    throw std::runtime_error("createrawtransaction expects a params object");
  }
  primitives::CTransaction tx;
  tx.version = 1;
  tx.lock_time = 0;

  if (!params.contains("inputs") || !params.at("inputs").is_array()) {
    throw std::runtime_error("createrawtransaction requires an 'inputs' array");
  }
  if (!params.contains("outputs") || !params.at("outputs").is_array()) {
    throw std::runtime_error("createrawtransaction requires an 'outputs' array");
  }

  const auto& in_arr = params.at("inputs");
  for (const auto& in_val : in_arr) {
    if (!in_val.is_object()) {
      throw std::runtime_error("inputs must be objects");
    }
    primitives::CTxIn in;
    if (!in_val.contains("txid") || !in_val.contains("vout")) {
      throw std::runtime_error("each input requires txid and vout");
    }
    const auto txid_hex = in_val.at("txid").get<std::string>();
    if (txid_hex.size() != 64) {
      throw std::runtime_error("txid must be 32-byte hex");
    }
    std::vector<std::uint8_t> txid_bytes;
    if (!util::HexDecode(txid_hex, &txid_bytes) || txid_bytes.size() != in.prevout.txid.size()) {
      throw std::runtime_error("invalid txid hex");
    }
    std::copy(txid_bytes.begin(), txid_bytes.end(), in.prevout.txid.begin());
    in.prevout.index = in_val.at("vout").get<std::uint32_t>();
    if (in_val.contains("sequence")) {
      in.sequence = in_val.at("sequence").get<std::uint32_t>();
    } else {
      in.sequence = 0xFFFFFFFFu;
    }
    in.unlocking_descriptor.clear();
    in.witness_stack.clear();
    tx.vin.push_back(std::move(in));
  }

  const auto& out_arr = params.at("outputs");
  const auto& cfg = config::GetNetworkConfig();
  for (const auto& out_val : out_arr) {
    if (!out_val.is_object()) {
      throw std::runtime_error("outputs must be objects");
    }
    primitives::CTxOut out;
    if (!out_val.contains("amount")) {
      throw std::runtime_error("each output requires amount");
    }
    auto amount_opt = ParseAmount(out_val.at("amount"));
    if (!amount_opt) {
      throw std::runtime_error("invalid amount in output");
    }
    out.value = *amount_opt;

    // Either "address" (P2QH) or "script_pubkey" (hex) must be present.
    if (out_val.contains("address")) {
      const auto addr = out_val.at("address").get<std::string>();
      crypto::P2QHDescriptor desc{};
      if (!crypto::DecodeP2QHAddress(addr, cfg.bech32_hrp, &desc)) {
        throw std::runtime_error("invalid P2QH address in output");
      }
      auto script = script::CreateP2QHScript(desc);
      out.locking_descriptor = script.data;
    } else if (out_val.contains("script_pubkey")) {
      const auto script_hex = out_val.at("script_pubkey").get<std::string>();
      std::vector<std::uint8_t> script_bytes;
      if (!util::HexDecode(script_hex, &script_bytes)) {
        throw std::runtime_error("invalid script_pubkey hex");
      }
      out.locking_descriptor = std::move(script_bytes);
    } else {
      throw std::runtime_error("each output requires address or script_pubkey");
    }
    tx.vout.push_back(std::move(out));
  }

  if (params.contains("lock_time")) {
    tx.lock_time = params.at("lock_time").get<std::uint32_t>();
  }

  std::vector<std::uint8_t> raw;
  primitives::serialize::SerializeTransaction(tx, &raw, /*include_witness=*/false);
  nlohmann::json result;
  result["hex"] =
      util::HexEncode(std::span<const std::uint8_t>(raw.data(), raw.size()));
  return result;
}

nlohmann::json RpcServer::HandleDecodeRawTransaction(const nlohmann::json& params) const {
  if (!params.is_object() || !params.contains("hex")) {
    throw std::runtime_error("decoderawtransaction expects params.hex");
  }
  const auto hex = params.at("hex").get<std::string>();
  std::vector<std::uint8_t> raw;
  if (!util::HexDecode(hex, &raw)) {
    throw std::runtime_error("invalid hex");
  }
  primitives::CTransaction tx;
  std::size_t offset = 0;
  if (!primitives::serialize::DeserializeTransaction(raw, &offset, &tx,
                                                     /*expect_witness=*/true) ||
      offset != raw.size()) {
    throw std::runtime_error("failed to deserialize transaction");
  }
  return TxToJson(tx, wallet_.get());
}

nlohmann::json RpcServer::HandleGetRawTransaction(const nlohmann::json& params) const {
  if (!params.is_object() || !params.contains("txid")) {
    throw std::runtime_error("getrawtransaction expects params.txid");
  }
  const auto txid_hex = params.at("txid").get<std::string>();
  if (txid_hex.size() != 64) {
    throw std::runtime_error("txid must be 32-byte hex");
  }
  std::vector<std::uint8_t> txid_bytes;
  if (!util::HexDecode(txid_hex, &txid_bytes) ||
      txid_bytes.size() != primitives::Hash256{}.size()) {
    throw std::runtime_error("invalid txid hex");
  }
  primitives::Hash256 target{};
  std::copy(txid_bytes.begin(), txid_bytes.end(), target.begin());

  primitives::CTransaction found_tx;
  std::string block_hash;
  std::uint32_t block_height = 0;
  bool in_mempool = false;
  bool found = false;

  {
    std::lock_guard<std::mutex> lock(mempool_mutex_);
    auto it = mempool_by_txid_.find(target);
    if (it != mempool_by_txid_.end()) {
      found_tx = it->second.tx;
      in_mempool = true;
      found = true;
    }
  }

  if (!found) {
    const auto blocks = chain_.BlockCount();
    for (std::size_t h = 0; h < blocks; ++h) {
      const auto* record = chain_.GetByHeight(h);
      if (!record) {
        continue;
      }
      primitives::CBlock block;
      std::string read_error;
      if (!chain_.ReadBlock(*record, &block, &read_error)) {
        continue;
      }
      for (const auto& tx : block.transactions) {
        const auto txid = primitives::ComputeTxId(tx);
        if (txid == target) {
          found_tx = tx;
          block_hash = record->hash_hex;
          block_height = static_cast<std::uint32_t>(record->height);
          found = true;
          break;
        }
      }
      if (found) {
        break;
      }
    }
  }

  if (!found) {
    throw std::runtime_error("tx not found");
  }

  bool verbose = false;
  if (params.contains("verbose")) {
    verbose = params.at("verbose").get<bool>();
  }

  if (!verbose) {
    return SerializeTransactionHex(found_tx);
  }

  nlohmann::json result = TxToJson(found_tx, wallet_.get());
  result["hex"] = SerializeTransactionHex(found_tx);
  result["blockhash"] = block_hash;
  result["in_mempool"] = in_mempool;
  if (!in_mempool && !block_hash.empty()) {
    const auto blocks = chain_.BlockCount();
    std::uint32_t confirmations = 0;
    if (blocks > block_height) {
      confirmations =
          static_cast<std::uint32_t>(blocks - block_height);
    } else {
      confirmations = 1;
    }
    result["confirmations"] = confirmations;
    result["blockheight"] = block_height;
  } else {
    result["confirmations"] = 0;
    result["blockheight"] = nullptr;
  }
  return result;
}

nlohmann::json RpcServer::HandleSendRawTransaction(const nlohmann::json& params) {
  if (!params.is_object() || !params.contains("hex")) {
    throw std::runtime_error("sendrawtransaction expects params.hex");
  }
  const auto hex = params.at("hex").get<std::string>();
  std::vector<std::uint8_t> raw;
  if (!util::HexDecode(hex, &raw)) {
    throw std::runtime_error("invalid hex");
  }
  primitives::CTransaction tx;
  std::size_t offset = 0;
  if (!primitives::serialize::DeserializeTransaction(raw, &offset, &tx,
                                                     /*expect_witness=*/true) ||
      offset != raw.size()) {
    throw std::runtime_error("failed to deserialize transaction");
  }
  if (tx.IsCoinbase()) {
    throw std::runtime_error("sendrawtransaction cannot be used with coinbase transactions");
  }

  std::string reject_reason;
  const bool accepted = AddToMempool(tx, std::nullopt, &reject_reason);
  if (!accepted) {
    if (reject_reason.empty()) {
      reject_reason = "rejected";
    }
    throw std::runtime_error("transaction rejected: " + reject_reason);
  }
  BroadcastTransaction(tx);

  const auto txid = primitives::ComputeTxId(tx);
  return HashToHex(txid);
}

nlohmann::json RpcServer::HandleEstimateSmartFee(const nlohmann::json& params) const {
  std::uint32_t target_blocks = 3;
  if (params.is_array() && !params.empty()) {
    target_blocks = params[0].get<std::uint32_t>();
  } else if (params.is_object() && params.contains("target_blocks")) {
    target_blocks = params.at("target_blocks").get<std::uint32_t>();
  }
  if (target_blocks == 0) {
    target_blocks = 1;
  }
  double fee_rate = fee_estimator_.EstimateFeeRate(target_blocks, mempool_min_fee_miks_per_vb_);
  nlohmann::json result;
  result["feerate"] = fee_rate;
  result["blocks"] = target_blocks;
  return result;
}

nlohmann::json RpcServer::HandleGetBlockTemplate(const nlohmann::json& params) {
  std::string address;
  std::string requested_longpollid;
  int timeout_seconds = 0;
  if (params.is_object()) {
    if (params.contains("address")) {
      address = params.at("address").get<std::string>();
    }
    if (params.contains("longpollid")) {
      requested_longpollid = params.at("longpollid").get<std::string>();
    }
    if (params.contains("timeout")) {
      timeout_seconds = params.at("timeout").get<int>();
    }
  }

  auto current_longpoll_id = [&]() -> std::string {
    std::string id;
    if (const auto* tip = chain_.Tip()) {
      id = tip->hash_hex;
    }
    std::uint64_t bytes = 0;
    std::size_t size = 0;
    {
      std::lock_guard<std::mutex> lock(mempool_mutex_);
      bytes = mempool_bytes_;
      size = mempool_by_txid_.size();
    }
    id += ":" + std::to_string(bytes) + ":" + std::to_string(size);
    return id;
  };

  if (!requested_longpollid.empty() && timeout_seconds > 0) {
    const auto start = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(timeout_seconds);
    while (requested_longpollid == current_longpoll_id()) {
      if (std::chrono::steady_clock::now() - start >= timeout) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
  }

  crypto::P2QHDescriptor descriptor;
  if (!address.empty()) {
    descriptor = DescriptorForAddress(address);
  } else {
    descriptor = DefaultMiningRewardDescriptor(&address);
  }
  node::BlockTemplate templ;
  std::string error;
  if (!node::BuildBlockTemplate(chain_, descriptor, &templ, &error)) {
    throw std::runtime_error("failed to build template: " + error);
  }
  FillBlockFromMempool(&templ.block, templ.height);

  // Build a miner-oriented transaction list to inspect or filter the block
  // contents before hashing. Fees and dependencies are derived from a fresh
  // UTXO snapshot so they are consistent with the current active chain.
  nlohmann::json txs = nlohmann::json::array();
  consensus::UTXOSet view = chain_.SnapshotUtxo();
  consensus::RevealedPubkeySet revealed_pubkeys = chain_.SnapshotRevealedPubkeys();
  primitives::Amount total_fees{0};
  const auto lock_time_cutoff_time = MedianTimePastTip(chain_);
  for (std::size_t i = 1; i < templ.block.transactions.size(); ++i) {
    const auto& tx = templ.block.transactions[i];
    nlohmann::json entry;
    const auto txid = primitives::ComputeTxId(tx);
    entry["txid"] = HashToHex(txid);
    entry["hash"] = HashToHex(primitives::ComputeWTxId(tx));  // wtxid

    std::vector<std::uint8_t> raw_tx;
    primitives::serialize::SerializeTransaction(tx, &raw_tx);
    entry["data"] = util::HexEncode(
        std::span<const std::uint8_t>(raw_tx.data(), raw_tx.size()));

    std::string tx_error;
    std::vector<primitives::Hash256> revealed_keys;
    if (!consensus::ValidateTransaction(tx, view, revealed_pubkeys, templ.height,
                                        lock_time_cutoff_time, &revealed_keys, &tx_error)) {
      entry["valid"] = false;
      entry["error"] = tx_error;
      entry["fee"] = 0;
      entry["depends"] = nlohmann::json::array();
      txs.push_back(entry);
      continue;
    }
    std::vector<primitives::Hash256> inserted_keys;
    inserted_keys.reserve(revealed_keys.size());
    bool inserted_all = true;
    for (const auto& pk_hash : revealed_keys) {
      if (!revealed_pubkeys.Insert(pk_hash)) {
        inserted_all = false;
        break;
      }
      inserted_keys.push_back(pk_hash);
    }
    if (!inserted_all) {
      for (const auto& pk_hash : inserted_keys) {
        revealed_pubkeys.Erase(pk_hash);
      }
      entry["valid"] = false;
      entry["error"] = "public key already revealed";
      entry["fee"] = 0;
      entry["depends"] = nlohmann::json::array();
      txs.push_back(entry);
      continue;
    }

    primitives::Amount fee = 0;
    if (!ComputeTransactionFee(tx, view, &fee)) {
      for (const auto& pk_hash : inserted_keys) {
        revealed_pubkeys.Erase(pk_hash);
      }
      entry["valid"] = false;
      entry["error"] = "fee computation failed";
      entry["fee"] = 0;
      entry["depends"] = nlohmann::json::array();
      txs.push_back(entry);
      continue;
    }

    entry["valid"] = true;
    entry["fee"] = fee;

    const auto sizes = primitives::serialize::MeasureTransactionSizes(tx);
    std::uint64_t weight =
        static_cast<std::uint64_t>(sizes.base_size) * 4ULL +
        static_cast<std::uint64_t>(sizes.witness_size);
    entry["weight"] = weight;

    // Dependencies: 0-based indices into this "transactions" list of earlier
    // transactions whose outputs are spent by this tx.
    nlohmann::json depends = nlohmann::json::array();
    for (const auto& in : tx.vin) {
      for (std::size_t j = 1; j < i; ++j) {
        const auto prev_txid = primitives::ComputeTxId(templ.block.transactions[j]);
        if (in.prevout.txid == prev_txid) {
          depends.push_back(static_cast<std::uint64_t>(j - 1));
          break;
        }
      }
    }
    entry["depends"] = depends;

    txs.push_back(entry);

    // Advance the local UTXO view so subsequent transactions can spend
    // these outputs, mirroring full node behavior.
    for (const auto& in : tx.vin) {
      view.SpendCoin(in.prevout);
    }
    for (std::size_t out_index = 0; out_index < tx.vout.size(); ++out_index) {
      primitives::COutPoint outpoint;
      outpoint.txid = txid;
      outpoint.index = static_cast<std::uint32_t>(out_index);
      consensus::Coin coin;
      coin.out = tx.vout[out_index];
      coin.height = templ.height;
      coin.coinbase = false;
      view.AddCoin(outpoint, coin);
    }
    primitives::Amount next_total_fees = 0;
    if (!primitives::CheckedAdd(total_fees, fee, &next_total_fees)) {
      total_fees = primitives::kMaxMoney;
    } else {
      total_fees = next_total_fees;
    }
  }

    std::vector<std::uint8_t> coinbase_bytes;
    primitives::serialize::SerializeTransaction(templ.block.transactions.front(), &coinbase_bytes);
    nlohmann::json result;
  result["version"] = templ.block.header.version;
  result["previousblockhash"] = HashToHex(templ.block.header.previous_block_hash);
  std::ostringstream bits;
  bits << std::hex << std::setw(8) << std::setfill('0') << templ.block.header.difficulty_bits;
  result["bits"] = bits.str();
  result["target"] =
      util::HexEncode(std::span<const std::uint8_t>(templ.target.data(), templ.target.size()));
  result["height"] = templ.height;
  result["curtime"] = templ.block.header.timestamp;
  result["coinbasevalue"] = templ.block.transactions.front().vout.front().value;
    result["coinbasetxn"] = util::HexEncode(coinbase_bytes);
    result["merkleroot"] = HashToHex(templ.block.header.merkle_root);

    // Extensions: transaction list, mutability hints, and a lightweight
    // longpoll identifier for future use.
    result["transactions"] = txs;

    nlohmann::json mutable_fields = nlohmann::json::array();
    mutable_fields.push_back("coinbase/append");
    mutable_fields.push_back("time");
    result["mutable"] = mutable_fields;

    result["longpollid"] = current_longpoll_id();

    // Capabilities/rules reserved for future miner coordination.
    result["rules"] = nlohmann::json::array();
    result["capabilities"] = nlohmann::json::array();
    result["totalfees"] = total_fees;
  return result;
}

nlohmann::json RpcServer::HandleGetBlockTemplateQry(const nlohmann::json& params) {
  std::string address;
  if (params.is_object() && params.contains("address")) {
    address = params.at("address").get<std::string>();
  }

  auto current_template_id = [&]() -> std::string {
    std::string id;
    if (const auto* tip = chain_.Tip()) {
      id = tip->hash_hex;
    }
    std::uint64_t bytes = 0;
    std::size_t size = 0;
    {
      std::lock_guard<std::mutex> lock(mempool_mutex_);
      bytes = mempool_bytes_;
      size = mempool_by_txid_.size();
    }
    id += ":" + std::to_string(bytes) + ":" + std::to_string(size);
    return id;
  };

  crypto::P2QHDescriptor descriptor;
  if (!address.empty()) {
    descriptor = DescriptorForAddress(address);
  } else {
    descriptor = DefaultMiningRewardDescriptor(&address);
  }

  node::BlockTemplate templ;
  std::string error;
  if (!node::BuildBlockTemplate(chain_, descriptor, &templ, &error)) {
    ThrowRpcError(-32603, error.empty() ? "failed to build template" : error);
  }
  FillBlockFromMempool(&templ.block, templ.height);

  const auto& chain_params = consensus::Params(config::GetNetworkConfig().type);
  const std::uint64_t subsidy =
      static_cast<std::uint64_t>(consensus::CalculateBlockSubsidy(templ.height));
  std::uint64_t total_fees = 0;
  if (!templ.block.transactions.empty() && !templ.block.transactions.front().vout.empty()) {
    const auto coinbase_value =
        static_cast<std::uint64_t>(templ.block.transactions.front().vout.front().value);
    total_fees = coinbase_value >= subsidy ? (coinbase_value - subsidy) : 0;
  }

  nlohmann::json txs = nlohmann::json::array();
  std::unordered_map<primitives::Hash256, std::size_t, Hash256Hasher> index_by_txid;
  if (templ.block.transactions.size() > 1) {
    index_by_txid.reserve(templ.block.transactions.size() - 1);
    for (std::size_t i = 1; i < templ.block.transactions.size(); ++i) {
      index_by_txid.emplace(primitives::ComputeTxId(templ.block.transactions[i]), i - 1);
    }
  }

  for (std::size_t i = 1; i < templ.block.transactions.size(); ++i) {
    const auto& tx = templ.block.transactions[i];
    nlohmann::json entry;
    const auto txid = primitives::ComputeTxId(tx);
    const auto wtxid = primitives::ComputeWTxId(tx);
    entry["txid"] = HashToHex(txid);
    entry["wtxid"] = HashToHex(wtxid);

    std::vector<std::uint8_t> raw_tx;
    primitives::serialize::SerializeTransaction(tx, &raw_tx, /*include_witness=*/true);
    entry["data"] = util::HexEncode(
        std::span<const std::uint8_t>(raw_tx.data(), raw_tx.size()));

    entry["fee_miks"] = nullptr;
    {
      std::lock_guard<std::mutex> lock(mempool_mutex_);
      auto it = mempool_by_txid_.find(txid);
      if (it != mempool_by_txid_.end()) {
        entry["fee_miks"] = static_cast<std::uint64_t>(it->second.fee_miks);
      }
    }

    const auto sizes = primitives::serialize::MeasureTransactionSizes(tx);
    const std::uint64_t weight =
        static_cast<std::uint64_t>(sizes.base_size) * 4ULL +
        static_cast<std::uint64_t>(sizes.witness_size);
    entry["weight"] = weight;

    nlohmann::json depends = nlohmann::json::array();
    for (const auto& in : tx.vin) {
      auto it = index_by_txid.find(in.prevout.txid);
      if (it != index_by_txid.end()) {
        depends.push_back(static_cast<std::uint64_t>(it->second));
      }
    }
    entry["depends"] = depends;
    txs.push_back(entry);
  }

  nlohmann::json coinbase;
  if (!templ.block.transactions.empty()) {
    const auto& cb = templ.block.transactions.front();
    if (!cb.vout.empty()) {
      const auto& payout = cb.vout.front();
      coinbase["payout_script"] = util::HexEncode(
          std::span<const std::uint8_t>(payout.locking_descriptor.data(),
                                        payout.locking_descriptor.size()));
      coinbase["subsidy_miks"] = subsidy;
      coinbase["total_fees_miks"] = total_fees;
      coinbase["witness_commitment_required"] =
          chain_params.witness_commitment_activation_height == 0 ||
          templ.height >= chain_params.witness_commitment_activation_height;
      coinbase["witness_commitment_tag"] =
          util::HexEncode(std::span<const std::uint8_t>(consensus::kWitnessCommitmentTag.data(),
                                                       consensus::kWitnessCommitmentTag.size()));

      nlohmann::json rules;
      rules["height_varint"] = "canonical";
      rules["extra_nonce_bytes"] = consensus::kCoinbaseExtraNonceSize;
      rules["tag"] = "QRYW01";
      rules["witness_root_bytes"] = consensus::kWitnessCommitmentRootSize;
      rules["no_trailing_bytes"] = true;
      coinbase["reward_unlocking_descriptor_rules"] = rules;
    }
  }

  nlohmann::json limits;
  limits["max_block_weight"] = 8'000'000;
  limits["max_block_serialized_bytes"] = chain_params.max_block_serialized_bytes;

  nlohmann::json result;
  result["rpc_version"] = 1;
  result["template_id"] = current_template_id();
  result["height"] = templ.height;
  result["prev_block_hash"] = HashToHex(templ.block.header.previous_block_hash);
  result["version"] = templ.block.header.version;
  result["difficulty_bits"] = templ.block.header.difficulty_bits;
  result["target"] =
      util::HexEncode(std::span<const std::uint8_t>(templ.target.data(), templ.target.size()));
  result["curtime"] = templ.block.header.timestamp;
  result["mutable_fields"] = nlohmann::json::array({"time", "transactions"});
  result["coinbase"] = coinbase;
  result["transactions"] = txs;
  result["limits"] = limits;
  return result;
}

nlohmann::json RpcServer::HandleSubmitBlock(const nlohmann::json& params) {
  std::string hex;
  if (params.is_array() && !params.empty()) {
    hex = params[0].get<std::string>();
  } else if (params.is_object() && params.contains("hex")) {
    hex = params.at("hex").get<std::string>();
  } else {
    throw std::runtime_error("submitblock expects hex string");
  }
  std::vector<std::uint8_t> raw;
  if (!util::HexDecode(hex, &raw)) {
    throw std::runtime_error("invalid hex");
  }
  primitives::CBlock block;
  std::size_t offset = 0;
  if (!primitives::serialize::DeserializeBlock(raw, &offset, &block)) {
    throw std::runtime_error("failed to deserialize block");
  }
  std::string error;
  if (!chain_.ConnectBlock(block, &error)) {
    throw std::runtime_error("block rejected: " + error);
  }
  const auto hash = consensus::ComputeBlockHash(block.header);
  IndexWalletOutputs(block);
  AnnounceBlock(hash);
  RemoveMinedTransactions(block, static_cast<std::uint32_t>(chain_.BlockCount() - 1));
  nlohmann::json result;
  result["status"] = "accepted";
  result["hash"] = HashToHex(hash);
  result["height"] = chain_.BlockCount() - 1;
  return result;
}

nlohmann::json RpcServer::HandleSubmitBlockQry(const nlohmann::json& params) {
  if (!params.is_object() || !params.contains("block_hex")) {
    ThrowRpcError(-32602, "missing block_hex");
  }
  const auto block_hex = params.at("block_hex").get<std::string>();

  std::vector<std::uint8_t> raw;
  if (!util::HexDecode(block_hex, &raw)) {
    ThrowRpcError(-32602, "invalid hex");
  }

  primitives::CBlock block;
  std::size_t offset = 0;
  if (!primitives::serialize::DeserializeBlock(raw, &offset, &block) || offset != raw.size()) {
    ThrowRpcError(-32602, "failed to deserialize block");
  }

  const auto hash = consensus::ComputeBlockHash(block.header);
  const auto hash_hex = HashToHex(hash);

  std::string connect_error;
  const bool ok = chain_.ConnectBlock(block, &connect_error);
  if (ok) {
    IndexWalletOutputs(block);
    AnnounceBlock(hash);
    RemoveMinedTransactions(block, static_cast<std::uint32_t>(chain_.BlockCount() - 1));
  }

  bool active = false;
  if (const auto* tip = chain_.Tip()) {
    active = (tip->hash_hex == hash_hex);
  }

  nlohmann::json result;
  result["rpc_version"] = 1;
  result["block_hash"] = hash_hex;
  if (!ok) {
    result["status"] = "rejected";
    result["reject_reason"] = connect_error.empty() ? "rejected" : connect_error;
    return result;
  }
  if (!active) {
    result["status"] = "rejected";
    result["reject_reason"] = "stale tip";
    return result;
  }
  result["status"] = "accepted";
  result["reject_reason"] = nullptr;
  return result;
}

nlohmann::json RpcServer::HandleGenerate(const nlohmann::json& params, bool to_address) {
  if (!allow_generate_) {
    throw std::runtime_error("generate disabled (start qryptd with --allow-generate)");
  }
  int blocks = 1;
  std::string address;
  const bool address_requested = to_address;
  if (params.is_array()) {
    if (!params.empty()) {
      blocks = params[0].get<int>();
    }
    if (to_address) {
      if (params.size() < 2) {
        throw std::runtime_error("generatetoaddress requires address");
      }
      address = params[1].get<std::string>();
    }
  } else if (params.is_object()) {
    if (params.contains("blocks")) {
      blocks = params.at("blocks").get<int>();
    }
    if (to_address && params.contains("address")) {
      address = params.at("address").get<std::string>();
    }
  }
  if (blocks <= 0) {
    throw std::runtime_error("blocks must be > 0");
  }
  nlohmann::json hashes = nlohmann::json::array();

  if (address_requested && address.empty()) {
    throw std::runtime_error("generatetoaddress requires address");
  }

  // If the caller specifies an address (or the operator configures one), mine
  // all requested blocks to that destination. Otherwise default to fresh payout
  // programs from the loaded wallet.
  if (!address.empty() || !default_mining_address_.empty()) {
    const std::string payout = !address.empty() ? address : default_mining_address_;
    auto descriptor = DescriptorForAddress(payout);
    for (int i = 0; i < blocks; ++i) {
      std::string hash_hex;
      std::uint32_t height = 0;
      std::string error;
      if (!MineSingleBlock(descriptor, &hash_hex, &height, &error)) {
        if (error.empty()) {
          error = "unknown error";
        }
        throw std::runtime_error("failed to mine block: " + error);
      }
      hashes.push_back(hash_hex);
    }
    return hashes;
  }

  if (!WalletLoaded()) {
    throw std::runtime_error(
        "no mining payout configured; pass an address, set --mining-address, or load a wallet");
  }

  auto& wallet = WalletOrThrow();
  for (int i = 0; i < blocks; ++i) {
    const std::string payout = wallet.NewAddress();
    auto descriptor = DescriptorForAddress(payout);
    std::string hash_hex;
    std::uint32_t height = 0;
    std::string error;
    if (!MineSingleBlock(descriptor, &hash_hex, &height, &error)) {
      if (error.empty()) {
        error = "unknown error";
      }
      throw std::runtime_error("failed to mine block: " + error);
    }
    hashes.push_back(hash_hex);
  }
  return hashes;
}

nlohmann::json RpcServer::HandleCreateWallet(const nlohmann::json& params) {
  if (!params.contains("wallet_path") || !params.contains("passphrase")) {
    throw std::runtime_error("wallet_path and passphrase are required");
  }
  const auto path = params.at("wallet_path").get<std::string>();
  const auto passphrase = params.at("passphrase").get<std::string>();
  if (passphrase.empty()) {
    throw std::runtime_error("passphrase cannot be empty");
  }
  if (params.contains("policy") || params.contains("hybrid_policy")) {
    throw std::runtime_error("wallet policy selection has been removed; Dilithium3 is mandatory");
  }

  // Optional mnemonic-based creation: if a mnemonic is provided, derive the
  // master seed from it so users can restore existing wallets.
  if (params.contains("mnemonic")) {
    const auto mnemonic = params.at("mnemonic").get<std::string>();
    std::string mnemonic_passphrase;
    if (params.contains("mnemonic_passphrase")) {
      mnemonic_passphrase = params.at("mnemonic_passphrase").get<std::string>();
    }
    if (!wallet_) {
      wallet_ = wallet::HDWallet::Create(path, passphrase, crypto::SignatureAlgorithm::kDilithium);
    }
    if (!wallet_ ||
        !wallet_->CreateFromMnemonic(path, passphrase, mnemonic, mnemonic_passphrase,
                                     crypto::SignatureAlgorithm::kDilithium)) {
      const std::string wallet_error = wallet_ ? wallet_->last_error() : std::string{};
      throw std::runtime_error(wallet_error.empty()
                                   ? "failed to create wallet from mnemonic"
                                   : ("failed to create wallet from mnemonic: " + wallet_error));
    }
  } else {
    if (!wallet_) {
      wallet_ = wallet::HDWallet::Create(path, passphrase, crypto::SignatureAlgorithm::kDilithium);
      if (!wallet_) {
        throw std::runtime_error("failed to create wallet");
      }
    } else {
      if (!wallet_->CreateFresh(path, passphrase, crypto::SignatureAlgorithm::kDilithium)) {
        const auto err = wallet_->last_error();
        throw std::runtime_error(err.empty() ? "failed to create wallet"
                                             : ("failed to create wallet: " + err));
      }
    }
  }

  auto& wallet = WalletOrThrow();

  // New wallets have no historical activity; record the current chain height as
  // the birth/scan point so future rescans can start from there.
  const auto blocks = chain_.BlockCount();
  wallet.SetBirthHeight(static_cast<std::uint32_t>(blocks));
  wallet.SetLastScanHeight(static_cast<std::uint32_t>(blocks));
  wallet.Save();

  nlohmann::json result;
  result["status"] = "created";
  result["path"] = path;
  if (params.contains("wallet_name")) {
    result["wallet_name"] = params.at("wallet_name").get<std::string>();
  } else {
    result["wallet_name"] =
        std::filesystem::path(path).parent_path().filename().string();
  }
  result["default_policy"] = AlgoToString(wallet.DefaultAlgorithm());
  return result;
}

nlohmann::json RpcServer::HandleLoadWallet(const nlohmann::json& params) {
  if (!params.contains("path")) {
    throw std::runtime_error("path parameter required");
  }
  const auto path = params.at("path").get<std::string>();
  std::string passphrase;
  if (params.contains("passphrase")) {
    passphrase = params.at("passphrase").get<std::string>();
  } else if (wallet_) {
    passphrase = wallet_->CurrentPassphrase();
  } else {
    throw std::runtime_error("passphrase parameter required");
  }

  if (wallet_) {
    if (!wallet_->LoadFromFile(path, passphrase)) {
      if (!wallet_->last_error().empty()) {
        throw std::runtime_error("failed to load wallet: " + wallet_->last_error());
      }
      throw std::runtime_error("failed to load wallet");
    }
  } else {
    std::string load_error;
    wallet_ = wallet::HDWallet::Load(path, passphrase, &load_error);
    if (!wallet_) {
      if (!load_error.empty()) {
        throw std::runtime_error("failed to load wallet: " + load_error);
      }
      throw std::runtime_error("failed to load wallet");
    }
  }

  // Optional, best-effort rescan controls to avoid full chain replay when not needed.
  // If rescan=false, we skip. If rescan_start is provided, scan only from that height
  // on the first run; subsequent runs rely on wallet metadata.
  bool do_rescan = true;
  std::size_t rescan_start = 0;
  if (params.contains("rescan")) {
    try {
      do_rescan = params.at("rescan").get<bool>();
    } catch (...) {
      do_rescan = true;
    }
  }
  if (params.contains("rescan_start")) {
    try {
      const auto start = params.at("rescan_start").get<std::int64_t>();
      if (start > 0) {
        rescan_start = static_cast<std::size_t>(start);
      }
    } catch (...) {
      rescan_start = 0;
    }
  }
  if (do_rescan) {
    RescanWallet(rescan_start);
  }
  nlohmann::json result;
  result["status"] = "loaded";
  result["path"] = path;
  result["wallet_name"] =
      std::filesystem::path(path).parent_path().filename().string();
  return result;
}

nlohmann::json RpcServer::HandleBackupWallet(const nlohmann::json& params) {
  if (!params.contains("destination")) {
    throw std::runtime_error("destination parameter required");
  }
  auto& wallet = WalletOrThrow();
  const auto destination = params.at("destination").get<std::string>();
  if (!wallet.BackupTo(destination)) {
    throw std::runtime_error("failed to backup wallet");
  }
  nlohmann::json result;
  result["status"] = "ok";
  result["destination"] = destination;
  return result;
}

nlohmann::json RpcServer::HandleEncryptWallet(const nlohmann::json& params) {
  if (!params.contains("passphrase")) {
    throw std::runtime_error("passphrase parameter required");
  }
  auto& wallet = WalletOrThrow();
  const auto passphrase = params.at("passphrase").get<std::string>();
  if (passphrase.empty()) {
    throw std::runtime_error("passphrase cannot be empty");
  }
  if (!wallet.ChangePassphrase(passphrase)) {
    throw std::runtime_error("failed to encrypt wallet");
  }
  wallet.Lock();
  nlohmann::json result;
  result["status"] = "encrypted";
  result["locked"] = true;
  return result;
}

bool RpcServer::MineSingleBlock(const crypto::P2QHDescriptor& reward, std::string* hash_hex,
                                std::uint32_t* height, std::string* error) {
  node::BlockTemplate templ;
  std::string template_error;
  if (!node::BuildBlockTemplate(chain_, reward, &templ, &template_error)) {
    if (error) {
      *error = template_error.empty() ? "failed to build block template" : template_error;
    }
    return false;
  }

  FillBlockFromMempool(&templ.block, templ.height);

  const auto extra_offset_opt =
      qryptcoin::node::FindCoinbaseExtraNonceOffset(templ.block);
  if (!extra_offset_opt) {
    if (error) {
      *error = "template coinbase missing [height||extra_nonce] layout";
    }
    return false;
  }

  // Extra-nonce-aware mining: for each extra-nonce, embed it into the
  // coinbase, recompute the Merkle root, and scan the 32-bit header
  // nonce space before bumping the extra-nonce again.
  std::uint64_t extra_nonce = 0;
  auto last_time_check = std::chrono::steady_clock::now();
  while (true) {
    qryptcoin::node::SetCoinbaseExtraNonce(&templ.block, *extra_offset_opt,
                                           extra_nonce);
    templ.block.header.merkle_root =
        primitives::ComputeMerkleRoot(templ.block.transactions);
    templ.block.header.nonce = 0;

    while (true) {
      const auto now_steady = std::chrono::steady_clock::now();
      if (now_steady - last_time_check >= std::chrono::seconds(1)) {
        last_time_check = now_steady;
        const auto now_system = std::chrono::system_clock::now();
        const auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
                                  now_system.time_since_epoch())
                                  .count();
        const auto ts32 = static_cast<std::uint32_t>(now_secs);
        const auto current_ts32 =
            static_cast<std::uint32_t>(templ.block.header.timestamp);
        if (ts32 > current_ts32) {
          templ.block.header.timestamp = ts32;
        }
      }

      const auto hash = consensus::ComputeBlockHash(templ.block.header);
      if (consensus::HashMeetsTarget(hash, templ.target)) {
        std::string connect_error;
        if (!chain_.ConnectBlock(templ.block, &connect_error)) {
          if (error) {
            *error = connect_error;
          }
          return false;
        }
        if (hash_hex) {
          *hash_hex = HashToHex(hash);
        }
        if (height) {
          *height = templ.height;
        }
        IndexWalletOutputs(templ.block);
        AnnounceBlock(hash);
        RemoveMinedTransactions(templ.block, templ.height);
        return true;
      }

      if (templ.block.header.nonce == std::numeric_limits<std::uint32_t>::max()) {
        break;
      }
      ++templ.block.header.nonce;
    }

    ++extra_nonce;
  }
}

crypto::P2QHDescriptor RpcServer::DescriptorForAddress(const std::string& address) const {
  crypto::P2QHDescriptor descriptor{};
  const auto& cfg = config::GetNetworkConfig();
  if (!crypto::DecodeP2QHAddress(address, cfg.bech32_hrp, &descriptor)) {
    throw std::runtime_error("invalid P2QH address");
  }
  return descriptor;
}

crypto::P2QHDescriptor RpcServer::DefaultMiningRewardDescriptor(std::string* out_address) {
  if (!default_mining_address_.empty()) {
    if (out_address) {
      *out_address = default_mining_address_;
    }
    return DescriptorForAddress(default_mining_address_);
  }

  if (!WalletLoaded()) {
    throw std::runtime_error(
        "mining payout not configured; pass params.address, set --mining-address, or load a wallet");
  }

  const auto next_height = static_cast<std::uint32_t>(chain_.BlockCount());
  std::string tip_hash_hex;
  if (const auto* tip = chain_.Tip()) {
    tip_hash_hex = tip->hash_hex;
  }

  {
    std::lock_guard<std::mutex> lock(mining_reward_mutex_);
    if (mining_reward_cached_ && mining_reward_height_ == next_height &&
        mining_reward_tip_hash_ == tip_hash_hex) {
      if (out_address) {
        *out_address = mining_reward_address_;
      }
      return mining_reward_descriptor_;
    }
  }

  auto& wallet = WalletOrThrow();
  std::string address = wallet.NewAddress();
  auto descriptor = DescriptorForAddress(address);

  {
    std::lock_guard<std::mutex> lock(mining_reward_mutex_);
    mining_reward_cached_ = true;
    mining_reward_height_ = next_height;
    mining_reward_tip_hash_ = std::move(tip_hash_hex);
    mining_reward_address_ = address;
    mining_reward_descriptor_ = descriptor;
  }

  if (out_address) {
    *out_address = address;
  }
  return descriptor;
}

std::string RpcServer::DefaultMiningAddress() const {
  if (!default_mining_address_.empty()) {
    return default_mining_address_;
  }
  if (!WalletLoaded()) {
    return {};
  }
  const auto& wallet = WalletOrThrow();
  const auto addresses = wallet.ListAddresses();
  if (!addresses.empty()) {
    return addresses.front();
  }
  return {};
}

void RpcServer::IndexWalletOutputs(const primitives::CBlock& block, bool save_wallet) {
  if (!WalletLoaded()) {
    return;
  }
  auto& wallet = WalletOrThrow();
  bool changed = false;
  for (const auto& tx : block.transactions) {
    const bool is_coinbase = tx.IsCoinbase();
    auto txid = primitives::ComputeTxId(tx);
    for (std::size_t i = 0; i < tx.vout.size(); ++i) {
      if (wallet.MaybeTrackOutput(txid, i, tx.vout[i], is_coinbase)) {
        changed = true;
      }
    }
  }
  if (changed && save_wallet) {
    wallet.Save();
  }
}

void RpcServer::AnnounceBlock(const primitives::Hash256& hash) {
  if (peers_ == nullptr) {
    return;
  }
  net::messages::InventoryMessage inv;
  net::messages::InventoryVector vec;
  vec.type = net::messages::InventoryType::kBlock;
  std::copy(hash.begin(), hash.end(), vec.identifier.begin());
  inv.entries.push_back(vec);
  peers_->BroadcastInventory(inv);
}

void RpcServer::BroadcastTransaction(const primitives::CTransaction& tx) {
  if (sync_ != nullptr) {
    const auto txid = primitives::ComputeTxId(tx);
    const std::size_t announced = sync_->AnnounceTransaction(txid);
    std::cerr << "[relay] tx announced " << HashToHex(txid) << " peers=" << announced << "\n";
    return;
  }
  if (peers_ == nullptr) {
    return;
  }
  net::messages::InventoryMessage inv;
  net::messages::InventoryVector vec;
  vec.type = net::messages::InventoryType::kTransaction;
  const auto txid = primitives::ComputeTxId(tx);
  std::copy(txid.begin(), txid.end(), vec.identifier.begin());
  inv.entries.push_back(vec);
  peers_->BroadcastInventory(inv);
  std::cerr << "[relay] tx announced " << HashToHex(txid)
            << " peers=" << peers_->GetPeerInfos().size() << "\n";
}

void RpcServer::RescanWallet(std::size_t start_height, bool force_start_height) {
  auto& wallet = WalletOrThrow();
  const std::size_t blocks = chain_.BlockCount();
  if (blocks == 0) {
    return;
  }
  std::size_t effective_start = 0;
  if (force_start_height) {
    effective_start = start_height;
  } else if (auto last = wallet.LastScanHeight()) {
    effective_start = *last;
  } else if (auto birth = wallet.BirthHeight()) {
    effective_start = *birth;
  } else {
    effective_start = start_height;
  }
  if (effective_start >= blocks) {
    wallet.SetLastScanHeight(static_cast<std::uint32_t>(blocks));
    wallet.Save();
    return;
  }
  for (std::size_t height = effective_start; height < blocks; ++height) {
    const auto* record = chain_.GetByHeight(height);
    if (!record || !record->in_active_chain) {
      continue;
    }
    primitives::CBlock block;
    std::string read_error;
    if (!chain_.ReadBlock(*record, &block, &read_error)) {
      continue;
    }
    IndexWalletOutputs(block, /*save_wallet=*/false);
  }
  wallet.SetLastScanHeight(static_cast<std::uint32_t>(blocks));
  wallet.Save();
}

nlohmann::json RpcServer::HandleWalletLock(const nlohmann::json&) {
  auto& wallet = WalletOrThrow();
  wallet.Lock();
  nlohmann::json result;
  result["status"] = "locked";
  result["locked"] = true;
  return result;
}

nlohmann::json RpcServer::HandleWalletPassphrase(const nlohmann::json& params) {
  if (!params.contains("passphrase")) {
    throw std::runtime_error("passphrase parameter required");
  }
  auto& wallet = WalletOrThrow();
  const auto passphrase = params.at("passphrase").get<std::string>();
  if (passphrase.empty()) {
    throw std::runtime_error("passphrase cannot be empty");
  }
  if (!wallet.Unlock(passphrase)) {
    throw std::runtime_error("invalid passphrase");
  }
  nlohmann::json result;
  result["status"] = "unlocked";
  result["locked"] = false;
  return result;
}

bool RpcServer::AddToMempool(const primitives::CTransaction& tx,
                             std::optional<double> feerate_miks_per_vb_override,
                             std::string* reject_reason,
                             std::optional<std::uint64_t> time_first_seen_override) {
  if (reject_reason) {
    reject_reason->clear();
  }
  auto set_reject = [&](std::string reason) {
    if (reject_reason && reject_reason->empty()) {
      *reject_reason = std::move(reason);
    }
  };
  if (tx.IsCoinbase()) {
    set_reject("coinbase transaction");
    return false;
  }
  std::string policy_error;
  if (!policy::IsStandardTransaction(tx, &policy_error)) {
    // Non-standard transactions are not admitted to the local mempool
    // or relayed. This is a policy decision and does not affect
    // consensus validation.
    if (!policy_error.empty()) {
      set_reject("non-standard: " + policy_error);
    } else {
      set_reject("non-standard transaction");
    }
    return false;
  }
  std::vector<std::uint8_t> raw;
  primitives::serialize::SerializeTransaction(tx, &raw);
  const std::uint64_t size_bytes = static_cast<std::uint64_t>(raw.size());
  if (size_bytes == 0) {
    set_reject("empty transaction payload");
    return false;
  }
  if (size_bytes > kMaxMempoolTxBytes) {
    set_reject("transaction too large");
    return false;
  }
  const std::uint64_t vbytes = ComputeTransactionVBytes(tx);
  if (vbytes == 0) {
    set_reject("invalid transaction weight");
    return false;
  }
  // Guard against pathological transactions with duplicated inputs: these are
  // rejected by consensus, but we check here so mempool bookkeeping stays
  // simple and bounded.
  {
    std::unordered_set<primitives::COutPoint, OutPointHasher> seen;
    seen.reserve(tx.vin.size());
    for (const auto& in : tx.vin) {
      if (!seen.insert(in.prevout).second) {
        set_reject("duplicate input outpoint");
        return false;
      }
  }
  }
  const auto txid = primitives::ComputeTxId(tx);
  std::vector<primitives::Hash256> revealed_pubkeys;

  primitives::Amount fee_miks{0};
  double feerate_miks_per_vb = 0.0;
  if (feerate_miks_per_vb_override) {
    if (!std::isfinite(*feerate_miks_per_vb_override) ||
        *feerate_miks_per_vb_override <= 0.0) {
      set_reject("invalid feerate override");
      return false;
    }
    feerate_miks_per_vb = *feerate_miks_per_vb_override;
    const long double fee_needed =
        std::ceil(static_cast<long double>(feerate_miks_per_vb) *
                  static_cast<long double>(vbytes));
    if (!DoubleToMoney(static_cast<double>(fee_needed), &fee_miks)) {
      set_reject("fee computation overflow");
      return false;
    }
    std::string reveal_error;
    if (!ExtractRevealedPubkeyHashes(tx, &revealed_pubkeys, &reveal_error)) {
      set_reject(reveal_error.empty() ? "consensus: failed to parse key reveal"
                                      : ("consensus: " + reveal_error));
      return false;
    }
    const auto chain_revealed = chain_.SnapshotRevealedPubkeys();
    for (const auto& pk_hash : revealed_pubkeys) {
      if (chain_revealed.Contains(pk_hash)) {
        set_reject("consensus: public key already revealed");
        return false;
      }
    }
  } else {
    if (chain_.Tip() == nullptr) {
      set_reject("no active chain");
      return false;
    }
    const auto chain_height = chain_.Height();
    if (chain_height >= std::numeric_limits<std::uint32_t>::max() - 1) {
      set_reject("chain height overflow");
      return false;
    }
    const std::uint32_t spending_height =
        static_cast<std::uint32_t>(chain_height + 1);
    const std::uint64_t lock_time_cutoff_time = MedianTimePastTip(chain_);
    const auto chain_revealed = chain_.SnapshotRevealedPubkeys();

    consensus::UTXOSet input_view;
    input_view.Reserve(tx.vin.size());
    std::vector<primitives::COutPoint> missing_inputs;
    missing_inputs.reserve(tx.vin.size());
    for (const auto& in : tx.vin) {
      consensus::Coin coin;
      if (chain_.GetCoin(in.prevout, &coin)) {
        input_view.AddCoin(in.prevout, coin);
        continue;
      }
      missing_inputs.push_back(in.prevout);
    }

    if (!missing_inputs.empty()) {
      std::lock_guard<std::mutex> lock(mempool_mutex_);
      for (const auto& outpoint : missing_inputs) {
        auto it_parent = mempool_by_txid_.find(outpoint.txid);
        if (it_parent == mempool_by_txid_.end()) {
          set_reject("missing UTXO");
          return false;
        }
        const auto& parent_tx = it_parent->second.tx;
        if (outpoint.index >= parent_tx.vout.size()) {
          set_reject("missing UTXO");
          return false;
        }
        consensus::Coin coin;
        coin.out = parent_tx.vout[outpoint.index];
        coin.height = spending_height;
        coin.coinbase = false;
        input_view.AddCoin(outpoint, coin);
      }
    }

    std::string consensus_error;
    if (!consensus::ValidateTransaction(tx, input_view, chain_revealed, spending_height,
                                        lock_time_cutoff_time, &revealed_pubkeys,
                                        &consensus_error)) {
      if (consensus_error.empty()) {
        consensus_error = "consensus validation failed";
      }
      set_reject("consensus: " + consensus_error);
      return false;
    }

    if (!ComputeTransactionFee(tx, input_view, &fee_miks)) {
      set_reject("fee computation failed");
      return false;
    }

    feerate_miks_per_vb =
        static_cast<double>(fee_miks) / static_cast<double>(vbytes);
    if (!std::isfinite(feerate_miks_per_vb) || feerate_miks_per_vb < 0.0) {
      set_reject("invalid feerate");
      return false;
    }
  }

  std::lock_guard<std::mutex> lock(mempool_mutex_);
  if (!feerate_miks_per_vb_override) {
    // Ensure all referenced inputs exist either in the chain UTXO set or as
    // outputs of another mempool transaction. This prevents orphan entries if
    // a parent is replaced/evicted between validation and insertion.
    for (const auto& in : tx.vin) {
      consensus::Coin coin;
      if (chain_.GetCoin(in.prevout, &coin)) {
        continue;
      }
      auto it_parent = mempool_by_txid_.find(in.prevout.txid);
      if (it_parent == mempool_by_txid_.end()) {
        set_reject("missing UTXO");
        return false;
      }
      const auto& parent_tx = it_parent->second.tx;
      if (in.prevout.index >= parent_tx.vout.size()) {
        set_reject("missing UTXO");
        return false;
      }
    }
  }
  // Decay the floor slightly if the mempool has drained since the last tick.
  const double usage =
      mempool_limit_bytes_ == 0
          ? 0.0
          : static_cast<double>(mempool_bytes_) / static_cast<double>(mempool_limit_bytes_);
  if (usage < 0.25) {
    MaybeDecayMempoolMinFeeLocked();
  }
  const long double required_fee =
      static_cast<long double>(mempool_min_fee_miks_per_vb_) *
      static_cast<long double>(vbytes);
  if (static_cast<long double>(fee_miks) + 1e-9L < required_fee) {
    // Below the current relay floor; silently drop.
    std::ostringstream oss;
    oss << "min relay fee not met (fee=" << fee_miks << " required="
        << static_cast<std::uint64_t>(std::ceil(required_fee)) << ")";
    set_reject(oss.str());
    return false;
  }
  if (mempool_by_txid_.find(txid) != mempool_by_txid_.end()) {
    set_reject("already in mempool");
    return false;
  }

  // Opt-in Replace-By-Fee: allow a higher-fee transaction to replace a
  // bounded set of conflicting mempool entries when the originals
  // signal RBF via sequence numbers.
  std::vector<primitives::Hash256> conflict_txids;
  conflict_txids.reserve(std::min<std::size_t>(tx.vin.size(), kMaxRbfConflicts + 1));
  for (const auto& in_new : tx.vin) {
    auto it = mempool_spends_.find(in_new.prevout);
    if (it != mempool_spends_.end()) {
      conflict_txids.push_back(it->second);
    }
  }
  std::sort(conflict_txids.begin(), conflict_txids.end());
  conflict_txids.erase(std::unique(conflict_txids.begin(), conflict_txids.end()),
                       conflict_txids.end());
  if (conflict_txids.size() > kMaxRbfConflicts) {
    set_reject("too many conflicts");
    return false;
  }

  if (!conflict_txids.empty()) {
    primitives::Amount replaced_fees{0};
    double min_conflicting_feerate = std::numeric_limits<double>::max();
    for (const auto& conflict_txid : conflict_txids) {
      auto it = mempool_by_txid_.find(conflict_txid);
      if (it == mempool_by_txid_.end()) {
        continue;
      }
      const auto& conflicting = it->second;
      if (!policy::SignalsOptInRbf(conflicting.tx)) {
        set_reject("conflicting tx does not signal RBF");
        return false;
      }
      primitives::Amount next_replaced = 0;
      if (!primitives::CheckedAdd(replaced_fees, conflicting.fee_miks, &next_replaced)) {
        set_reject("rbf fee computation overflow");
        return false;
      }
      replaced_fees = next_replaced;
      if (conflicting.feerate_miks_per_vb < min_conflicting_feerate) {
        min_conflicting_feerate = conflicting.feerate_miks_per_vb;
      }
    }
    const double new_total_fee =
        static_cast<double>(fee_miks);
    const double old_total_fee =
        static_cast<double>(replaced_fees);
    if (new_total_fee <= old_total_fee * kRbfMinFeeBoost) {
      set_reject("rbf insufficient fee bump");
      return false;
    }
    if (feerate_miks_per_vb <= min_conflicting_feerate) {
      set_reject("rbf feerate too low");
      return false;
    }
    for (const auto& conflict_txid : conflict_txids) {
      RemoveFromMempoolWithDescendantsLocked(conflict_txid);
    }
  }

  for (const auto& pk_hash : revealed_pubkeys) {
    if (mempool_revealed_pubkeys_.find(pk_hash) != mempool_revealed_pubkeys_.end()) {
      set_reject("public key already revealed in mempool");
      return false;
    }
  }

  MempoolEntry entry;
  entry.tx = tx;
  entry.txid = txid;
  entry.size_bytes = size_bytes;
  entry.vbytes = vbytes;
  entry.fee_miks = fee_miks;
  entry.feerate_miks_per_vb = feerate_miks_per_vb;
  entry.feerate_q = QuantizeFeerate(feerate_miks_per_vb);
  const std::uint64_t feerate_q = entry.feerate_q;
  // Record the current height so that we can later estimate how many blocks
  // the transaction took to confirm.
  entry.entry_height = static_cast<std::uint32_t>(chain_.Height());
  entry.time_first_seen =
      time_first_seen_override.value_or(
          static_cast<std::uint64_t>(std::time(nullptr)));
  if (size_bytes > std::numeric_limits<std::uint64_t>::max() - mempool_bytes_) {
    set_reject("mempool size overflow");
    return false;
  }
  if (!mempool_by_txid_.emplace(txid, std::move(entry)).second) {
    set_reject("mempool insert failed");
    return false;
  }
  for (const auto& pk_hash : revealed_pubkeys) {
    mempool_revealed_pubkeys_.insert(pk_hash);
  }
  for (const auto& in : tx.vin) {
    mempool_spends_[in.prevout] = txid;
  }
  mempool_fee_index_.insert(FeeIndexKey{feerate_q, txid});
  mempool_bytes_ += size_bytes;
  mempool_dirty_.store(true, std::memory_order_relaxed);
  TrimMempoolIfNeededLocked();
  std::cerr << "[mempool] tx accepted " << HashToHex(txid)
            << " feerate_miks_per_vb=" << feerate_miks_per_vb
            << " fee_miks=" << fee_miks
            << " vbytes=" << vbytes
            << " bytes=" << size_bytes << "\n";
  return true;
}

void RpcServer::RemoveFromMempoolLocked(const primitives::Hash256& txid) {
  auto it = mempool_by_txid_.find(txid);
  if (it == mempool_by_txid_.end()) {
    return;
  }
  const auto& entry = it->second;

  std::vector<primitives::Hash256> revealed_pubkeys;
  ExtractRevealedPubkeyHashes(entry.tx, &revealed_pubkeys, nullptr);
  for (const auto& pk_hash : revealed_pubkeys) {
    mempool_revealed_pubkeys_.erase(pk_hash);
  }

  // Remove outpoint spend index entries owned by this transaction.
  for (const auto& in : entry.tx.vin) {
    auto sit = mempool_spends_.find(in.prevout);
    if (sit != mempool_spends_.end() && sit->second == txid) {
      mempool_spends_.erase(sit);
    }
  }

  mempool_fee_index_.erase(FeeIndexKey{entry.feerate_q, txid});
  if (entry.size_bytes <= mempool_bytes_) {
    mempool_bytes_ -= entry.size_bytes;
  }
  mempool_by_txid_.erase(it);
  mempool_dirty_.store(true, std::memory_order_relaxed);
}

void RpcServer::RemoveFromMempoolWithDescendantsLocked(const primitives::Hash256& txid) {
  // When evicting or replacing a mempool transaction, also evict any descendants
  // that spend its outputs so we don't retain orphaned entries.
  //
  // This is intentionally not used for mined transaction removal: once a parent
  // confirms, descendants may become valid against the chain tip.
  std::vector<primitives::Hash256> queue;
  queue.push_back(txid);
  std::unordered_set<primitives::Hash256, Hash256Hasher> seen;
  seen.insert(txid);

  for (std::size_t index = 0; index < queue.size(); ++index) {
    const auto current = queue[index];
    auto it = mempool_by_txid_.find(current);
    if (it == mempool_by_txid_.end()) {
      continue;
    }
    const auto& current_tx = it->second.tx;
    for (std::size_t vout = 0; vout < current_tx.vout.size(); ++vout) {
      primitives::COutPoint outpoint;
      outpoint.txid = current;
      outpoint.index = static_cast<std::uint32_t>(vout);
      auto spend_it = mempool_spends_.find(outpoint);
      if (spend_it == mempool_spends_.end()) {
        continue;
      }
      const auto& child_txid = spend_it->second;
      if (seen.insert(child_txid).second) {
        queue.push_back(child_txid);
      }
    }
  }

  for (const auto& victim : queue) {
    RemoveFromMempoolLocked(victim);
  }
}

bool RpcServer::HasMempoolTransaction(const primitives::Hash256& txid) const {
  std::lock_guard<std::mutex> lock(mempool_mutex_);
  return mempool_by_txid_.find(txid) != mempool_by_txid_.end();
}

bool RpcServer::GetMempoolTransactionBytes(const primitives::Hash256& txid,
                                           std::vector<std::uint8_t>* out) const {
  if (!out) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mempool_mutex_);
  auto it = mempool_by_txid_.find(txid);
  if (it == mempool_by_txid_.end()) {
    return false;
  }
  out->clear();
  primitives::serialize::SerializeTransaction(it->second.tx, out);
  return true;
}

bool RpcServer::SubmitTransactionFromNetwork(const primitives::CTransaction& tx,
                                             std::string* reject_reason) {
  if (reject_reason) {
    reject_reason->clear();
  }
  auto set_reject = [&](std::string reason) {
    if (reject_reason && reject_reason->empty()) {
      *reject_reason = std::move(reason);
    }
  };

  if (tx.IsCoinbase()) {
    set_reject("coinbase transaction");
    return false;
  }
  if (AddToMempool(tx, std::nullopt, reject_reason)) {
    // Re-announce to peers so that transactions discovered via one
    // connection propagate through the wider network.
    BroadcastTransaction(tx);
    return true;
  }
  return false;
}

void RpcServer::NotifyBlockConnected(const primitives::CBlock& block, std::uint32_t height) {
  IndexWalletOutputs(block);
  RemoveMinedTransactions(block, height);
}

void RpcServer::FillBlockFromMempool(primitives::CBlock* block, std::uint32_t height) {
  if (!block) return;
  constexpr std::size_t kMaxBlockBytes = 1'000'000;
  std::size_t current_size = SerializedBlockSize(*block);

  std::vector<MempoolEntry> snapshot;
  {
    std::lock_guard<std::mutex> lock(mempool_mutex_);
    snapshot.reserve(mempool_by_txid_.size());
    for (const auto& kv : mempool_by_txid_) {
      snapshot.push_back(kv.second);
    }
  }

  consensus::UTXOSet view = chain_.SnapshotUtxo();
  consensus::RevealedPubkeySet revealed_pubkeys = chain_.SnapshotRevealedPubkeys();
  primitives::Amount total_fees{0};
  const auto lock_time_cutoff_time = MedianTimePastTip(chain_);

  std::sort(snapshot.begin(), snapshot.end(),
            [](const MempoolEntry& a, const MempoolEntry& b) {
              if (a.feerate_q != b.feerate_q) {
                return a.feerate_q > b.feerate_q;
              }
              return a.txid < b.txid;
            });

  std::unordered_map<primitives::Hash256, std::size_t, Hash256Hasher> index_by_txid;
  index_by_txid.reserve(snapshot.size());
  for (std::size_t i = 0; i < snapshot.size(); ++i) {
    index_by_txid.emplace(snapshot[i].txid, i);
  }

  std::unordered_set<primitives::Hash256, Hash256Hasher> included_txids;
  included_txids.reserve(snapshot.size());

  auto build_package = [&](const primitives::Hash256& txid,
                           std::vector<const MempoolEntry*>* out) -> bool {
    if (!out) {
      return false;
    }
    out->clear();
    std::unordered_set<primitives::Hash256, Hash256Hasher> visiting;
    std::unordered_set<primitives::Hash256, Hash256Hasher> seen;

    std::function<bool(const primitives::Hash256&)> dfs =
        [&](const primitives::Hash256& current) -> bool {
      if (included_txids.find(current) != included_txids.end()) {
        return true;
      }
      if (!seen.insert(current).second) {
        return true;
      }
      if (!visiting.insert(current).second) {
        return false;
      }
      auto it = index_by_txid.find(current);
      if (it == index_by_txid.end()) {
        return false;
      }
      const auto& entry = snapshot[it->second];
      for (const auto& in : entry.tx.vin) {
        if (view.GetCoin(in.prevout) != nullptr) {
          continue;
        }
        auto pit = index_by_txid.find(in.prevout.txid);
        if (pit == index_by_txid.end()) {
          return false;
        }
        const auto& parent = snapshot[pit->second];
        if (in.prevout.index >= parent.tx.vout.size()) {
          return false;
        }
        if (!dfs(in.prevout.txid)) {
          return false;
        }
      }
      visiting.erase(current);
      out->push_back(&entry);
      return true;
    };

    return dfs(txid);
  };

  auto try_apply_package = [&](const std::vector<const MempoolEntry*>& package) {
    const std::size_t transactions_before = block->transactions.size();
    const std::size_t size_before = current_size;
    const primitives::Amount fees_before = total_fees;

    struct SpentCoin {
      primitives::COutPoint outpoint;
      consensus::Coin coin;
    };
    std::vector<SpentCoin> spent_coins;
    std::vector<primitives::COutPoint> added_outpoints;
    std::unordered_set<primitives::COutPoint, OutPointHasher> added_outpoint_set;
    std::vector<primitives::Hash256> newly_included;
    std::vector<primitives::Hash256> newly_revealed_pubkeys;

    auto rollback = [&]() {
      for (const auto& outpoint : added_outpoints) {
        view.SpendCoin(outpoint);
      }
      for (const auto& spent : spent_coins) {
        view.AddCoin(spent.outpoint, spent.coin);
      }
      for (const auto& pk_hash : newly_revealed_pubkeys) {
        revealed_pubkeys.Erase(pk_hash);
      }
      for (const auto& txid : newly_included) {
        included_txids.erase(txid);
      }
      block->transactions.resize(transactions_before);
      current_size = size_before;
      total_fees = fees_before;
    };

    for (const auto* entry_ptr : package) {
      if (!entry_ptr) {
        rollback();
        return false;
      }
      const auto& entry = *entry_ptr;
      if (included_txids.find(entry.txid) != included_txids.end()) {
        continue;
      }
      if (current_size + entry.size_bytes > kMaxBlockBytes) {
        rollback();
        return false;
      }
      std::string error;
      std::vector<primitives::Hash256> revealed_keys;
      if (!consensus::ValidateTransaction(entry.tx, view, revealed_pubkeys, height,
                                          lock_time_cutoff_time, &revealed_keys, &error)) {
        rollback();
        return false;
      }
      for (const auto& pk_hash : revealed_keys) {
        if (!revealed_pubkeys.Insert(pk_hash)) {
          rollback();
          return false;
        }
        newly_revealed_pubkeys.push_back(pk_hash);
      }
      primitives::Amount fee = 0;
      if (!ComputeTransactionFee(entry.tx, view, &fee)) {
        rollback();
        return false;
      }

      for (const auto& in : entry.tx.vin) {
        if (added_outpoint_set.find(in.prevout) != added_outpoint_set.end()) {
          continue;
        }
        const auto* coin = view.GetCoin(in.prevout);
        if (!coin) {
          rollback();
          return false;
        }
        spent_coins.push_back(SpentCoin{in.prevout, *coin});
      }
      for (const auto& in : entry.tx.vin) {
        view.SpendCoin(in.prevout);
      }
      for (std::size_t idx = 0; idx < entry.tx.vout.size(); ++idx) {
        primitives::COutPoint outpoint;
        outpoint.txid = entry.txid;
        outpoint.index = static_cast<std::uint32_t>(idx);
        consensus::Coin coin;
        coin.out = entry.tx.vout[idx];
        coin.height = height;
        coin.coinbase = false;
        view.AddCoin(outpoint, coin);
        added_outpoints.push_back(outpoint);
        added_outpoint_set.insert(outpoint);
      }

      block->transactions.push_back(entry.tx);
      current_size += entry.size_bytes;
      primitives::Amount next_total_fees = 0;
      if (!primitives::CheckedAdd(total_fees, fee, &next_total_fees)) {
        total_fees = primitives::kMaxMoney;
      } else {
        total_fees = next_total_fees;
      }
      included_txids.insert(entry.txid);
      newly_included.push_back(entry.txid);
    }
    return true;
  };

  for (const auto& entry : snapshot) {
    if (included_txids.find(entry.txid) != included_txids.end()) {
      continue;
    }
    std::vector<const MempoolEntry*> package;
    if (!build_package(entry.txid, &package)) {
      continue;
    }
    std::size_t package_bytes = 0;
    bool overflow = false;
    for (const auto* ptr : package) {
      if (!ptr) {
        overflow = true;
        break;
      }
      if (ptr->size_bytes > std::numeric_limits<std::size_t>::max() - package_bytes) {
        overflow = true;
        break;
      }
      package_bytes += static_cast<std::size_t>(ptr->size_bytes);
    }
    if (overflow) {
      continue;
    }
    if (current_size + package_bytes > kMaxBlockBytes) {
      continue;
    }
    (void)try_apply_package(package);
  }

  // Update the coinbase output to claim both the subsidy (set by the
  // block builder) and the total fees from included transactions.
  if (!block->transactions.empty() && !block->transactions.front().vout.empty()) {
    auto& coinbase = block->transactions.front();
    primitives::Amount updated = 0;
    if (primitives::CheckedAdd(coinbase.vout.front().value, total_fees, &updated)) {
      coinbase.vout.front().value = updated;
    }
    // Refresh the coinbase witness commitment now that the transaction set
    // is final. This ensures max-sized blocks remain relayable and prevents
    // witness malleability from producing "same header hash, different body"
    // blocks.
    if (!coinbase.vin.empty()) {
      auto& desc = coinbase.vin.front().unlocking_descriptor;
      std::size_t cursor = 0;
      std::uint64_t encoded_height = 0;
      std::uint64_t extra_nonce = 0;
      if (primitives::serialize::ReadVarInt(desc, &cursor, &encoded_height) &&
          encoded_height == static_cast<std::uint64_t>(height) &&
          primitives::serialize::ReadUint64(desc, &cursor, &extra_nonce)) {
        std::vector<std::uint8_t> rebuilt;
        primitives::serialize::WriteVarInt(&rebuilt, static_cast<std::uint64_t>(height));
        primitives::serialize::WriteUint64(&rebuilt, extra_nonce);
        rebuilt.insert(rebuilt.end(),
                       consensus::kWitnessCommitmentTag.begin(),
                       consensus::kWitnessCommitmentTag.end());
        const auto witness_root =
            primitives::ComputeWitnessMerkleRoot(block->transactions);
        rebuilt.insert(rebuilt.end(), witness_root.begin(), witness_root.end());
        desc = std::move(rebuilt);
      }
    }
    block->header.merkle_root =
        primitives::ComputeMerkleRoot(block->transactions);
  }
}

void RpcServer::RemoveMinedTransactions(const primitives::CBlock& block,
                                        std::uint32_t height) {
  if (block.transactions.size() <= 1) {
    return;
  }
  std::lock_guard<std::mutex> lock(mempool_mutex_);
  if (mempool_by_txid_.empty()) {
    return;
  }

  std::vector<primitives::Hash256> mined;
  mined.reserve(block.transactions.size() - 1);
  std::vector<primitives::Hash256> conflicts;
  conflicts.reserve(block.transactions.size());
  for (std::size_t i = 1; i < block.transactions.size(); ++i) {
    const auto& tx = block.transactions[i];
    const auto txid = primitives::ComputeTxId(tx);
    mined.push_back(txid);
    // Evict any conflicting mempool transactions (and their descendants) that
    // spend inputs already consumed by this block.
    for (const auto& in : tx.vin) {
      auto it = mempool_spends_.find(in.prevout);
      if (it != mempool_spends_.end() && it->second != txid) {
        conflicts.push_back(it->second);
      }
    }
  }

  for (const auto& txid : mined) {
    auto it = mempool_by_txid_.find(txid);
    if (it == mempool_by_txid_.end()) {
      continue;
    }
    const auto entry_height = it->second.entry_height;
    const auto feerate = it->second.feerate_miks_per_vb;
    if (height > entry_height) {
      const std::uint32_t conf =
          std::max<std::uint32_t>(1, height - entry_height);
      fee_estimator_.AddConfirmation(feerate, conf);
    }
    RemoveFromMempoolLocked(txid);
  }

  if (!conflicts.empty()) {
    std::sort(conflicts.begin(), conflicts.end());
    conflicts.erase(std::unique(conflicts.begin(), conflicts.end()), conflicts.end());
    for (const auto& txid : conflicts) {
      RemoveFromMempoolWithDescendantsLocked(txid);
    }
  }
  const double usage =
      mempool_limit_bytes_ == 0
          ? 0.0
          : static_cast<double>(mempool_bytes_) / static_cast<double>(mempool_limit_bytes_);
  if (usage < 0.25) {
    MaybeDecayMempoolMinFeeLocked();
  }
}

void RpcServer::TrimMempoolIfNeededLocked() {
  if (mempool_limit_bytes_ == 0) {
    return;
  }
  bool trimmed = false;

  while (mempool_bytes_ > mempool_limit_bytes_ && !mempool_fee_index_.empty()) {
    const auto victim = *mempool_fee_index_.begin();
    auto it = mempool_by_txid_.find(victim.txid);
    if (it == mempool_by_txid_.end()) {
      mempool_fee_index_.erase(mempool_fee_index_.begin());
      continue;
    }
    RemoveFromMempoolWithDescendantsLocked(victim.txid);
    trimmed = true;
  }
  if (trimmed && !mempool_fee_index_.empty()) {
    const auto lowest = *mempool_fee_index_.begin();
    const auto it = mempool_by_txid_.find(lowest.txid);
    if (it == mempool_by_txid_.end()) {
      return;
    }
    const double floor = it->second.feerate_miks_per_vb;
    // Never decrease the floor as a side-effect of eviction.
    if (floor > mempool_min_fee_miks_per_vb_) {
      mempool_min_fee_miks_per_vb_ = floor;
    }
  }
}

void RpcServer::MaybeDecayMempoolMinFeeLocked() {
  if (mempool_min_fee_miks_per_vb_ <= kMinRelayFeeMiksPerVb) {
    return;
  }
  // When the mempool is mostly empty, relax the floor gradually.
  const double usage =
      mempool_limit_bytes_ == 0
          ? 0.0
          : static_cast<double>(mempool_bytes_) / static_cast<double>(mempool_limit_bytes_);
  if (usage >= 0.25) {
    return;
  }
  mempool_min_fee_miks_per_vb_ *= 0.5;
  if (mempool_min_fee_miks_per_vb_ < kMinRelayFeeMiksPerVb) {
    mempool_min_fee_miks_per_vb_ = kMinRelayFeeMiksPerVb;
  }
}

void RpcServer::MempoolMaintenanceLoop(std::stop_token stop) {
  using clock = std::chrono::steady_clock;
  auto expiry_check_interval = std::chrono::seconds(60);
  if (mempool_expiry_.count() > 0) {
    auto seconds = mempool_expiry_.count() / 10;
    if (seconds < 5) {
      seconds = 5;
    } else if (seconds > 60) {
      seconds = 60;
    }
    expiry_check_interval = std::chrono::seconds(seconds);
  }
  auto next_expiry_check = clock::now() + expiry_check_interval;
  auto next_rebroadcast = clock::now() + mempool_rebroadcast_interval_;
  auto next_persist = clock::now() + mempool_persist_interval_;

  while (!stop.stop_requested()) {
    const auto now = clock::now();
    const auto now_seconds = static_cast<std::uint64_t>(std::time(nullptr));

    if (mempool_expiry_.count() > 0 && now >= next_expiry_check) {
      MaybeExpireMempool(now_seconds);
      next_expiry_check = now + expiry_check_interval;
    }

    if (mempool_rebroadcast_interval_.count() > 0 && now >= next_rebroadcast) {
      RebroadcastMempool();
      next_rebroadcast = now + mempool_rebroadcast_interval_;
    }

    if (!mempool_persist_path_.empty() && now >= next_persist) {
      const bool dirty = mempool_dirty_.exchange(false, std::memory_order_relaxed);
      if (dirty) {
        std::string error;
        if (!SaveMempoolToDisk(&error)) {
          mempool_dirty_.store(true, std::memory_order_relaxed);
          std::cerr << "[mempool] warn: failed to persist mempool: "
                    << (!error.empty() ? error : "unknown error") << "\n";
        }
      }
      next_persist = now + mempool_persist_interval_;
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

void RpcServer::MaybeExpireMempool(std::uint64_t now_seconds) {
  if (mempool_expiry_.count() <= 0) {
    return;
  }
  const auto expiry_seconds = static_cast<std::uint64_t>(mempool_expiry_.count());
  std::vector<primitives::Hash256> expired;
  {
    std::lock_guard<std::mutex> lock(mempool_mutex_);
    for (const auto& kv : mempool_by_txid_) {
      const auto first_seen = kv.second.time_first_seen;
      if (first_seen == 0) {
        continue;
      }
      if (now_seconds <= first_seen) {
        continue;
      }
      if (now_seconds - first_seen >= expiry_seconds) {
        expired.push_back(kv.first);
      }
    }
    if (!expired.empty()) {
      std::sort(expired.begin(), expired.end());
      expired.erase(std::unique(expired.begin(), expired.end()), expired.end());
      for (const auto& txid : expired) {
        RemoveFromMempoolWithDescendantsLocked(txid);
      }
    }
  }
  if (!expired.empty()) {
    std::cerr << "[mempool] expired " << expired.size() << " transactions\n";
  }
}

void RpcServer::RebroadcastMempool() {
  if (sync_ == nullptr || mempool_rebroadcast_interval_.count() <= 0) {
    return;
  }
  struct Candidate {
    std::uint64_t first_seen{0};
    primitives::Hash256 txid{};
  };
  std::vector<Candidate> candidates;
  {
    std::lock_guard<std::mutex> lock(mempool_mutex_);
    candidates.reserve(mempool_by_txid_.size());
    for (const auto& kv : mempool_by_txid_) {
      candidates.push_back(Candidate{kv.second.time_first_seen, kv.first});
    }
  }
  if (candidates.empty()) {
    return;
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const Candidate& a, const Candidate& b) {
              if (a.first_seen != b.first_seen) {
                return a.first_seen < b.first_seen;
              }
              return a.txid < b.txid;
            });
  std::size_t inv_sent = 0;
  for (const auto& c : candidates) {
    inv_sent += sync_->AnnounceTransaction(c.txid, /*force=*/true);
  }
  std::cerr << "[relay] rebroadcast txs=" << candidates.size()
            << " inv_sent=" << inv_sent << "\n";
}

bool RpcServer::LoadMempoolFromDisk(std::string* error) {
  if (error) {
    error->clear();
  }
  if (mempool_persist_path_.empty()) {
    if (error) {
      *error = "persistence disabled";
    }
    return false;
  }
  std::error_code ec;
  const auto path = std::filesystem::path(mempool_persist_path_);
  if (!std::filesystem::exists(path, ec)) {
    return true;
  }
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in) {
    if (error) {
      *error = "failed to open " + path.string();
    }
    return false;
  }
  std::string contents((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
  if (contents.empty()) {
    return true;
  }
  nlohmann::json root;
  try {
    root = nlohmann::json::parse(contents);
  } catch (const std::exception& ex) {
    if (error) {
      *error = std::string("invalid json: ") + ex.what();
    }
    return false;
  }
  if (!root.is_object() || !root.contains("version") || !root.contains("mempool")) {
    if (error) {
      *error = "unexpected file schema";
    }
    return false;
  }
  const auto version = root.at("version").get<int>();
  if (version != 1) {
    if (error) {
      *error = "unsupported version";
    }
    return false;
  }
  const auto& arr = root.at("mempool");
  if (!arr.is_array()) {
    if (error) {
      *error = "mempool field must be an array";
    }
    return false;
  }
  if (arr.size() > 200'000) {
    if (error) {
      *error = "mempool file too large";
    }
    return false;
  }
  std::size_t accepted = 0;
  std::size_t rejected = 0;
  const auto now_seconds = static_cast<std::uint64_t>(std::time(nullptr));
  for (const auto& item : arr) {
    if (!item.is_object() || !item.contains("tx_hex")) {
      ++rejected;
      continue;
    }
    const auto hex = item.at("tx_hex").get<std::string>();
    std::uint64_t first_seen = 0;
    if (item.contains("time_first_seen")) {
      first_seen = item.at("time_first_seen").get<std::uint64_t>();
    }
    if (first_seen > now_seconds) {
      first_seen = now_seconds;
    }
    std::vector<std::uint8_t> raw;
    if (!util::HexDecode(hex, &raw)) {
      ++rejected;
      continue;
    }
    primitives::CTransaction tx;
    std::size_t offset = 0;
    if (!primitives::serialize::DeserializeTransaction(raw, &offset, &tx,
                                                       /*expect_witness=*/true) ||
        offset != raw.size()) {
      ++rejected;
      continue;
    }
    std::string reject_reason;
    if (AddToMempool(tx, std::nullopt, &reject_reason, first_seen)) {
      ++accepted;
    } else {
      ++rejected;
    }
  }

  if (rejected == 0) {
    mempool_dirty_.store(false, std::memory_order_relaxed);
  }
  if (accepted > 0 || rejected > 0) {
    std::cerr << "[mempool] loaded persisted entries accepted=" << accepted
              << " rejected=" << rejected << "\n";
  }
  return true;
}

bool RpcServer::SaveMempoolToDisk(std::string* error) {
  if (error) {
    error->clear();
  }
  if (mempool_persist_path_.empty()) {
    if (error) {
      *error = "persistence disabled";
    }
    return false;
  }

  std::vector<MempoolEntry> snapshot;
  {
    std::lock_guard<std::mutex> lock(mempool_mutex_);
    snapshot.reserve(mempool_by_txid_.size());
    for (const auto& kv : mempool_by_txid_) {
      snapshot.push_back(kv.second);
    }
  }
  std::sort(snapshot.begin(), snapshot.end(),
            [](const MempoolEntry& a, const MempoolEntry& b) {
              return a.txid < b.txid;
            });

  nlohmann::json root;
  root["version"] = 1;
  nlohmann::json arr = nlohmann::json::array();
  for (const auto& entry : snapshot) {
    nlohmann::json item;
    item["txid"] = HashToHex(entry.txid);
    item["time_first_seen"] = entry.time_first_seen;
    item["entry_height"] = entry.entry_height;
    item["tx_hex"] = SerializeTransactionHex(entry.tx);
    arr.push_back(std::move(item));
  }
  root["mempool"] = std::move(arr);

  const auto path = std::filesystem::path(mempool_persist_path_);
  std::error_code ec_create;
  if (!path.parent_path().empty()) {
    std::filesystem::create_directories(path.parent_path(), ec_create);
  }

  const auto tmp = path.string() + ".tmp";
  std::ofstream out(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
  if (!out) {
    if (error) {
      *error = "failed to write " + tmp;
    }
    return false;
  }
  out << root.dump();
  out << "\n";
  out.close();
  if (!out) {
    if (error) {
      *error = "failed to flush " + tmp;
    }
    return false;
  }

  std::error_code ec;
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    std::filesystem::remove(path, ec);
    ec.clear();
    std::filesystem::rename(tmp, path, ec);
  }
  if (ec) {
    if (error) {
      *error = "failed to replace mempool file: " + ec.message();
    }
    return false;
  }
  return true;
}

}  // namespace qryptcoin::rpc
