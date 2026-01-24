#include <array>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "consensus/sighash.hpp"
#include "crypto/hash.hpp"
#include "primitives/transaction.hpp"

namespace {

std::string BytesToHex(std::span<const std::uint8_t> data) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto byte : data) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

std::span<const std::uint8_t> BytesFromString(std::string_view view) {
  return {reinterpret_cast<const std::uint8_t*>(view.data()), view.size()};
}

#ifdef _WIN32
bool ShouldUpdateVectors() {
  char* buffer = nullptr;
  size_t len = 0;
  if (_dupenv_s(&buffer, &len, "QRY_UPDATE_SIGHASH") == 0 && buffer != nullptr) {
    free(buffer);
    return true;
  }
  if (buffer != nullptr) {
    free(buffer);
  }
  return false;
}
#else
bool ShouldUpdateVectors() {
  return std::getenv("QRY_UPDATE_SIGHASH") != nullptr;
}
#endif

qryptcoin::primitives::CTxOut MakeP2QHOutput(std::string_view tag, qryptcoin::primitives::Amount value) {
  qryptcoin::primitives::CTxOut out;
  out.value = value;
  auto program = qryptcoin::crypto::Sha3_256(BytesFromString(tag));
  out.locking_descriptor.push_back(0x51);  // OP_1
  out.locking_descriptor.push_back(0x20);  // push 32 bytes
  out.locking_descriptor.insert(out.locking_descriptor.end(), program.begin(), program.end());
  return out;
}

qryptcoin::primitives::CTransaction BuildTransaction() {
  using qryptcoin::primitives::CTransaction;
  using qryptcoin::primitives::CTxIn;
  using qryptcoin::primitives::CTxOut;
  CTransaction tx;
  tx.version = 3;
  tx.lock_time = 0x01020304;
  tx.vin.resize(2);
  tx.vout.resize(2);

  auto& in0 = tx.vin[0];
  in0.prevout.txid.fill(0x11);
  in0.prevout.index = 1;
  in0.sequence = 0xFFFFFFFE;

  auto& in1 = tx.vin[1];
  in1.prevout.txid.fill(0x22);
  in1.prevout.txid[0] = 0xAB;
  in1.prevout.index = 7;
  in1.sequence = 0xFFFFFFFD;

  tx.vout[0] = MakeP2QHOutput("tx-output-0", 7 * qryptcoin::primitives::kMiksPerQRY);
  tx.vout[1] = MakeP2QHOutput("tx-output-1", 13 * qryptcoin::primitives::kMiksPerQRY);
  return tx;
}

std::array<std::uint8_t, 32> ComputeHashForInput(const qryptcoin::primitives::CTransaction& tx,
                                                 std::size_t index, const qryptcoin::consensus::Coin& coin) {
  return qryptcoin::consensus::ComputeSighash(tx, index, coin);
}

constexpr std::string_view kSighashInput0 = "38d059e0657c1f853aa531ea26cdea4d3dd418ac0a8cf07b6e3733b9bcdb9693";
constexpr std::string_view kSighashInput1 = "484cd5c15b81acc86795add43aa354940226f0f61b2b3d2eec8f62da3ea64619";

}  // namespace

int main() {
  using qryptcoin::consensus::Coin;
  auto tx = BuildTransaction();

  Coin coin0;
  coin0.out = MakeP2QHOutput("utxo-0", 12 * qryptcoin::primitives::kMiksPerQRY);
  Coin coin1;
  coin1.out = MakeP2QHOutput("utxo-1", 21 * qryptcoin::primitives::kMiksPerQRY);

  const auto hash0 = ComputeHashForInput(tx, 0, coin0);
  const auto hash1 = ComputeHashForInput(tx, 1, coin1);

  if (ShouldUpdateVectors()) {
    std::cout << "input0=" << BytesToHex(hash0) << "\n";
    std::cout << "input1=" << BytesToHex(hash1) << "\n";
    return EXIT_SUCCESS;
  }

  if (BytesToHex(hash0) != kSighashInput0) {
    std::cerr << "Sighash input 0 mismatch\n";
    return EXIT_FAILURE;
  }
  if (BytesToHex(hash1) != kSighashInput1) {
    std::cerr << "Sighash input 1 mismatch\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
