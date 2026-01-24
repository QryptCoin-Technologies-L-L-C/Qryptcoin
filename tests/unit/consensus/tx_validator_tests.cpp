#include <cstdlib>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <vector>

#include "consensus/monetary.hpp"
#include "consensus/sighash.hpp"
#include "consensus/tx_validator.hpp"
#include "consensus/utxo.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/pq_engine.hpp"
#include "primitives/amount.hpp"
#include "primitives/transaction.hpp"
#include "script/p2qh.hpp"
#include "tests/unit/util/deterministic_rng.hpp"

using namespace qryptcoin;

namespace {

using qryptcoin::test::ScopedDeterministicRng;

struct TestContext {
  crypto::QPqDilithiumKey dilithium;
  crypto::P2QHDescriptor descriptor;
  std::vector<std::uint8_t> reveal;
  script::ScriptPubKey script;
};

TestContext BuildDilithiumContext() {
  TestContext ctx{
      .dilithium = crypto::QPqDilithiumKey::Generate(),
  };
  ctx.reveal = crypto::BuildP2QHReveal(ctx.dilithium.PublicKey());
  ctx.descriptor = crypto::DescriptorFromReveal(ctx.reveal);
  ctx.script = script::CreateP2QHScript(ctx.descriptor);
  return ctx;
}

bool SignSpend(const TestContext& ctx, const consensus::Coin& coin, primitives::CTransaction* tx) {
  if (!tx || tx->vin.empty()) return false;
  const auto sighash = consensus::ComputeSighash(*tx, 0, coin);
  auto dilithium_sig =
      ctx.dilithium.Sign(std::span<const std::uint8_t>(sighash.data(), sighash.size()));

  primitives::WitnessStackItem reveal_item{ctx.reveal};
  primitives::WitnessStackItem dilithium_item{dilithium_sig};
  tx->vin[0].witness_stack = {reveal_item, dilithium_item};
  return true;
}

bool BuildSignedSpend(const TestContext& ctx, consensus::UTXOSet* view,
                      primitives::CTransaction* tx_out, consensus::Coin* coin_out = nullptr) {
  if (!view || !tx_out) return false;

  consensus::Coin coin;
  coin.out.value = 10 * primitives::kMiksPerQRY;
  coin.out.locking_descriptor = ctx.script.data;
  coin.coinbase = false;
  coin.height = 5;

  primitives::COutPoint prevout{};
  prevout.txid.fill(0x42);
  prevout.index = 0;
  view->AddCoin(prevout, coin);

  primitives::CTransaction tx;
  tx.version = 2;
  tx.lock_time = 0;
  tx.vin.resize(1);
  tx.vin[0].prevout = prevout;
  tx.vout.resize(1);
  tx.vout[0].value = 5 * primitives::kMiksPerQRY;
  tx.vout[0].locking_descriptor = ctx.script.data;

  if (!SignSpend(ctx, coin, &tx)) {
    return false;
  }

  *tx_out = std::move(tx);
  if (coin_out) {
    *coin_out = coin;
  }
  return true;
}

bool TestNonFinalLockTime() {
  ScopedDeterministicRng rng(0xABCD1234ULL);
  auto ctx = BuildDilithiumContext();
  consensus::UTXOSet view;
  primitives::CTransaction tx;
  if (!BuildSignedSpend(ctx, &view, &tx)) {
    std::cerr << "Failed to build signed spend\n";
    return false;
  }

  // Make the transaction non-final by setting a height-based lock_time
  // that is equal to the spending height. Because at least one input
  // has a non-final sequence (see below), this should be rejected.
  tx.lock_time = 100;
  tx.vin[0].sequence = 0xFFFFFFFEu;  // opt in to locktime
  const std::uint32_t spending_height = 100;
  const std::uint64_t lock_time_cutoff_time = 0;  // unused for height-based locks

  consensus::RevealedPubkeySet revealed_pubkeys;
  std::string error;
  if (consensus::ValidateTransaction(tx, view, revealed_pubkeys, spending_height,
                                     lock_time_cutoff_time, nullptr, &error)) {
    std::cerr << "Expected non-final locktime transaction to fail\n";
    return false;
  }
  if (error.find("non-final") == std::string::npos) {
    std::cerr << "Unexpected error for non-final locktime test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestDuplicateInputs() {
  ScopedDeterministicRng rng(0xDEADBEEFULL);
  auto ctx = BuildDilithiumContext();
  consensus::UTXOSet view;
  primitives::CTransaction base;
  if (!BuildSignedSpend(ctx, &view, &base)) {
    std::cerr << "Failed to build signed spend for duplicate-input test\n";
    return false;
  }

  primitives::CTransaction tx = base;
  // Duplicate the single input so that vin[0] and vin[1] reference the
  // same outpoint with identical witness data.
  tx.vin.push_back(tx.vin[0]);

  const std::uint32_t spending_height = 200;
  const std::uint64_t lock_time_cutoff_time = 0;
  consensus::RevealedPubkeySet revealed_pubkeys;
  std::string error;
  if (consensus::ValidateTransaction(tx, view, revealed_pubkeys, spending_height,
                                     lock_time_cutoff_time, nullptr, &error)) {
    std::cerr << "Expected duplicate-input transaction to fail\n";
    return false;
  }
  if (error.find("duplicate inputs") == std::string::npos) {
    std::cerr << "Unexpected error for duplicate-input test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestOutputValueOutOfRange() {
  ScopedDeterministicRng rng(0x99999999ULL);
  auto ctx = BuildDilithiumContext();
  consensus::UTXOSet view;
  primitives::CTransaction tx;
  consensus::Coin coin;
  if (!BuildSignedSpend(ctx, &view, &tx, &coin)) {
    std::cerr << "Failed to build signed spend for output-range test\n";
    return false;
  }

  tx.vout[0].value = primitives::kMaxMoney + 1;
  if (!SignSpend(ctx, coin, &tx)) {
    std::cerr << "Failed to resign spend for output-range test\n";
    return false;
  }

  std::string error;
  consensus::RevealedPubkeySet revealed_pubkeys;
  if (consensus::ValidateTransaction(tx, view, revealed_pubkeys, /*spending_height=*/10,
                                     /*lock_time_cutoff_time=*/0, nullptr, &error)) {
    std::cerr << "Expected output value out-of-range tx to fail\n";
    return false;
  }
  if (error.find("output value out of range") == std::string::npos) {
    std::cerr << "Unexpected error for output-range test: " << error << "\n";
    return false;
  }
  return true;
}

bool TestOutputTotalOutOfRange() {
  ScopedDeterministicRng rng(0x88888888ULL);
  auto ctx = BuildDilithiumContext();
  consensus::UTXOSet view;
  primitives::CTransaction tx;
  consensus::Coin coin;
  if (!BuildSignedSpend(ctx, &view, &tx, &coin)) {
    std::cerr << "Failed to build signed spend for output-sum-range test\n";
    return false;
  }

  tx.vout.resize(2);
  tx.vout[0].value = primitives::kMaxMoney;
  tx.vout[0].locking_descriptor = ctx.script.data;
  tx.vout[1].value = 1;
  tx.vout[1].locking_descriptor = ctx.script.data;
  if (!SignSpend(ctx, coin, &tx)) {
    std::cerr << "Failed to resign spend for output-sum-range test\n";
    return false;
  }

  std::string error;
  consensus::RevealedPubkeySet revealed_pubkeys;
  if (consensus::ValidateTransaction(tx, view, revealed_pubkeys, /*spending_height=*/10,
                                     /*lock_time_cutoff_time=*/0, nullptr, &error)) {
    std::cerr << "Expected output total out-of-range tx to fail\n";
    return false;
  }
  if (error.find("output total out of range") == std::string::npos) {
    std::cerr << "Unexpected error for output-sum-range test: " << error << "\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  if (!TestNonFinalLockTime()) {
    return EXIT_FAILURE;
  }
  if (!TestDuplicateInputs()) {
    return EXIT_FAILURE;
  }
  if (!TestOutputValueOutOfRange()) {
    return EXIT_FAILURE;
  }
  if (!TestOutputTotalOutOfRange()) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
