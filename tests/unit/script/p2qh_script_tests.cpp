#include <array>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "consensus/monetary.hpp"
#include "consensus/sighash.hpp"
#include "consensus/tx_validator.hpp"
#include "consensus/utxo.hpp"
#include "crypto/hash.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/pq_engine.hpp"
#include "primitives/amount.hpp"
#include "script/p2qh.hpp"
#include "tests/unit/util/deterministic_rng.hpp"

namespace {

using qryptcoin::test::ScopedDeterministicRng;

std::vector<std::uint8_t> Sha3Bytes(std::string_view str) {
  const auto hash = qryptcoin::crypto::Sha3_256(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(str.data()), str.size()));
  return {hash.begin(), hash.end()};
}

struct TestContext {
  qryptcoin::crypto::QPqDilithiumKey dilithium;
  qryptcoin::crypto::P2QHDescriptor descriptor;
  std::vector<std::uint8_t> reveal;
  qryptcoin::script::ScriptPubKey script;
};

TestContext BuildDilithiumContext() {
  TestContext ctx{
      .dilithium = qryptcoin::crypto::QPqDilithiumKey::Generate(),
  };
  ctx.reveal = qryptcoin::crypto::BuildP2QHReveal(ctx.dilithium.PublicKey());
  ctx.descriptor = qryptcoin::crypto::DescriptorFromReveal(ctx.reveal);
  ctx.script = qryptcoin::script::CreateP2QHScript(ctx.descriptor);
  return ctx;
}

qryptcoin::primitives::CTransaction BuildSpendTransaction(
    const qryptcoin::primitives::COutPoint& prevout, const std::vector<std::uint8_t>& reveal,
    const std::vector<std::uint8_t>& dilithium_sig) {
  using qryptcoin::primitives::CTxIn;
  using qryptcoin::primitives::CTxOut;
  using qryptcoin::primitives::CTransaction;
  using qryptcoin::primitives::WitnessStackItem;
  CTransaction tx;
  tx.vin.resize(1);
  tx.vin[0].prevout = prevout;
  WitnessStackItem reveal_item{reveal};
  WitnessStackItem dilithium_item{dilithium_sig};
  tx.vin[0].witness_stack = {reveal_item, dilithium_item};
  tx.vout.resize(1);
  tx.vout[0].value = 5 * qryptcoin::primitives::kMiksPerQRY;
  tx.vout[0].locking_descriptor.clear();
  return tx;
}

bool TestDilithiumPipeline() {
  ScopedDeterministicRng rng(0x1111'2222ULL);
  auto ctx = BuildDilithiumContext();

  qryptcoin::consensus::UTXOSet view;
  qryptcoin::primitives::COutPoint prevout{};
  prevout.txid.fill(0xAB);
  prevout.index = 0;

  qryptcoin::consensus::Coin coin;
  coin.out.value = 10 * qryptcoin::primitives::kMiksPerQRY;
  coin.out.locking_descriptor = ctx.script.data;
  view.AddCoin(prevout, coin);

  qryptcoin::primitives::CTransaction tx;
  tx.version = 2;
  tx.vin.resize(1);
  tx.vin[0].prevout = prevout;
  tx.vout.resize(1);
  tx.vout[0].value = 5 * qryptcoin::primitives::kMiksPerQRY;
  tx.vout[0].locking_descriptor = ctx.script.data;

  const auto sighash = qryptcoin::consensus::ComputeSighash(tx, 0, coin);
  auto dilithium_sig =
      ctx.dilithium.Sign(std::span<const std::uint8_t>(sighash.data(), sighash.size()));

  qryptcoin::primitives::WitnessStackItem reveal_item{ctx.reveal};
  qryptcoin::primitives::WitnessStackItem dilithium_item{dilithium_sig};
  tx.vin[0].witness_stack = {reveal_item, dilithium_item};

  qryptcoin::consensus::RevealedPubkeySet revealed_pubkeys;
  std::string error;
  if (!qryptcoin::consensus::ValidateTransaction(
          tx, view, revealed_pubkeys, qryptcoin::consensus::kCoinbaseMaturity,
          /*lock_time_cutoff_time=*/0, nullptr, &error)) {
    std::cerr << "Dilithium validation failed: " << error << "\n";
    return false;
  }
  return true;
}

bool TestCoinbaseMaturity() {
  ScopedDeterministicRng rng(0x55556666ULL);
  auto ctx = BuildDilithiumContext();

  qryptcoin::consensus::UTXOSet view;
  qryptcoin::primitives::COutPoint prevout{};
  prevout.txid.fill(0x33);
  prevout.index = 2;

  qryptcoin::consensus::Coin coin;
  coin.out.value = 8 * qryptcoin::primitives::kMiksPerQRY;
  coin.out.locking_descriptor = ctx.script.data;
  coin.coinbase = true;
  coin.height = 10;
  view.AddCoin(prevout, coin);

  qryptcoin::primitives::CTransaction tx;
  tx.version = 2;
  tx.vin.resize(1);
  tx.vin[0].prevout = prevout;
  tx.vout.resize(1);
  tx.vout[0].value = 4 * qryptcoin::primitives::kMiksPerQRY;
  tx.vout[0].locking_descriptor = ctx.script.data;

  const auto sighash = qryptcoin::consensus::ComputeSighash(tx, 0, coin);
  auto dilithium_sig =
      ctx.dilithium.Sign(std::span<const std::uint8_t>(sighash.data(), sighash.size()));

  qryptcoin::primitives::WitnessStackItem reveal_item{ctx.reveal};
  qryptcoin::primitives::WitnessStackItem dilithium_item{dilithium_sig};
  tx.vin[0].witness_stack = {reveal_item, dilithium_item};

  const std::uint32_t immature_height =
      coin.height + qryptcoin::consensus::kCoinbaseMaturity - 1;
  qryptcoin::consensus::RevealedPubkeySet revealed_pubkeys;
  if (qryptcoin::consensus::ValidateTransaction(tx, view, revealed_pubkeys, immature_height,
                                               /*lock_time_cutoff_time=*/0, nullptr, nullptr)) {
    std::cerr << "Expected immature coinbase spend to fail\n";
    return false;
  }
  const std::uint32_t mature_height =
      coin.height + qryptcoin::consensus::kCoinbaseMaturity;
  std::string error;
  if (!qryptcoin::consensus::ValidateTransaction(tx, view, revealed_pubkeys, mature_height,
                                                /*lock_time_cutoff_time=*/0, nullptr, &error)) {
    std::cerr << "Coinbase maturity validation failed: " << error << "\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  if (!TestDilithiumPipeline()) {
    return EXIT_FAILURE;
  }
  if (!TestCoinbaseMaturity()) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
