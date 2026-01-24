#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

#include "crypto/deterministic_rng.hpp"
#include "crypto/pq_engine.hpp"
#include "wallet/hd_wallet.hpp"

namespace {

bool TestKyberUnaffectedByWalletDeterministicRng() {
  using namespace qryptcoin;

  std::array<std::uint8_t, 32> seed{};
  std::memcpy(seed.data(), "WALLET-RNG-SEED", 15);

  std::vector<std::uint8_t> pk1;
  std::vector<std::uint8_t> pk2;
  {
    crypto::DeterministicOqsRng rng(seed);
    auto k1 = crypto::QPqKyberKEM::Generate();
    pk1.assign(k1.PublicKey().begin(), k1.PublicKey().end());
  }
  {
    crypto::DeterministicOqsRng rng(seed);
    auto k2 = crypto::QPqKyberKEM::Generate();
    pk2.assign(k2.PublicKey().begin(), k2.PublicKey().end());
  }

  if (pk1 == pk2) {
    std::cerr << "Kyber keypairs repeated while deterministic wallet RNG was active\n";
    return false;
  }
  return true;
}

bool TestConcurrentWalletDerivationAndKyber() {
  using namespace qryptcoin;

  std::array<std::uint8_t, 32> wallet_seed{};
  wallet_seed.fill(0x42);
  auto wallet = wallet::HDWallet::FromSeedForTools(wallet_seed, crypto::SignatureAlgorithm::kDilithium);
  if (!wallet) {
    std::cerr << "Failed to create in-memory wallet\n";
    return false;
  }

  const auto baseline = wallet->DeriveAddressForTools(0, crypto::SignatureAlgorithm::kDilithium);
  std::atomic<bool> wallet_ok{true};
  std::vector<std::vector<std::uint8_t>> kyber_pubkeys;

  std::thread wallet_thread([&]() {
    for (int i = 0; i < 200; ++i) {
      const auto derived = wallet->DeriveAddressForTools(0, crypto::SignatureAlgorithm::kDilithium);
      if (derived != baseline) {
        wallet_ok.store(false);
        break;
      }
    }
  });

  std::thread kyber_thread([&]() {
    kyber_pubkeys.reserve(16);
    for (int i = 0; i < 16; ++i) {
      auto k = crypto::QPqKyberKEM::Generate();
      kyber_pubkeys.emplace_back(k.PublicKey().begin(), k.PublicKey().end());
    }
  });

  wallet_thread.join();
  kyber_thread.join();

  if (!wallet_ok.load()) {
    std::cerr << "Wallet derivation became non-deterministic under concurrent PQ operations\n";
    return false;
  }
  if (kyber_pubkeys.size() < 2) {
    std::cerr << "Kyber concurrency test did not generate enough keys\n";
    return false;
  }
  if (std::all_of(kyber_pubkeys.begin() + 1, kyber_pubkeys.end(),
                  [&](const std::vector<std::uint8_t>& pk) { return pk == kyber_pubkeys.front(); })) {
    std::cerr << "Kyber public keys unexpectedly identical under concurrency\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  if (!TestKyberUnaffectedByWalletDeterministicRng()) {
    return EXIT_FAILURE;
  }
  if (!TestConcurrentWalletDerivationAndKyber()) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

