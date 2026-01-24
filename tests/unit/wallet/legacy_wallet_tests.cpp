#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "config/network.hpp"
#include "crypto/deterministic_rng.hpp"
#include "crypto/hash.hpp"
#include "crypto/p2qh_address.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/pq_engine.hpp"
#include "primitives/serialize.hpp"
#include "util/aead.hpp"
#include "util/argon2_kdf.hpp"
#include "wallet/hd_wallet.hpp"

namespace {

constexpr std::uint32_t kWalletMagic = 0x51574C54;  // 'QTLT'
constexpr std::uint16_t kLegacyWalletVersion = 4;

std::vector<std::uint8_t> BuildSeedLabel(const std::array<std::uint8_t, 32>& seed,
                                         std::uint32_t index,
                                         std::string_view context) {
  using qryptcoin::primitives::serialize::WriteUint32;

  std::vector<std::uint8_t> buffer(seed.begin(), seed.end());
  WriteUint32(&buffer, index);
  buffer.insert(buffer.end(), context.begin(), context.end());
  return qryptcoin::crypto::Sha3_256Vector(buffer);
}

std::string DeriveLegacyDilithiumAddress(const std::array<std::uint8_t, 32>& seed,
                                        std::uint32_t index) {
  using namespace qryptcoin;

  auto dil_label = BuildSeedLabel(seed, index, "DILITHIUM");
  crypto::DeterministicOqsRng rng(
      std::span<const std::uint8_t>(dil_label.data(), dil_label.size()),
      crypto::DeterministicOqsRng::Mode::kLegacyMt19937);
  const auto key = crypto::QPqDilithiumKey::Generate();
  const auto pub = key.PublicKey();

  const auto reveal = crypto::BuildP2QHReveal(pub);
  const auto descriptor = crypto::DescriptorFromReveal(reveal);
  return crypto::EncodeP2QHAddress(descriptor, config::GetNetworkConfig().bech32_hrp);
}

std::vector<std::uint8_t> SerializeLegacyWalletPayload(std::span<const std::uint8_t> seed,
                                                       std::uint32_t next_index,
                                                       const std::string& addr0) {
  using namespace qryptcoin;
  std::vector<std::uint8_t> payload;

  payload.insert(payload.end(), seed.begin(), seed.end());
  primitives::serialize::WriteUint32(&payload, next_index);
  payload.push_back(crypto::EncodeSignatureAlgorithm(crypto::SignatureAlgorithm::kDilithium));

  primitives::serialize::WriteVarIntLegacy(&payload, 1);  // address count
  primitives::serialize::WriteUint32(&payload, 0);        // index
  payload.push_back(crypto::EncodeSignatureAlgorithm(crypto::SignatureAlgorithm::kDilithium));
  primitives::serialize::WriteVarIntLegacy(&payload, addr0.size());
  payload.insert(payload.end(), addr0.begin(), addr0.end());

  // Include a single UTXO with a script length > 0xFD so legacy varint encoding
  // uses the buggy 0xFD + 4-byte branch. This ensures Save() preserves legacy
  // encoding for v4 wallets.
  primitives::serialize::WriteVarIntLegacy(&payload, 1);  // utxo count
  std::array<std::uint8_t, 32> txid{};
  txid.fill(0x11);
  payload.insert(payload.end(), txid.begin(), txid.end());
  primitives::serialize::WriteUint32(&payload, 0);     // vout index
  primitives::serialize::WriteUint64(&payload, 1000);  // value

  const std::size_t script_len = 300;
  primitives::serialize::WriteVarIntLegacy(&payload, script_len);
  payload.insert(payload.end(), script_len, 0x00);
  primitives::serialize::WriteUint32(&payload, 0);  // key_index
  payload.push_back(crypto::EncodeSignatureAlgorithm(crypto::SignatureAlgorithm::kDilithium));
  payload.push_back(0x00);  // spent
  payload.push_back(0x00);  // watch_only

  primitives::serialize::WriteVarIntLegacy(&payload, 0);  // watch-only count
  return payload;
}

bool WriteLegacyWalletFile(const std::filesystem::path& path,
                           const std::string& password,
                           const std::vector<std::uint8_t>& payload) {
  using namespace qryptcoin;

  std::vector<std::uint8_t> header_salt(32, 0);
  for (std::size_t i = 0; i < 16; ++i) {
    header_salt[i] = static_cast<std::uint8_t>(i);
  }
  util::Argon2idParams params;
  params.t_cost = 1;
  params.m_cost_kib = 1024;
  params.parallelism = 1;
  auto encode_u32 = [&](std::uint32_t value, std::size_t offset) {
    header_salt[offset + 0] = static_cast<std::uint8_t>(value & 0xFF);
    header_salt[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    header_salt[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    header_salt[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
  };
  encode_u32(params.t_cost, 16);
  encode_u32(params.m_cost_kib, 20);
  encode_u32(params.parallelism, 24);

  std::array<std::uint8_t, util::kChaCha20Poly1305NonceSize> nonce{};
  for (std::size_t i = 0; i < nonce.size(); ++i) {
    nonce[i] = static_cast<std::uint8_t>(0xA0 + i);
  }

  std::vector<std::uint8_t> key;
  if (!util::DeriveKeyArgon2id(password,
                               std::span<const std::uint8_t>(header_salt.data(),
                                                             header_salt.size()),
                               params, &key)) {
    return false;
  }
  const auto ciphertext = util::ChaCha20Poly1305Encrypt(
      std::span<const std::uint8_t>(key.data(), key.size()),
      std::span<const std::uint8_t>(nonce.data(), nonce.size()),
      std::span<const std::uint8_t>(header_salt.data(), header_salt.size()),
      std::span<const std::uint8_t>(payload.data(), payload.size()));

  std::vector<std::uint8_t> file;
  primitives::serialize::WriteUint32(&file, kWalletMagic);
  file.push_back(static_cast<std::uint8_t>(kLegacyWalletVersion & 0xFFu));
  file.push_back(static_cast<std::uint8_t>((kLegacyWalletVersion >> 8) & 0xFFu));
  const std::uint16_t reserved = 1;  // Argon2id
  file.push_back(static_cast<std::uint8_t>(reserved & 0xFFu));
  file.push_back(static_cast<std::uint8_t>((reserved >> 8) & 0xFFu));
  file.insert(file.end(), header_salt.begin(), header_salt.end());
  file.insert(file.end(), nonce.begin(), nonce.end());
  primitives::serialize::WriteUint32(&file, static_cast<std::uint32_t>(ciphertext.size()));
  file.insert(file.end(), ciphertext.begin(), ciphertext.end());

  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out.is_open()) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(file.data()),
            static_cast<std::streamsize>(file.size()));
  return out.good();
}

std::uint16_t ReadWalletVersion(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) {
    return 0;
  }
  std::array<std::uint8_t, 8> header{};
  in.read(reinterpret_cast<char*>(header.data()),
          static_cast<std::streamsize>(header.size()));
  if (!in.good()) {
    return 0;
  }
  const std::uint32_t magic = static_cast<std::uint32_t>(header[0]) |
                              (static_cast<std::uint32_t>(header[1]) << 8) |
                              (static_cast<std::uint32_t>(header[2]) << 16) |
                              (static_cast<std::uint32_t>(header[3]) << 24);
  if (magic != kWalletMagic) {
    return 0;
  }
  return static_cast<std::uint16_t>(header[4] | (header[5] << 8));
}

}  // namespace

int main() {
  using namespace qryptcoin;
  try {
    const auto original_network = config::GetNetworkConfig().type;
    config::SelectNetwork(config::NetworkType::kRegtest);

    const std::filesystem::path wallet_path = "legacy_wallet_v4.dat";
    std::filesystem::remove(wallet_path);

    std::array<std::uint8_t, 32> seed{};
    seed.fill(0x42);
    const auto addr0 = DeriveLegacyDilithiumAddress(seed, 0);

    const auto payload = SerializeLegacyWalletPayload(
        std::span<const std::uint8_t>(seed.data(), seed.size()),
        /*next_index=*/1, addr0);
    const std::string password = "testpass";
    if (!WriteLegacyWalletFile(wallet_path, password, payload)) {
      std::cerr << "Failed to write legacy wallet fixture\n";
      return EXIT_FAILURE;
    }
    if (ReadWalletVersion(wallet_path) != kLegacyWalletVersion) {
      std::cerr << "Legacy wallet header version mismatch\n";
      return EXIT_FAILURE;
    }

    std::string error;
    auto wallet = wallet::HDWallet::Load(wallet_path.string(), password, &error);
    if (wallet) {
      std::cerr << "Expected legacy wallet format to be rejected\n";
      return EXIT_FAILURE;
    }
    if (error.find("unsupported wallet format version " + std::to_string(kLegacyWalletVersion)) ==
        std::string::npos) {
      std::cerr << "Unexpected legacy wallet rejection error: " << error << "\n";
      return EXIT_FAILURE;
    }

    std::filesystem::remove(wallet_path);
    config::SelectNetwork(config::NetworkType::kMainnet);

    const std::filesystem::path mainnet_wallet_path = "legacy_wallet_v4_mainnet.dat";
    std::filesystem::remove(mainnet_wallet_path);
    const auto addr_mainnet = DeriveLegacyDilithiumAddress(seed, 0);
    const auto payload_mainnet = SerializeLegacyWalletPayload(
        std::span<const std::uint8_t>(seed.data(), seed.size()),
        /*next_index=*/1, addr_mainnet);
    if (!WriteLegacyWalletFile(mainnet_wallet_path, password, payload_mainnet)) {
      std::cerr << "Failed to write legacy wallet fixture (mainnet)\n";
      return EXIT_FAILURE;
    }
    if (ReadWalletVersion(mainnet_wallet_path) != kLegacyWalletVersion) {
      std::cerr << "Legacy wallet header version mismatch (mainnet)\n";
      return EXIT_FAILURE;
    }

    auto rejected = wallet::HDWallet::Load(mainnet_wallet_path.string(), password, &error);
    if (rejected ||
        error.find("unsupported wallet format version " + std::to_string(kLegacyWalletVersion)) ==
            std::string::npos) {
      std::cerr << "Unexpected legacy wallet rejection error: " << error << "\n";
      return EXIT_FAILURE;
    }
    std::filesystem::remove(mainnet_wallet_path);

    config::SelectNetwork(original_network);
  } catch (const std::exception& ex) {
    std::cerr << "legacy_wallet_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << "legacy_wallet_tests unknown exception\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

