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
#include "primitives/serialize.hpp"
#include "util/aead.hpp"
#include "wallet/hd_wallet.hpp"

namespace {

constexpr std::uint32_t kWalletMagic = 0x51574C54;  // 'QTLT'
constexpr std::uint16_t kWalletVersionV2 = 2;
constexpr std::size_t kSha3_256BlockSize = 136;
constexpr std::uint32_t kPbkdf2Iterations = 200000;

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

std::vector<std::uint8_t> HmacSha3_256(const std::vector<std::uint8_t>& key,
                                       std::span<const std::uint8_t> data) {
  using namespace qryptcoin;

  std::vector<std::uint8_t> normalized = key;
  if (normalized.size() > kSha3_256BlockSize) {
    normalized = crypto::Sha3_256Vector(normalized);
  }
  normalized.resize(kSha3_256BlockSize, 0);
  std::vector<std::uint8_t> o_key(kSha3_256BlockSize);
  std::vector<std::uint8_t> i_key(kSha3_256BlockSize);
  for (std::size_t i = 0; i < kSha3_256BlockSize; ++i) {
    o_key[i] = static_cast<std::uint8_t>(normalized[i] ^ 0x5c);
    i_key[i] = static_cast<std::uint8_t>(normalized[i] ^ 0x36);
  }
  std::vector<std::uint8_t> inner;
  inner.reserve(i_key.size() + data.size());
  inner.insert(inner.end(), i_key.begin(), i_key.end());
  inner.insert(inner.end(), data.begin(), data.end());
  const auto inner_hash = crypto::Sha3_256Vector(inner);

  std::vector<std::uint8_t> outer;
  outer.reserve(o_key.size() + inner_hash.size());
  outer.insert(outer.end(), o_key.begin(), o_key.end());
  outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
  return crypto::Sha3_256Vector(outer);
}

std::vector<std::uint8_t> DeriveEncryptionKey(const std::string& password,
                                              const std::vector<std::uint8_t>& salt) {
  std::vector<std::uint8_t> key_material(password.begin(), password.end());
  std::uint32_t block_index = 1;
  std::vector<std::uint8_t> derived;
  derived.reserve(32);
  while (derived.size() < 32) {
    std::vector<std::uint8_t> salt_block = salt;
    salt_block.push_back(static_cast<std::uint8_t>((block_index >> 24) & 0xFF));
    salt_block.push_back(static_cast<std::uint8_t>((block_index >> 16) & 0xFF));
    salt_block.push_back(static_cast<std::uint8_t>((block_index >> 8) & 0xFF));
    salt_block.push_back(static_cast<std::uint8_t>(block_index & 0xFF));
    auto u = HmacSha3_256(key_material, salt_block);
    auto t = u;
    for (std::uint32_t i = 1; i < kPbkdf2Iterations; ++i) {
      u = HmacSha3_256(key_material, u);
      for (std::size_t j = 0; j < t.size(); ++j) {
        t[j] ^= u[j];
      }
    }
    derived.insert(derived.end(), t.begin(), t.end());
    ++block_index;
  }
  derived.resize(32);
  return derived;
}

std::vector<std::uint8_t> SerializeLegacyV2Payload(std::span<const std::uint8_t> seed,
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

  primitives::serialize::WriteVarIntLegacy(&payload, 0);  // utxo count
  primitives::serialize::WriteVarIntLegacy(&payload, 0);  // watch-only count
  return payload;
}

bool WriteLegacyV2WalletFile(const std::filesystem::path& path,
                             const std::string& password,
                             const std::vector<std::uint8_t>& payload) {
  using namespace qryptcoin;

  std::vector<std::uint8_t> salt(32, 0);
  for (std::size_t i = 0; i < 16; ++i) {
    salt[i] = static_cast<std::uint8_t>(i);
  }

  std::array<std::uint8_t, util::kChaCha20Poly1305NonceSize> nonce{};
  for (std::size_t i = 0; i < nonce.size(); ++i) {
    nonce[i] = static_cast<std::uint8_t>(0xA0 + i);
  }

  const auto key = DeriveEncryptionKey(password, salt);
  const auto ciphertext = util::ChaCha20Poly1305Encrypt(
      std::span<const std::uint8_t>(key.data(), key.size()),
      std::span<const std::uint8_t>(nonce.data(), nonce.size()),
      std::span<const std::uint8_t>(salt.data(), salt.size()),
      std::span<const std::uint8_t>(payload.data(), payload.size()));

  std::vector<std::uint8_t> file;
  primitives::serialize::WriteUint32(&file, kWalletMagic);
  file.push_back(static_cast<std::uint8_t>(kWalletVersionV2 & 0xFFu));
  file.push_back(static_cast<std::uint8_t>((kWalletVersionV2 >> 8) & 0xFFu));
  const std::uint16_t reserved = 0;  // legacy PBKDF2-HMAC-SHA3
  file.push_back(static_cast<std::uint8_t>(reserved & 0xFFu));
  file.push_back(static_cast<std::uint8_t>((reserved >> 8) & 0xFFu));
  file.insert(file.end(), salt.begin(), salt.end());
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

    const std::filesystem::path wallet_path = "legacy_wallet_v2.dat";
    std::filesystem::remove(wallet_path);

    std::array<std::uint8_t, 32> seed{};
    seed.fill(0x42);
    const auto addr0 = DeriveLegacyDilithiumAddress(seed, 0);

    const auto payload = SerializeLegacyV2Payload(
        std::span<const std::uint8_t>(seed.data(), seed.size()),
        /*next_index=*/1, addr0);
    const std::string password = "";  // historical wallets allowed empty passphrases
    if (!WriteLegacyV2WalletFile(wallet_path, password, payload)) {
      std::cerr << "Failed to write v2 wallet fixture\n";
      return EXIT_FAILURE;
    }
    if (ReadWalletVersion(wallet_path) != kWalletVersionV2) {
      std::cerr << "v2 wallet header version mismatch\n";
      return EXIT_FAILURE;
    }

    std::string error;
    auto wallet = wallet::HDWallet::Load(wallet_path.string(), password, &error);
    if (wallet) {
      std::cerr << "Expected v2 wallet format to be rejected\n";
      return EXIT_FAILURE;
    }
    if (error.find("unsupported wallet format version " + std::to_string(kWalletVersionV2)) ==
        std::string::npos) {
      std::cerr << "Unexpected legacy wallet rejection error: " << error << "\n";
      return EXIT_FAILURE;
    }

    std::filesystem::remove(wallet_path);

    config::SelectNetwork(config::NetworkType::kMainnet);

    const std::filesystem::path mainnet_wallet_path = "legacy_wallet_v2_mainnet.dat";
    std::filesystem::remove(mainnet_wallet_path);
    const auto addr_mainnet = DeriveLegacyDilithiumAddress(seed, 0);
    const auto payload_mainnet = SerializeLegacyV2Payload(
        std::span<const std::uint8_t>(seed.data(), seed.size()),
        /*next_index=*/1, addr_mainnet);
    if (!WriteLegacyV2WalletFile(mainnet_wallet_path, password, payload_mainnet)) {
      std::cerr << "Failed to write v2 wallet fixture (mainnet)\n";
      return EXIT_FAILURE;
    }
    if (ReadWalletVersion(mainnet_wallet_path) != kWalletVersionV2) {
      std::cerr << "v2 wallet header version mismatch (mainnet)\n";
      return EXIT_FAILURE;
    }

    auto rejected = wallet::HDWallet::Load(mainnet_wallet_path.string(), password, &error);
    if (rejected || error.find("unsupported wallet format version " + std::to_string(kWalletVersionV2)) ==
                        std::string::npos) {
      std::cerr << "Unexpected legacy wallet rejection error: " << error << "\n";
      return EXIT_FAILURE;
    }
    std::filesystem::remove(mainnet_wallet_path);
    config::SelectNetwork(original_network);
  } catch (const std::exception& ex) {
    std::cerr << "wallet_format_v2_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

