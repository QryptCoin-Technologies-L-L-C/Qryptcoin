#include "wallet/hd_wallet.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <span>

#include "config/network.hpp"
#include "consensus/sighash.hpp"
#include "crypto/deterministic_rng.hpp"
#include "crypto/hash.hpp"
#include "crypto/payment_code.hpp"
#include "crypto/p2qh_address.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/mnemonic.hpp"
#include "primitives/amount.hpp"
#include "primitives/serialize.hpp"
#include "primitives/txid.hpp"
#include "script/p2qh.hpp"
#include "util/aead.hpp"
#include "util/hex.hpp"
#include "util/argon2_kdf.hpp"
#include "util/atomic_file.hpp"
#include "util/csprng.hpp"
#include "util/secure_wipe.hpp"

namespace qryptcoin::wallet {

namespace {

constexpr std::uint32_t kWalletMagic = 0x51574C54;  // 'QTLT'
constexpr std::uint16_t kWalletVersion = 7;
constexpr std::uint16_t kMinWalletVersion = 6;
constexpr std::size_t kSha3_256BlockSize = 136;
constexpr std::uint32_t kPbkdf2Iterations = 200000;
constexpr primitives::Amount kDustChangeThreshold =
    primitives::kMiksPerQRY / 10'000ULL;  // 0.0001 QRY
// Maintain a modest HD gap so that rescans can safely pick up funds
// sent to "next" external addresses without requiring explicit
// address derivation first.
constexpr std::uint32_t kDefaultKeypoolGap = 20;
// Upper bound on the number of inputs the wallet will consider for
// branch-and-bound style coin selection. This keeps the exponential
// search space bounded while still handling common operator cases.
constexpr std::size_t kMaxBranchAndBoundInputs = 12;

// Argon2id parameter caps when loading wallet files (DoS hardening).
constexpr std::uint32_t kMaxWalletArgon2idT = 10;
constexpr std::uint32_t kMaxWalletArgon2idMemoryKiB = 1024u * 1024u;  // 1 GiB
constexpr std::uint32_t kMaxWalletArgon2idParallelism = 8;

constexpr std::uint64_t kBaseTxInBytes = 32 + 4 + 1 + 4;
constexpr std::uint64_t kBaseTxOutValueBytes = 8;
constexpr std::uint64_t kBaseTxVersionBytes = 4;
constexpr std::uint64_t kBaseTxLockTimeBytes = 4;
constexpr std::size_t kP2QHScriptBytes = 2 + script::kP2QHWitnessProgramSize;

std::size_t VarIntSize(std::uint64_t value) {
  if (value < 0xFDu) return 1;
  if (value <= 0xFFFFu) return 3;
  if (value <= 0xFFFFFFFFu) return 5;
  return 9;
}

std::size_t EstimateRevealBytes(crypto::SignatureAlgorithm algo) {
  // P2QH reveal payload is encoded as:
  //   version(1) + algo_id(1) + params_id(1) + reserved(2) + pk_len(2) + pk_bytes
  (void)algo;
  const auto pubkey_bytes = crypto::DilithiumPublicKeySize();
  return 7 + pubkey_bytes;
}

std::size_t EstimateWitnessBytesPerInput(crypto::SignatureAlgorithm algo) {
  // Each input witness stack includes:
  //   item_count(varint=2) + [reveal] + [signature]
  const std::size_t reveal_bytes = EstimateRevealBytes(algo);
  const std::size_t signature_bytes = crypto::DilithiumSignatureSize();
  return VarIntSize(/*item_count=*/2) +
         VarIntSize(reveal_bytes) + reveal_bytes +
         VarIntSize(signature_bytes) + signature_bytes;
}

std::uint64_t EstimateTransactionVBytes(std::uint64_t inputs,
                                       std::uint64_t outputs,
                                       crypto::SignatureAlgorithm algo) {
  if (inputs == 0 || outputs == 0) {
    return 0;
  }
  const std::uint64_t output_bytes =
      outputs * (kBaseTxOutValueBytes + VarIntSize(kP2QHScriptBytes) + kP2QHScriptBytes);
  const std::uint64_t base_bytes =
      kBaseTxVersionBytes +
      VarIntSize(inputs) +
      inputs * kBaseTxInBytes +
      VarIntSize(outputs) +
      output_bytes +
      kBaseTxLockTimeBytes;
  const std::uint64_t witness_bytes =
      2 + inputs * static_cast<std::uint64_t>(EstimateWitnessBytesPerInput(algo));
  const std::uint64_t weight = base_bytes * 4ULL + witness_bytes;
  return (weight + 3ULL) / 4ULL;
}

enum class WalletKdf : std::uint16_t {
  kLegacyHmacSha3 = 0,
  kArgon2id = 1,
};

std::vector<std::uint8_t> RandomBytes(std::size_t size) {
  return util::SecureRandomBytes(size);
}

std::vector<std::uint8_t> HmacSha3_256(const std::vector<std::uint8_t>& key,
                                       std::span<const std::uint8_t> data) {
  std::vector<std::uint8_t> normalized = key;
  if (normalized.size() > kSha3_256BlockSize) {
    auto hashed = crypto::Sha3_256Vector(normalized);
    util::SecureWipe(normalized);
    normalized = std::move(hashed);
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
  auto inner_hash = crypto::Sha3_256Vector(inner);

  std::vector<std::uint8_t> outer;
  outer.reserve(o_key.size() + inner_hash.size());
  outer.insert(outer.end(), o_key.begin(), o_key.end());
  outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
  auto result = crypto::Sha3_256Vector(outer);
  util::SecureWipe(normalized);
  util::SecureWipe(o_key);
  util::SecureWipe(i_key);
  util::SecureWipe(inner);
  util::SecureWipe(inner_hash);
  util::SecureWipe(outer);
  return result;
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
    std::vector<std::uint8_t> t = u;
    for (std::uint32_t i = 1; i < kPbkdf2Iterations; ++i) {
      auto next_u = HmacSha3_256(key_material, u);
      util::SecureWipe(u);
      u = std::move(next_u);
      for (std::size_t j = 0; j < t.size(); ++j) {
        t[j] ^= u[j];
      }
    }
    for (std::size_t j = 0; j < t.size() && derived.size() < 32; ++j) {
      derived.push_back(t[j]);
    }
    util::SecureWipe(salt_block);
    util::SecureWipe(u);
    util::SecureWipe(t);
    ++block_index;
  }
  util::SecureWipe(key_material);
  return derived;
}

std::array<std::uint8_t, 32> HexToArray(const std::string& hex) {
  std::array<std::uint8_t, 32> result{};
  for (std::size_t i = 0; i < hex.size() / 2 && i < result.size(); ++i) {
    result[i] = static_cast<std::uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
  }
  return result;
}

std::string ArrayToHex(const std::array<std::uint8_t, 32>& data) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (auto byte : data) {
    out.push_back(kHex[(byte >> 4) & 0xF]);
    out.push_back(kHex[byte & 0xF]);
  }
  return out;
}

std::array<std::uint8_t, 32> DeriveMldsaKeygenSeed(const std::array<std::uint8_t, 32>& master_seed,
                                                   std::uint32_t index) {
  constexpr std::string_view kTag = "QRY-MLDSA-KEYGEN-V1";
  std::vector<std::uint8_t> buffer;
  buffer.reserve(kTag.size() + master_seed.size() + sizeof(std::uint32_t));
  buffer.insert(buffer.end(), kTag.begin(), kTag.end());
  buffer.insert(buffer.end(), master_seed.begin(), master_seed.end());
  primitives::serialize::WriteUint32(&buffer, index);
  return crypto::Sha3_256(buffer);
}

std::string DescriptorHex(const crypto::P2QHDescriptor& descriptor) {
  const auto serialized = crypto::SerializeP2QHDescriptor(descriptor);
  return util::HexEncode(std::span<const std::uint8_t>(serialized.data(), serialized.size()));
}

// A tiny branch-and-bound style subset-selection helper: given a list
// of candidate UTXOs (already sorted by the wallet's preferred spend
// order) and a target amount, search for a subset whose total value is
// at least the target while minimizing the excess ("waste"). Fees are
// handled by the caller; this routine operates purely on values.
struct BnbSelection {
  bool found{false};
  primitives::Amount best_sum{0};
  primitives::Amount best_waste{0};
  std::vector<std::size_t> chosen_indices;
};

template <typename Candidate>
void BranchAndBoundDfs(const std::vector<Candidate>& candidates,
                       std::size_t idx,
                       primitives::Amount target,
                       primitives::Amount current_sum,
                       std::vector<bool>* current_choice,
                       BnbSelection* out) {
  if (idx == candidates.size()) {
    if (current_sum >= target) {
      const primitives::Amount waste = current_sum - target;
      if (!out->found || waste < out->best_waste) {
        out->found = true;
        out->best_sum = current_sum;
        out->best_waste = waste;
        out->chosen_indices.clear();
        for (std::size_t i = 0; i < candidates.size(); ++i) {
          if ((*current_choice)[i]) {
            out->chosen_indices.push_back(candidates[i].index);
          }
        }
      }
    }
    return;
  }

  // Simple pruning: if we already have a strictly better solution with
  // zero waste, there is nothing left to improve.
  if (out->found && out->best_waste == 0) {
    return;
  }

  // Include the current candidate.
  (*current_choice)[idx] = true;
  primitives::Amount included_sum = 0;
  if (primitives::CheckedAdd(current_sum, candidates[idx].value, &included_sum)) {
    BranchAndBoundDfs(candidates, idx + 1, target, included_sum,
                      current_choice, out);
  }

  // Exclude the current candidate.
  (*current_choice)[idx] = false;
  BranchAndBoundDfs(candidates, idx + 1, target, current_sum,
                    current_choice, out);
}

}  // namespace

HDWallet::HDWallet(std::string path, std::string password, std::array<std::uint8_t, 32> seed,
                   crypto::SignatureAlgorithm default_algo)
    : wallet_path_(std::move(path)),
      password_(std::move(password)),
      wallet_format_version_(kWalletVersion),
      derivation_scheme_(DerivationScheme::kSha3Ctr),
      seed_(seed),
      default_algorithm_(default_algo) {}

HDWallet::~HDWallet() {
  util::SecureWipe(password_);
  util::SecureWipe(seed_);
}

std::unique_ptr<HDWallet> HDWallet::Create(const std::string& path, const std::string& password,
                                           crypto::SignatureAlgorithm default_algo) {
  auto seed = RandomBytes(32);
  std::array<std::uint8_t, 32> seed_arr{};
  std::copy_n(seed.begin(), seed_arr.size(), seed_arr.begin());
  util::SecureWipe(seed);
  auto wallet = std::unique_ptr<HDWallet>(new HDWallet(path, password, seed_arr, default_algo));
  util::SecureWipe(seed_arr);
  wallet->locked_ = false;
  wallet->EnsureKeypoolGap(kDefaultKeypoolGap);
  if (!wallet->Save()) {
    return nullptr;
  }
  return wallet;
}

std::unique_ptr<HDWallet> HDWallet::ImportSeedHex(const std::string& path,
                                                  const std::string& password,
                                                  const std::string& seed_hex,
                                                  crypto::SignatureAlgorithm default_algo) {
  auto wallet = std::unique_ptr<HDWallet>(
      new HDWallet(path, password, HexToArray(seed_hex), default_algo));
  wallet->locked_ = false;
  wallet->EnsureKeypoolGap(kDefaultKeypoolGap);
  if (!wallet->Save()) {
    return nullptr;
  }
  return wallet;
}

std::unique_ptr<HDWallet> HDWallet::FromSeedForTools(
    const std::array<std::uint8_t, 32>& seed,
    crypto::SignatureAlgorithm default_algo) {
  auto wallet = std::unique_ptr<HDWallet>(
      new HDWallet(std::string{}, std::string{}, seed, default_algo));
  wallet->in_memory_ = true;
  wallet->locked_ = false;
  wallet->EnsureKeypoolGap(kDefaultKeypoolGap);
  return wallet;
}

std::string HDWallet::GenerateMnemonic24() {
  // 24-word mnemonics use 256 bits of entropy (plus 8 bits of checksum).
  // 256 bits entropy + 8 bits checksum, split into 24 groups of 11-bit
  // indices into the embedded English wordlist.
  constexpr std::size_t kEntropyBytes = 32;
  auto entropy = RandomBytes(kEntropyBytes);
  const auto& words = crypto::EnglishMnemonicWordlist();
  if (words.size() != 2048) {
    // Fallback: should never happen in normal builds.
    return {};
  }

  // Build a 264-bit buffer: 256 bits entropy + 8 bits checksum.
  std::vector<bool> bits;
  bits.reserve((entropy.size() + 1) * 8);
  for (std::uint8_t byte : entropy) {
    for (int i = 7; i >= 0; --i) {
      bits.push_back(((byte >> i) & 0x01) != 0);
    }
  }
  const auto hash =
      crypto::Sha256(std::span<const std::uint8_t>(entropy.data(), entropy.size()));
  const std::uint8_t checksum_byte = hash[0];
  for (int i = 7; i >= 0; --i) {
    bits.push_back(((checksum_byte >> i) & 0x01) != 0);
  }

  // Split into 24 groups of 11 bits each to index the wordlist.
  if (bits.size() != 264) {
    return {};
  }
  std::string mnemonic;
  for (int i = 0; i < 24; ++i) {
    std::uint32_t index = 0;
    for (int j = 0; j < 11; ++j) {
      index <<= 1;
      if (bits[static_cast<std::size_t>(i * 11 + j)]) {
        index |= 1;
      }
    }
    if (index >= words.size()) {
      return {};
    }
    if (!mnemonic.empty()) {
      mnemonic.push_back(' ');
    }
    mnemonic.append(words[index]);
  }
  return mnemonic;
}

std::unique_ptr<HDWallet> HDWallet::Load(const std::string& path, const std::string& password) {
  return Load(path, password, nullptr);
}

std::unique_ptr<HDWallet> HDWallet::Load(const std::string& path, const std::string& password,
                                        std::string* error) {
  if (error) {
    error->clear();
  }
  auto wallet = std::unique_ptr<HDWallet>(
      new HDWallet(path, password, std::array<std::uint8_t, 32>{},
                   crypto::SignatureAlgorithm::kDilithium));
  std::vector<std::uint8_t> payload;
  std::uint16_t version = 0;
  if (!wallet->ReadAndDecrypt(&payload, &version)) {
    if (error) {
      *error = wallet->last_error();
    }
    util::SecureWipe(payload);
    return nullptr;
  }
  if (!wallet->DeserializeState(payload, version)) {
    if (error) {
      *error = wallet->last_error();
    }
    util::SecureWipe(payload);
    return nullptr;
  }
  util::SecureWipe(payload);
  // After loading, ensure there is a small buffer of future addresses so
  // rescans can safely discover funds sent to the next few indices.
  wallet->EnsureKeypoolGap(kDefaultKeypoolGap);
  wallet->locked_ = false;
  return wallet;
}

std::string HDWallet::DeriveAddressForTools(std::uint32_t index,
                                            crypto::SignatureAlgorithm algorithm) {
  return DeriveAddressInternal(index, algorithm);
}

bool HDWallet::ExportDerivedKeyForTools(std::uint32_t index,
                                        crypto::SignatureAlgorithm algorithm,
                                        DerivedKeyInfo* out) const {
  if (!out) {
    return false;
  }
  auto material = DeriveKeyMaterial(index, algorithm);
  DerivedKeyInfo info;
  info.index = index;
  info.algorithm = material.algorithm;
  info.descriptor = material.descriptor;
  info.reveal = material.reveal;

  if (material.dilithium) {
    const auto pub = material.dilithium->PublicKey();
    const auto sec = material.dilithium->SecretKey();
    info.dilithium_public_key.assign(pub.begin(), pub.end());
    info.dilithium_secret_key.assign(sec.begin(), sec.end());
  }

  *out = std::move(info);
  return true;
}

void HDWallet::EnsureKeypoolGap(std::uint32_t gap_limit) {
  if (gap_limit == 0) {
    return;
  }
  // Determine which key indices currently have unspent outputs so we can
  // approximate a "used" flag for each derived address.
  std::unordered_map<std::uint32_t, bool> used_indices;
  used_indices.reserve(utxos_.size());
  for (const auto& utxo : utxos_) {
    if (!utxo.spent) {
      used_indices[utxo.key_index] = true;
    }
  }

  std::uint32_t consecutive_unused = 0;
  if (!addresses_.empty()) {
    for (std::size_t i = addresses_.size(); i > 0; --i) {
      const auto& entry = addresses_[i - 1];
      const bool used = used_indices.find(entry.index) != used_indices.end();
      if (used) {
        break;
      }
      ++consecutive_unused;
      if (consecutive_unused >= gap_limit) {
        return;
      }
    }
  }

  // Extend the keychain until the requested tail gap is satisfied.
  while (consecutive_unused < gap_limit) {
    auto material = DeriveKeyMaterial(next_index_, default_algorithm_);
    AddressEntry entry;
    entry.index = next_index_;
    entry.algorithm = default_algorithm_;
    entry.descriptor = material.descriptor;
    entry.program = material.descriptor.program;
    entry.address = crypto::EncodeP2QHAddress(
        entry.descriptor, config::GetNetworkConfig().bech32_hrp);
    addresses_.push_back(entry);
    IndexAddress(addresses_.size() - 1);
    ++next_index_;
    ++consecutive_unused;
  }
}

bool HDWallet::CreateFromMnemonic(const std::string& path, const std::string& password,
                                  const std::string& mnemonic,
                                  const std::string& mnemonic_passphrase,
                                  crypto::SignatureAlgorithm default_algo) {
  last_error_.clear();
  if (path.empty()) {
    last_error_ = "wallet path is empty";
    return false;
  }
  if (password.empty()) {
    last_error_ = "passphrase cannot be empty";
    return false;
  }
  std::string mnemonic_error;
  if (!crypto::ValidateMnemonic24(mnemonic, &mnemonic_error)) {
    last_error_ = mnemonic_error.empty() ? "invalid 24-word mnemonic"
                                         : ("invalid 24-word mnemonic: " + mnemonic_error);
    return false;
  }

  // Canonicalize the mnemonic for seed derivation: lowercase words joined by
  // single ASCII spaces. This keeps wallet recovery stable under harmless
  // whitespace or casing differences in user input.
  std::string canonical_mnemonic;
  canonical_mnemonic.reserve(mnemonic.size());
  std::size_t pos = 0;
  std::size_t word_count = 0;
  auto is_space = [](char ch) {
    return std::isspace(static_cast<unsigned char>(ch)) != 0;
  };
  while (pos < mnemonic.size()) {
    while (pos < mnemonic.size() && is_space(mnemonic[pos])) {
      ++pos;
    }
    if (pos >= mnemonic.size()) {
      break;
    }
    const std::size_t start = pos;
    while (pos < mnemonic.size() && !is_space(mnemonic[pos])) {
      ++pos;
    }
    if (start == pos) {
      continue;
    }
    if (word_count > 0) {
      canonical_mnemonic.push_back(' ');
    }
    for (std::size_t i = start; i < pos; ++i) {
      canonical_mnemonic.push_back(static_cast<char>(
          std::tolower(static_cast<unsigned char>(mnemonic[i]))));
    }
    ++word_count;
  }
  if (word_count != 24) {
    last_error_ = "mnemonic must contain exactly 24 words";
    util::SecureWipe(canonical_mnemonic);
    return false;
  }
  util::SecureWipe(password_);
  util::SecureWipe(seed_);
  wallet_path_ = path;
  password_ = password;
  wallet_format_version_ = kWalletVersion;
  derivation_scheme_ = DerivationScheme::kSha3Ctr;
  default_algorithm_ = default_algo;
  next_index_ = 0;
  addresses_.clear();
  address_index_.clear();
  program_index_.clear();
  utxos_.clear();
  burned_key_indices_.clear();
  transactions_.clear();
  watch_only_.clear();
  watch_only_address_index_.clear();
  watch_only_program_index_.clear();
  payment_code_reservations_.clear();
  in_memory_ = false;

  // Derive the mnemonic seed and compress it to the 32-byte internal master
  // seed via SHA3-256 to stay aligned with the existing PQ HD derivation pipe.
  auto mnemonic_seed = crypto::MnemonicSeedFromSentence(canonical_mnemonic, mnemonic_passphrase);
  util::SecureWipe(canonical_mnemonic);
  auto seed32 = crypto::Sha3_256(
      std::span<const std::uint8_t>(mnemonic_seed.data(), mnemonic_seed.size()));
  std::copy(seed32.begin(), seed32.end(), seed_.begin());
  util::SecureWipe(mnemonic_seed);
  util::SecureWipe(seed32);

  locked_ = false;
  EnsureKeypoolGap(kDefaultKeypoolGap);
  if (!Save()) {
    if (last_error_.empty()) {
      last_error_ = "failed to write wallet file";
    }
    return false;
  }
  last_error_.clear();
  return true;
}

std::string HDWallet::NewAddress(crypto::SignatureAlgorithm policy) {
  (void)policy;
  auto material = DeriveKeyMaterial(next_index_, crypto::SignatureAlgorithm::kDilithium);
  AddressEntry entry;
  entry.index = next_index_;
  entry.algorithm = crypto::SignatureAlgorithm::kDilithium;
  entry.descriptor = material.descriptor;
  entry.program = material.descriptor.program;
  entry.address =
      crypto::EncodeP2QHAddress(entry.descriptor, config::GetNetworkConfig().bech32_hrp);
  const auto inserted_index = next_index_;
  addresses_.push_back(entry);
  IndexAddress(addresses_.size() - 1);
  next_index_++;

  if (wallet_path_.empty()) {
    if (in_memory_) {
      return entry.address;
    }
    address_index_.erase(entry.address);
    program_index_.erase(entry.program);
    addresses_.pop_back();
    next_index_ = inserted_index;
    last_error_ = "wallet path is empty";
    return {};
  }

  // Persist the newly derived address/index so it survives restarts even
  // before any funds have been received. If persistence fails, roll back
  // the in-memory mutation to avoid accidentally re-issuing the same key
  // after restart.
  if (!Save()) {
    address_index_.erase(entry.address);
    program_index_.erase(entry.program);
    addresses_.pop_back();
    next_index_ = inserted_index;
    return {};
  }
  return entry.address;
}

std::string HDWallet::NewAddress(bool hybrid_override) {
  (void)hybrid_override;
  return NewAddress(crypto::SignatureAlgorithm::kDilithium);
}

bool HDWallet::ReservePaymentCodeAddress(const PaymentCodeReservation& reservation,
                                         std::string* out_address,
                                         std::string* error) {
  if (error) {
    error->clear();
  }
  if (out_address) {
    out_address->clear();
  }
  if (locked_) {
    if (error) {
      *error = "wallet is locked";
    }
    return false;
  }

  auto material = DeriveKeyMaterial(next_index_, crypto::SignatureAlgorithm::kDilithium);
  AddressEntry entry;
  entry.index = next_index_;
  entry.algorithm = crypto::SignatureAlgorithm::kDilithium;
  entry.descriptor = material.descriptor;
  entry.program = material.descriptor.program;
  entry.address =
      crypto::EncodeP2QHAddress(entry.descriptor, config::GetNetworkConfig().bech32_hrp);

  const auto inserted_index = next_index_;
  addresses_.push_back(entry);
  IndexAddress(addresses_.size() - 1);
  next_index_++;

  PaymentCodeReservation stored = reservation;
  stored.key_index = inserted_index;
  if (stored.issued_time == 0) {
    stored.issued_time = Now();
  }
  payment_code_reservations_.push_back(stored);

  if (wallet_path_.empty() && in_memory_) {
    if (out_address) {
      *out_address = entry.address;
    }
    return true;
  }

  if (!Save()) {
    payment_code_reservations_.pop_back();
    address_index_.erase(entry.address);
    program_index_.erase(entry.program);
    addresses_.pop_back();
    next_index_ = inserted_index;
    if (error) {
      *error = last_error_.empty() ? "wallet write failed" : last_error_;
    }
    return false;
  }

  if (out_address) {
    *out_address = entry.address;
  }
  return true;
}

std::size_t HDWallet::PaymentCodeReservationCount() const {
  return payment_code_reservations_.size();
}

bool HDWallet::HasPaymentCodeReservationForKeyIndex(std::uint32_t key_index) const {
  for (const auto& reservation : payment_code_reservations_) {
    if (reservation.key_index == key_index) {
      return true;
    }
  }
  return false;
}

std::string HDWallet::PaymentCode() const {
  const auto& cfg = config::GetNetworkConfig();
  auto network_id_from_magic = [](const std::array<std::uint8_t, 4>& magic) -> std::uint32_t {
    return static_cast<std::uint32_t>(magic[0]) |
           (static_cast<std::uint32_t>(magic[1]) << 8) |
           (static_cast<std::uint32_t>(magic[2]) << 16) |
           (static_cast<std::uint32_t>(magic[3]) << 24);
  };

  auto tagged_seed_hash = [&](std::string_view tag) -> crypto::Sha3_256Hash {
    std::vector<std::uint8_t> preimage;
    preimage.reserve(tag.size() + cfg.message_start.size() + seed_.size());
    for (char c : tag) {
      preimage.push_back(static_cast<std::uint8_t>(c));
    }
    preimage.insert(preimage.end(), cfg.message_start.begin(), cfg.message_start.end());
    preimage.insert(preimage.end(), seed_.begin(), seed_.end());
    return crypto::Sha3_256(preimage);
  };

  crypto::PaymentCodeV1 code{};
  code.network_id = network_id_from_magic(cfg.message_start);
  code.kdf_id = 0x01;
  const auto scan = tagged_seed_hash("QRY-PAYCODE-SCAN-V1");
  const auto spend = tagged_seed_hash("QRY-PAYCODE-SPENDROOT-V1");
  std::copy(scan.begin(), scan.end(), code.scan_pubkey.begin());
  std::copy(spend.begin(), spend.end(), code.spend_root_commitment.begin());
  return crypto::EncodePaymentCodeV1(code, cfg.bech32_hrp);
}

std::vector<std::string> HDWallet::ListAddresses() const {
  std::vector<std::string> result;
  for (const auto& addr : addresses_) {
    result.push_back(addr.address);
  }
  return result;
}

std::vector<std::string> HDWallet::ListWatchOnlyAddresses() const {
  std::vector<std::string> result;
  result.reserve(watch_only_.size());
  for (const auto& entry : watch_only_) {
    result.push_back(entry.address);
  }
  return result;
}

bool HDWallet::ForgetAddress(const std::string& address) {
  auto it = address_index_.find(address);
  if (it == address_index_.end()) {
    return false;
  }
  const std::size_t idx = it->second;
  address_index_.erase(it);
  program_index_.erase(addresses_[idx].program);
  addresses_.erase(addresses_.begin() + static_cast<std::ptrdiff_t>(idx));
  // Rebuild indexes for affected entries.
  for (std::size_t i = idx; i < addresses_.size(); ++i) {
    address_index_[addresses_[i].address] = i;
    program_index_[addresses_[i].program] = i;
  }
  Save();
  return true;
}

bool HDWallet::AddWatchOnlyAddress(const std::string& address) {
  // Reject obviously empty inputs.
  if (address.empty()) {
    return false;
  }
  // Avoid duplicating existing watch-only entries.
  if (watch_only_address_index_.find(address) != watch_only_address_index_.end()) {
    return false;
  }
  // Decode the bech32m P2QH address into a descriptor so we can track
  // its witness program hash.
  crypto::P2QHDescriptor descriptor{};
  if (!crypto::DecodeP2QHAddress(address, config::GetNetworkConfig().bech32_hrp,
                                 &descriptor)) {
    return false;
  }
  WatchOnlyEntry entry;
  entry.address = address;
  entry.descriptor = descriptor;
  entry.program = descriptor.program;
  const std::size_t idx = watch_only_.size();
  watch_only_.push_back(entry);
  watch_only_address_index_[address] = idx;
  watch_only_program_index_[entry.program] = idx;
  Save();
  return true;
}

bool HDWallet::RemoveWatchOnlyAddress(const std::string& address) {
  auto it = watch_only_address_index_.find(address);
  if (it == watch_only_address_index_.end()) {
    return false;
  }
  const std::size_t idx = it->second;
  watch_only_address_index_.erase(it);
  watch_only_program_index_.erase(watch_only_[idx].program);
  watch_only_.erase(watch_only_.begin() + static_cast<std::ptrdiff_t>(idx));
  // Rebuild indices for shifted entries.
  for (std::size_t i = idx; i < watch_only_.size(); ++i) {
    watch_only_address_index_[watch_only_[i].address] = i;
    watch_only_program_index_[watch_only_[i].program] = i;
  }
  Save();
  return true;
}

std::vector<std::string> HDWallet::ListDescriptorHexes() const {
  std::vector<std::string> descriptors;
  descriptors.reserve(addresses_.size());
  for (const auto& entry : addresses_) {
    descriptors.push_back(DescriptorHex(entry.descriptor));
  }
  return descriptors;
}

std::optional<std::vector<std::uint8_t>> HDWallet::ScriptForAddress(const std::string& address) const {
  const auto* entry = FindAddressEntry(address);
  if (entry == nullptr) {
    return std::nullopt;
  }
  auto script = script::CreateP2QHScript(entry->descriptor);
  return script.data;
}

std::optional<std::uint32_t> HDWallet::KeyIndexForAddress(const std::string& address) const {
  const auto* entry = FindAddressEntry(address);
  if (entry == nullptr) return std::nullopt;
  return entry->index;
}

std::optional<crypto::P2QHDescriptor> HDWallet::DescriptorForAddress(const std::string& address) const {
  const auto* entry = FindAddressEntry(address);
  if (entry == nullptr) return std::nullopt;
  return entry->descriptor;
}

std::optional<crypto::P2QHDescriptor> HDWallet::DescriptorForProgram(
    std::span<const std::uint8_t> program) const {
  if (program.size() != primitives::Hash256{}.size()) return std::nullopt;
  primitives::Hash256 key{};
  std::copy(program.begin(), program.end(), key.begin());
  auto it = program_index_.find(key);
  if (it == program_index_.end()) {
    return std::nullopt;
  }
  return addresses_[it->second].descriptor;
}

bool HDWallet::IsKeyBurned(std::uint32_t key_index) const {
  return std::binary_search(burned_key_indices_.begin(), burned_key_indices_.end(), key_index);
}

void HDWallet::BurnKeyIndex(std::uint32_t key_index) {
  const auto it =
      std::lower_bound(burned_key_indices_.begin(), burned_key_indices_.end(), key_index);
  if (it == burned_key_indices_.end() || *it != key_index) {
    burned_key_indices_.insert(it, key_index);
  }
}

primitives::Amount HDWallet::GetBalance() const {
  auto outpoint_less = [](const primitives::COutPoint& a, const primitives::COutPoint& b) {
    if (a.txid != b.txid) {
      return std::lexicographical_compare(a.txid.begin(), a.txid.end(),
                                          b.txid.begin(), b.txid.end());
    }
    return a.index < b.index;
  };
  struct BestCandidate {
    primitives::Amount value{0};
    primitives::COutPoint outpoint;
    bool initialized{false};
  };
  std::unordered_map<std::uint32_t, BestCandidate> best_by_key;
  best_by_key.reserve(utxos_.size());
  for (const auto& utxo : utxos_) {
    if (utxo.spent || utxo.watch_only) {
      continue;
    }
    if (utxo.txout.value == 0) {
      continue;
    }
    if (IsKeyBurned(utxo.key_index)) {
      continue;
    }
    auto& best = best_by_key[utxo.key_index];
    if (!best.initialized || utxo.txout.value > best.value ||
        (utxo.txout.value == best.value && outpoint_less(utxo.outpoint, best.outpoint))) {
      best.value = utxo.txout.value;
      best.outpoint = utxo.outpoint;
      best.initialized = true;
    }
  }

  primitives::Amount total = 0;
  for (const auto& kv : best_by_key) {
    const auto& best = kv.second;
    if (!best.initialized) {
      continue;
    }
    primitives::Amount next = 0;
    if (!primitives::CheckedAdd(total, best.value, &next)) {
      return primitives::kMaxMoney;
    }
    total = next;
  }
  return total;
}

primitives::Amount HDWallet::GetWatchOnlyBalance() const {
  primitives::Amount total = 0;
  for (const auto& utxo : utxos_) {
    if (!utxo.spent && utxo.watch_only) {
      primitives::Amount next = 0;
      if (!primitives::CheckedAdd(total, utxo.txout.value, &next)) {
        return primitives::kMaxMoney;
      }
      total = next;
    }
  }
  return total;
}

std::vector<WalletTransaction> HDWallet::ListTransactions() const {
  return transactions_;
}

bool HDWallet::AddUTXO(const WalletUTXO& utxo, bool is_coinbase,
                       primitives::Amount tx_fee_miks) {
  if (!primitives::MoneyRange(utxo.txout.value)) {
    return false;
  }
  bool is_new = true;
  for (auto& existing : utxos_) {
    if (existing.outpoint.txid == utxo.outpoint.txid &&
        existing.outpoint.index == utxo.outpoint.index) {
      is_new = false;
      if (is_coinbase) {
        existing.coinbase = true;
      }
      break;
    }
  }
  if (is_new) {
    WalletUTXO stored = utxo;
    stored.coinbase = is_coinbase;
    utxos_.push_back(stored);
  }
  WalletTransaction event;
  event.txid = util::HexEncode(
      std::span<const std::uint8_t>(utxo.outpoint.txid.data(), utxo.outpoint.txid.size()));
  event.amount = utxo.txout.value;
  event.incoming = true;
  event.timestamp = Now();
  event.label = is_coinbase ? "Mined" : "Incoming";
  event.fee = tx_fee_miks;
  event.confirmations = 0;
  event.coinbase = is_coinbase;
  RecordTransaction(event);
  return is_new;
}

bool HDWallet::MaybeTrackOutput(const primitives::Hash256& txid, std::size_t vout_index,
                                const primitives::CTxOut& txout, bool is_coinbase,
                                primitives::Amount tx_fee_miks) {
  script::ScriptPubKey script{txout.locking_descriptor};
  std::array<std::uint8_t, script::kP2QHWitnessProgramSize> program{};
  if (!script::ExtractWitnessProgram(script, &program)) {
    return false;
  }
  primitives::Hash256 program_hash{};
  std::copy(program.begin(), program.end(), program_hash.begin());
  // Prefer treating outputs as spendable if they belong to a known
  // HD-derived address, falling back to watch-only tracking when the
  // script matches a registered watch-only descriptor.
  auto it = program_index_.find(program_hash);
  if (it != program_index_.end()) {
    const auto& entry = addresses_[it->second];
    WalletUTXO utxo;
    utxo.outpoint.txid = txid;
    utxo.outpoint.index = static_cast<std::uint32_t>(vout_index);
    utxo.txout = txout;
    utxo.key_index = entry.index;
    utxo.algorithm = entry.algorithm;
    utxo.watch_only = false;
    return AddUTXO(utxo, is_coinbase, tx_fee_miks);
  }
  auto it_watch = watch_only_program_index_.find(program_hash);
  if (it_watch == watch_only_program_index_.end()) {
    return false;
  }
  const auto& watch_entry = watch_only_[it_watch->second];
  WalletUTXO utxo;
  utxo.outpoint.txid = txid;
  utxo.outpoint.index = static_cast<std::uint32_t>(vout_index);
  utxo.txout = txout;
  utxo.key_index = 0;
  utxo.algorithm = watch_entry.descriptor.algorithm;
  utxo.watch_only = true;
  return AddUTXO(utxo, is_coinbase, tx_fee_miks);
}

HDWallet::KeyMaterial HDWallet::DeriveKeyMaterial(std::uint32_t index,
                                                  crypto::SignatureAlgorithm /*algorithm*/) const {
  KeyMaterial material;
  material.algorithm = crypto::SignatureAlgorithm::kDilithium;

  // Deterministically derive an ML-DSA-65 keypair from the wallet master
  // seed and child index using a SHAKE256 XOF as the byte stream feeding
  // liboqs key generation.
  const auto drbg_seed = DeriveMldsaKeygenSeed(seed_, index);
  crypto::DeterministicOqsRng dil_rng(
      std::span<const std::uint8_t>(drbg_seed.data(), drbg_seed.size()),
      crypto::DeterministicOqsRng::Mode::kShake256Xof);
  material.dilithium.emplace(crypto::QPqDilithiumKey::Generate());

  const auto dil_span = material.dilithium->PublicKey();
  material.reveal = crypto::BuildP2QHReveal(dil_span);
  material.descriptor = crypto::DescriptorFromReveal(material.reveal);
  return material;
}

std::string HDWallet::DeriveAddressInternal(std::uint32_t index,
                                            crypto::SignatureAlgorithm algorithm) {
  auto material = DeriveKeyMaterial(index, algorithm);
  return crypto::EncodeP2QHAddress(material.descriptor, config::GetNetworkConfig().bech32_hrp);
}

HDWallet::AddressEntry* HDWallet::FindAddressEntry(const std::string& address) {
  auto it = address_index_.find(address);
  if (it == address_index_.end()) {
    return nullptr;
  }
  return &addresses_[it->second];
}

const HDWallet::AddressEntry* HDWallet::FindAddressEntry(const std::string& address) const {
  auto it = address_index_.find(address);
  if (it == address_index_.end()) {
    return nullptr;
  }
  return &addresses_[it->second];
}

void HDWallet::IndexAddress(std::size_t idx) {
  const auto& entry = addresses_[idx];
  address_index_[entry.address] = idx;
  program_index_[entry.program] = idx;
}

std::optional<HDWallet::AddressEntry> HDWallet::RebuildEntry(std::uint32_t index,
                                                             crypto::SignatureAlgorithm algorithm,
                                                             const std::string& address) {
  auto material = DeriveKeyMaterial(index, algorithm);
  AddressEntry entry;
  entry.index = index;
  entry.algorithm = algorithm;
  entry.descriptor = material.descriptor;
  entry.program = material.descriptor.program;
  entry.address =
      crypto::EncodeP2QHAddress(entry.descriptor, config::GetNetworkConfig().bech32_hrp);
  if (!address.empty() && entry.address != address) {
    return std::nullopt;
  }
  return entry;
}

void HDWallet::RecordTransaction(const WalletTransaction& tx) {
  transactions_.push_back(tx);
  if (transactions_.size() > 1000) {
    transactions_.erase(transactions_.begin(),
                        transactions_.begin() + (transactions_.size() - 1000));
  }
}

std::uint64_t HDWallet::Now() const {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::optional<CreatedTransaction> HDWallet::CreateTransaction(
    const std::vector<std::pair<std::string, primitives::Amount>>& outputs,
    primitives::Amount fee_rate, std::string* error) {
  if (locked_) {
    if (error) *error = "wallet is locked";
    return std::nullopt;
  }
  if (!primitives::MoneyRange(fee_rate)) {
    if (error) *error = "fee rate out of range";
    return std::nullopt;
  }
  primitives::Amount total_output = 0;
  struct OutputTarget {
    crypto::P2QHDescriptor descriptor;
    primitives::Amount value{0};
  };
  std::vector<OutputTarget> targets;
  targets.reserve(outputs.size());
  for (const auto& out : outputs) {
    if (!primitives::MoneyRange(out.second)) {
      if (error) *error = "output value out of range";
      return std::nullopt;
    }
    crypto::P2QHDescriptor descriptor{};
    if (!crypto::DecodeP2QHAddress(out.first, config::GetNetworkConfig().bech32_hrp,
                                   &descriptor)) {
      if (error) *error = "invalid recipient address";
      return std::nullopt;
    }
    primitives::Amount next = 0;
    if (!primitives::CheckedAdd(total_output, out.second, &next)) {
      if (error) *error = "output total out of range";
      return std::nullopt;
    }
    total_output = next;
    targets.push_back(OutputTarget{descriptor, out.second});
  }
  std::vector<std::size_t> selected;
  primitives::Amount accumulated = 0;
  primitives::Amount fee = 0;
  primitives::Amount needed = total_output;
  auto need_more = [&]() -> bool {
    const std::uint64_t estimate_inputs = static_cast<std::uint64_t>(selected.size()) + 1;
    const std::uint64_t estimate_outputs = static_cast<std::uint64_t>(targets.size()) + 1;
    const std::uint64_t estimated_vbytes =
        EstimateTransactionVBytes(estimate_inputs, estimate_outputs, default_algorithm_);
    if (estimated_vbytes == 0) {
      return false;
    }
    primitives::Amount next_fee = 0;
    if (!primitives::CheckedMul(fee_rate, estimated_vbytes, &next_fee)) {
      return false;
    }
    primitives::Amount next_needed = 0;
    if (!primitives::CheckedAdd(total_output, next_fee, &next_needed)) {
      return false;
    }
    fee = next_fee;
    needed = next_needed;
    return true;
  };
  if (!need_more()) {
    if (error) *error = "fee computation overflow";
    return std::nullopt;
  }

  struct Candidate {
    std::size_t index{0};
    primitives::Amount value{0};
    bool is_change{false};
    bool coinbase{false};
  };

  std::vector<Candidate> candidates;
  candidates.reserve(utxos_.size());
  std::unordered_map<std::uint32_t, Candidate> best_by_key;
  best_by_key.reserve(utxos_.size());
  for (std::size_t i = 0; i < utxos_.size(); ++i) {
    const auto& utxo = utxos_[i];
    if (utxo.spent || utxo.watch_only || utxo.txout.value == 0) {
      continue;
    }
    if (IsKeyBurned(utxo.key_index)) {
      continue;
    }
    Candidate candidate{i, utxo.txout.value, utxo.is_change, utxo.coinbase};
    const auto key_index = utxo.key_index;
    auto it = best_by_key.find(key_index);
    if (it == best_by_key.end()) {
      best_by_key.emplace(key_index, candidate);
      continue;
    }
    const auto& best = it->second;
    if (candidate.value > best.value ||
        (candidate.value == best.value && candidate.index < best.index)) {
      it->second = candidate;
    }
  }
  for (const auto& kv : best_by_key) {
    candidates.push_back(kv.second);
  }

  std::sort(candidates.begin(), candidates.end(),
            [](const Candidate& a, const Candidate& b) {
              auto priority = [](const Candidate& c) {
                // Prefer spending non-coinbase change first to consolidate
                // wallet-local change, then regular non-coinbase funds, and
                // defer coinbase outputs until needed.
                if (c.is_change && !c.coinbase) return 0;
                if (!c.is_change && !c.coinbase) return 1;
                if (c.is_change && c.coinbase) return 2;
                return 3;  // non-change coinbase last
              };
              const int pa = priority(a);
              const int pb = priority(b);
              if (pa != pb) {
                return pa < pb;
              }
              if (a.value != b.value) {
                // Within the same priority bucket, prefer larger inputs so
                // typical spends use fewer inputs and pay lower fees.
                return a.value > b.value;
              }
              return a.index < b.index;
            });

  // First try a small branch-and-bound style search over the sorted
  // candidate set to find a subset whose total value is close to the
  // target. This prefers exact (or near-exact) matches and reduces the
  // need for change outputs when feasible. Fees are handled via the
  // existing size-based estimator; if the BnB selection cannot cover
  // both outputs and the fee, we fall back to the greedy strategy.
  if (!candidates.empty() && candidates.size() <= kMaxBranchAndBoundInputs) {
    BnbSelection sel;
    std::vector<bool> choice(candidates.size(), false);
    BranchAndBoundDfs(candidates, /*idx=*/0, total_output,
                      /*current_sum=*/0, &choice, &sel);
    if (sel.found) {
      selected = sel.chosen_indices;
      accumulated = sel.best_sum;
      if (!need_more()) {
        if (error) *error = "fee computation overflow";
        return std::nullopt;
      }
      if (accumulated < needed) {
        // Not enough value once fees are taken into account; discard
        // the BnB selection and fall back to the greedy strategy.
        selected.clear();
        accumulated = 0;
        fee = 0;
        needed = total_output;
        if (!need_more()) {
          if (error) *error = "fee computation overflow";
          return std::nullopt;
        }
      }
    }
  }

  // Greedy fallback: sweep UTXOs in priority order until the target
  // (including estimated fees) is met.
  if (selected.empty()) {
    for (const auto& cand : candidates) {
      selected.push_back(cand.index);
      primitives::Amount next_accumulated = 0;
      if (!primitives::CheckedAdd(accumulated, cand.value, &next_accumulated)) {
        if (error) *error = "input amount out of range";
        return std::nullopt;
      }
      accumulated = next_accumulated;
      if (accumulated >= needed) break;
      if (!need_more()) {
        if (error) *error = "fee computation overflow";
        return std::nullopt;
      }
    }
  }
  if (accumulated < needed) {
    if (error) *error = "insufficient funds";
    return std::nullopt;
  }
  primitives::Amount change = 0;
  if (!primitives::CheckedSub(accumulated, needed, &change)) {
    if (error) *error = "change underflow";
    return std::nullopt;
  }
  bool add_change_output = change > 0;
  if (add_change_output && change <= kDustChangeThreshold) {
    // Avoid creating uneconomical "dust" change outputs. Instead, fold very
    // small change back into the fee so the resulting transaction is simpler
    // and the effective feerate is slightly higher than requested.
    primitives::Amount next_fee = 0;
    if (!primitives::CheckedAdd(fee, change, &next_fee)) {
      if (error) *error = "fee out of range";
      return std::nullopt;
    }
    fee = next_fee;
    change = 0;
    add_change_output = false;
  }

  primitives::CTransaction tx;
  tx.version = 1;
  for (auto index : selected) {
    primitives::CTxIn in;
    in.prevout = utxos_[index].outpoint;
    in.sequence = 0xFFFFFFFF;
    tx.vin.push_back(in);
  }
  for (const auto& target : targets) {
    primitives::CTxOut out;
    out.value = target.value;
    auto script = script::CreateP2QHScript(target.descriptor);
    out.locking_descriptor = script.data;
    tx.vout.push_back(out);
  }
  if (add_change_output && change > 0) {
    auto change_address = NewAddress();
    crypto::P2QHDescriptor descriptor;
    crypto::DecodeP2QHAddress(change_address, config::GetNetworkConfig().bech32_hrp, &descriptor);
    primitives::CTxOut change_out;
    change_out.value = change;
    change_out.locking_descriptor = script::CreateP2QHScript(descriptor).data;
    tx.vout.push_back(change_out);
  }

  for (std::size_t idx = 0; idx < selected.size(); ++idx) {
    auto& utxo = utxos_[selected[idx]];
    consensus::Coin coin;
    coin.out = utxo.txout;
    auto sighash = consensus::ComputeSighash(tx, idx, coin);
    auto material = DeriveKeyMaterial(utxo.key_index, crypto::SignatureAlgorithm::kDilithium);
    std::vector<primitives::WitnessStackItem> witness_items;
    witness_items.push_back(primitives::WitnessStackItem{material.reveal});
    const auto msg_span = std::span<const std::uint8_t>(sighash.data(), sighash.size());
    if (!material.dilithium.has_value()) {
      if (error) *error = "missing Dilithium key material";
      return std::nullopt;
    }
    witness_items.push_back(primitives::WitnessStackItem{material.dilithium->Sign(msg_span)});
    tx.vin[idx].witness_stack = std::move(witness_items);
  }

  CreatedTransaction created;
  created.fee = fee;
  primitives::Amount sent_total = 0;
  if (!primitives::CheckedAdd(total_output, fee, &sent_total)) {
    sent_total = primitives::kMaxMoney;
  }
  created.sent_total = sent_total;
  created.spent_outpoints.reserve(selected.size());
  for (auto index : selected) {
    created.spent_outpoints.push_back(utxos_[index].outpoint);
  }

  if (change > 0 && add_change_output) {
    const auto txid_vec = primitives::ComputeTxId(tx);
    primitives::COutPoint change_outpoint;
    std::copy(txid_vec.begin(), txid_vec.end(), change_outpoint.txid.begin());
    change_outpoint.index = static_cast<std::uint32_t>(tx.vout.size() - 1);
    WalletUTXO change_utxo;
    change_utxo.outpoint = change_outpoint;
    change_utxo.txout = tx.vout.back();
    change_utxo.key_index = next_index_ - 1;
    change_utxo.algorithm = default_algorithm_;
    change_utxo.spent = false;
    change_utxo.is_change = true;
    change_utxo.coinbase = false;
    created.change_utxo = change_utxo;
  }

  created.tx = std::move(tx);
  return created;
}

bool HDWallet::CommitTransaction(const CreatedTransaction& created, std::string* error) {
  if (created.spent_outpoints.empty()) {
    if (error) *error = "no inputs selected";
    return false;
  }

  for (const auto& outpoint : created.spent_outpoints) {
    bool found = false;
    for (auto& utxo : utxos_) {
      if (utxo.outpoint.txid == outpoint.txid && utxo.outpoint.index == outpoint.index) {
        utxo.spent = true;
        if (!utxo.watch_only) {
          BurnKeyIndex(utxo.key_index);
        }
        found = true;
        break;
      }
    }
    if (!found) {
      if (error) *error = "missing utxo for spend";
      return false;
    }
  }

  if (created.change_utxo.has_value()) {
    const auto& utxo = *created.change_utxo;
    bool exists = false;
    for (const auto& existing : utxos_) {
      if (existing.outpoint.txid == utxo.outpoint.txid &&
          existing.outpoint.index == utxo.outpoint.index) {
        exists = true;
        break;
      }
    }
    if (!exists) {
      utxos_.push_back(utxo);
    }
  }

  WalletTransaction event;
  const auto txid = primitives::ComputeTxId(created.tx);
  event.txid = util::HexEncode(std::span<const std::uint8_t>(txid.data(), txid.size()));
  event.amount = created.sent_total;
  event.incoming = false;
  event.timestamp = Now();
  event.label = "Send";
  event.fee = created.fee;
  event.confirmations = 0;
  event.coinbase = false;
  RecordTransaction(event);

  return true;
}

bool HDWallet::Save() const {
  auto payload = SerializeState();
  const bool ok = EncryptAndWrite(payload);
  util::SecureWipe(payload);
  return ok;
}

std::string HDWallet::ExportSeedHex() const { return ArrayToHex(seed_); }

bool HDWallet::CreateFresh(const std::string& path, const std::string& password,
                           crypto::SignatureAlgorithm default_algo) {
  last_error_.clear();
  if (password.empty()) {
    last_error_ = "passphrase cannot be empty";
    return false;
  }
  util::SecureWipe(password_);
  util::SecureWipe(seed_);
  wallet_path_ = path;
  password_ = password;
  wallet_format_version_ = kWalletVersion;
  derivation_scheme_ = DerivationScheme::kSha3Ctr;
  default_algorithm_ = default_algo;
  next_index_ = 0;
  addresses_.clear();
  address_index_.clear();
  program_index_.clear();
  utxos_.clear();
  burned_key_indices_.clear();
  transactions_.clear();
  watch_only_.clear();
  watch_only_address_index_.clear();
  watch_only_program_index_.clear();
  payment_code_reservations_.clear();
  in_memory_ = false;
  auto seed_bytes = RandomBytes(seed_.size());
  std::copy_n(seed_bytes.begin(), seed_.size(), seed_.begin());
  util::SecureWipe(seed_bytes);
  locked_ = false;
  if (!Save()) {
    if (last_error_.empty()) {
      last_error_ = "failed to write wallet file";
    }
    return false;
  }
  last_error_.clear();
  return true;
}

bool HDWallet::LoadFromFile(const std::string& path, const std::string& password) {
  last_error_.clear();
  if (path.empty()) {
    last_error_ = "wallet path is empty";
    return false;
  }
  if (password.empty()) {
    last_error_ = "passphrase cannot be empty";
    return false;
  }

  std::string error;
  auto loaded = HDWallet::Load(path, password, &error);
  if (!loaded) {
    last_error_ = error.empty() ? "failed to read wallet" : error;
    return false;
  }

  util::SecureWipe(password_);
  util::SecureWipe(seed_);
  *this = *loaded;
  last_error_.clear();
  return true;
}

bool HDWallet::BackupTo(const std::string& destination) const {
  try {
    const auto parent = std::filesystem::path(destination).parent_path();
    if (!parent.empty()) {
      std::error_code ec;
      std::filesystem::create_directories(parent, ec);
      if (ec) {
        return false;
      }
    }
    std::filesystem::copy_file(wallet_path_, destination,
                               std::filesystem::copy_options::overwrite_existing);
    return true;
  } catch (...) {
    return false;
  }
}

bool HDWallet::ChangePassphrase(const std::string& new_passphrase) {
  if (new_passphrase.empty()) {
    return false;
  }
  util::SecureWipe(password_);
  password_ = new_passphrase;
  return Save();
}

void HDWallet::Lock() {
  locked_ = true;
  util::SecureWipe(password_);
}

bool HDWallet::Unlock(const std::string& passphrase) {
  if (wallet_path_.empty() || passphrase.empty()) {
    return false;
  }
  auto tmp = HDWallet::Load(wallet_path_, passphrase);
  if (!tmp) {
    return false;
  }
  util::SecureWipe(password_);
  password_ = passphrase;
  locked_ = false;
  return true;
}

std::vector<std::uint8_t> HDWallet::SerializeState() const {
  std::vector<std::uint8_t> buffer;
  const bool legacy_varint = (wallet_format_version_ <= 4);
  auto write_varint = [&](std::uint64_t value) {
    if (legacy_varint) {
      primitives::serialize::WriteVarIntLegacy(&buffer, value);
    } else {
      primitives::serialize::WriteVarInt(&buffer, value);
    }
  };
  buffer.insert(buffer.end(), seed_.begin(), seed_.end());
  primitives::serialize::WriteUint32(&buffer, next_index_);
  buffer.push_back(crypto::EncodeSignatureAlgorithm(default_algorithm_));
  write_varint(addresses_.size());
  for (const auto& entry : addresses_) {
    primitives::serialize::WriteUint32(&buffer, entry.index);
    buffer.push_back(crypto::EncodeSignatureAlgorithm(entry.algorithm));
    write_varint(entry.address.size());
    buffer.insert(buffer.end(), entry.address.begin(), entry.address.end());
  }
  write_varint(utxos_.size());
  for (const auto& utxo : utxos_) {
    buffer.insert(buffer.end(), utxo.outpoint.txid.begin(), utxo.outpoint.txid.end());
    primitives::serialize::WriteUint32(&buffer, utxo.outpoint.index);
    primitives::serialize::WriteUint64(&buffer, utxo.txout.value);
    write_varint(utxo.txout.locking_descriptor.size());
    buffer.insert(buffer.end(), utxo.txout.locking_descriptor.begin(),
                  utxo.txout.locking_descriptor.end());
    primitives::serialize::WriteUint32(&buffer, utxo.key_index);
    buffer.push_back(crypto::EncodeSignatureAlgorithm(utxo.algorithm));
    buffer.push_back(static_cast<std::uint8_t>(utxo.spent));
    buffer.push_back(static_cast<std::uint8_t>(utxo.watch_only));
  }
  // Persist the set of watch-only addresses as a simple list of
  // bech32m-encoded P2QH addresses. On load, these are decoded back
  // into descriptors and witness-program hashes.
  write_varint(watch_only_.size());
  for (const auto& entry : watch_only_) {
    write_varint(entry.address.size());
    buffer.insert(buffer.end(), entry.address.begin(), entry.address.end());
  }
  // Optional wallet metadata (birth/scan heights). Append in a tagged trailer so
  // older binaries that stop parsing after the UTXO set remain compatible.
  std::uint8_t flags = 0;
  if (birth_height_.has_value()) {
    flags |= 0x01;
  }
  if (last_scan_height_.has_value()) {
    flags |= 0x02;
  }
  if (flags != 0) {
    buffer.push_back(0x01);  // metadata tag v1
    buffer.push_back(flags);
    if (birth_height_.has_value()) {
      primitives::serialize::WriteUint32(&buffer, *birth_height_);
    }
    if (last_scan_height_.has_value()) {
      primitives::serialize::WriteUint32(&buffer, *last_scan_height_);
    }
  }
  // Persist UTXO attributes (coinbase/change) in a tagged trailer so older
  // wallet binaries can ignore it safely.
  buffer.push_back(0x02);  // utxo flags tag v1
  write_varint(utxos_.size());
  for (const auto& utxo : utxos_) {
    buffer.insert(buffer.end(), utxo.outpoint.txid.begin(), utxo.outpoint.txid.end());
    primitives::serialize::WriteUint32(&buffer, utxo.outpoint.index);
    std::uint8_t utxo_flags = 0;
    if (utxo.coinbase) utxo_flags |= 0x01;
    if (utxo.is_change) utxo_flags |= 0x02;
    buffer.push_back(utxo_flags);
  }
  if (!burned_key_indices_.empty()) {
    buffer.push_back(0x03);  // burned key indices tag v1
    write_varint(burned_key_indices_.size());
    for (const auto key_index : burned_key_indices_) {
      primitives::serialize::WriteUint32(&buffer, key_index);
    }
  }
  if (!payment_code_reservations_.empty()) {
    buffer.push_back(0x04);  // payment code reservations tag v1
    write_varint(payment_code_reservations_.size());
    for (const auto& reservation : payment_code_reservations_) {
      primitives::serialize::WriteUint32(&buffer, reservation.key_index);
      primitives::serialize::WriteUint64(&buffer, reservation.issued_time);
      primitives::serialize::WriteUint32(&buffer, reservation.issued_height);
      primitives::serialize::WriteUint32(&buffer, reservation.expiry_height);
      buffer.insert(buffer.end(), reservation.challenge.begin(), reservation.challenge.end());
      buffer.push_back(static_cast<std::uint8_t>(reservation.status));
    }
  }
  return buffer;
}

bool HDWallet::DeserializeState(const std::vector<std::uint8_t>& payload, std::uint16_t version) {
  last_error_.clear();
  auto fail = [&](std::string message) -> bool {
    last_error_ = std::move(message);
    return false;
  };

  if (version < kMinWalletVersion || version > kWalletVersion) {
    return fail("unsupported wallet state version " + std::to_string(version));
  }
  wallet_format_version_ = version;
  derivation_scheme_ = (version <= 4) ? DerivationScheme::kLegacyMt19937
                                      : DerivationScheme::kSha3Ctr;
  const bool legacy_varint = (version <= 4);
  std::size_t offset = 0;

  if (payload.size() < seed_.size()) {
    return fail("wallet payload truncated (seed)");
  }
  std::copy(payload.begin(), payload.begin() + seed_.size(), seed_.begin());
  offset += seed_.size();

  if (!primitives::serialize::ReadUint32(payload, &offset, &next_index_)) {
    return fail("wallet payload truncated (next key index)");
  }
  if (offset >= payload.size()) {
    return fail("wallet payload truncated (default policy byte)");
  }
  try {
    default_algorithm_ = crypto::DecodeSignatureAlgorithm(payload[offset++]);
  } catch (const std::exception&) {
    return fail("wallet payload contains invalid default signature policy id");
  }

  auto read_varint = [&](std::uint64_t* out) -> bool {
    return legacy_varint ? primitives::serialize::ReadVarIntLegacy(payload, &offset, out)
                         : primitives::serialize::ReadVarInt(payload, &offset, out);
  };

  std::uint64_t address_count = 0;
  if (!read_varint(&address_count)) {
    return fail("wallet payload invalid varint (address count)");
  }
  addresses_.clear();
  address_index_.clear();
  program_index_.clear();
  for (std::uint64_t i = 0; i < address_count; ++i) {
    AddressEntry entry;
    if (!primitives::serialize::ReadUint32(payload, &offset, &entry.index)) {
      return fail("wallet payload truncated (address index)");
    }
    if (offset >= payload.size()) {
      return fail("wallet payload truncated (address policy id)");
    }
    try {
      entry.algorithm = crypto::DecodeSignatureAlgorithm(payload[offset++]);
    } catch (const std::exception&) {
      return fail("wallet payload contains invalid address signature policy id");
    }
    std::uint64_t addr_len = 0;
    if (!read_varint(&addr_len)) {
      return fail("wallet payload invalid varint (address length)");
    }
    if (addr_len > payload.size() - offset) {
      return fail("wallet payload truncated (address bytes)");
    }
    const std::size_t addr_size = static_cast<std::size_t>(addr_len);
    entry.address.assign(reinterpret_cast<const char*>(payload.data() + offset), addr_size);
    offset += addr_size;

    auto rebuilt = RebuildEntry(entry.index, entry.algorithm, entry.address);
    if (!rebuilt) {
      std::string expected;
      try {
        expected = DeriveAddressInternal(entry.index, entry.algorithm);
      } catch (...) {
        expected = "<derivation failed>";
      }
      return fail("wallet address derivation mismatch at index " + std::to_string(entry.index) +
                  " (stored=" + entry.address + ", expected=" + expected +
                  "); check network selection and wallet compatibility");
    }
    addresses_.push_back(*rebuilt);
    IndexAddress(addresses_.size() - 1);
  }

  std::uint64_t utxo_count = 0;
  if (!read_varint(&utxo_count)) {
    return fail("wallet payload invalid varint (utxo count)");
  }
  utxos_.clear();
  for (std::uint64_t i = 0; i < utxo_count; ++i) {
    WalletUTXO utxo;
    if (offset + utxo.outpoint.txid.size() > payload.size()) {
      return fail("wallet payload truncated (utxo txid)");
    }
    std::copy(payload.begin() + offset, payload.begin() + offset + utxo.outpoint.txid.size(),
              utxo.outpoint.txid.begin());
    offset += utxo.outpoint.txid.size();
    if (!primitives::serialize::ReadUint32(payload, &offset, &utxo.outpoint.index)) {
      return fail("wallet payload truncated (utxo outpoint index)");
    }
    std::uint64_t value = 0;
    if (!primitives::serialize::ReadUint64(payload, &offset, &value)) {
      return fail("wallet payload truncated (utxo value)");
    }
    if (value > primitives::kMaxMoney) {
      return fail("wallet payload contains out-of-range utxo value");
    }
    utxo.txout.value = static_cast<primitives::Amount>(value);
    std::uint64_t script_len = 0;
    if (!read_varint(&script_len)) {
      return fail("wallet payload invalid varint (utxo script length)");
    }
    if (script_len > payload.size() - offset) {
      return fail("wallet payload truncated (utxo script bytes)");
    }
    const std::size_t script_size = static_cast<std::size_t>(script_len);
    utxo.txout.locking_descriptor.assign(payload.begin() + offset,
                                         payload.begin() + offset + script_size);
    offset += script_size;
    if (!primitives::serialize::ReadUint32(payload, &offset, &utxo.key_index)) {
      return fail("wallet payload truncated (utxo key index)");
    }
    const std::size_t flags_bytes = (version >= 3) ? 3 : 2;
    if (offset + flags_bytes > payload.size()) {
      return fail("wallet payload truncated (utxo flags)");
    }
    try {
      utxo.algorithm = crypto::DecodeSignatureAlgorithm(payload[offset++]);
    } catch (const std::exception&) {
      return fail("wallet payload contains invalid utxo signature policy id");
    }
    utxo.spent = payload[offset++] != 0;
    if (version >= 3) {
      utxo.watch_only = payload[offset++] != 0;
    } else {
      utxo.watch_only = false;
    }
    utxos_.push_back(utxo);
  }

  // Rebuild the watch-only address set. Older wallet versions did not
  // persist this information, so they simply leave the set empty.
  watch_only_.clear();
  watch_only_address_index_.clear();
  watch_only_program_index_.clear();
  if (version >= 4 && offset < payload.size()) {
    std::uint64_t watch_count = 0;
    if (!read_varint(&watch_count)) {
      return fail("wallet payload invalid varint (watch-only count)");
    }
    for (std::uint64_t i = 0; i < watch_count; ++i) {
      std::uint64_t addr_len = 0;
      if (!read_varint(&addr_len)) {
        return fail("wallet payload invalid varint (watch-only address length)");
      }
      if (addr_len > payload.size() - offset) {
        return fail("wallet payload truncated (watch-only address bytes)");
      }
      std::string address(reinterpret_cast<const char*>(payload.data() + offset),
                          static_cast<std::size_t>(addr_len));
      offset += static_cast<std::size_t>(addr_len);
      crypto::P2QHDescriptor descriptor{};
      if (!crypto::DecodeP2QHAddress(address, config::GetNetworkConfig().bech32_hrp, &descriptor)) {
        return fail("wallet payload contains invalid watch-only address " + address);
      }
      WatchOnlyEntry entry;
      entry.address = address;
      entry.descriptor = descriptor;
      entry.program = descriptor.program;
      const std::size_t idx = watch_only_.size();
      watch_only_.push_back(entry);
      watch_only_address_index_[address] = idx;
      watch_only_program_index_[entry.program] = idx;
    }
  }

  birth_height_.reset();
  last_scan_height_.reset();
  burned_key_indices_.clear();
  payment_code_reservations_.clear();

  auto apply_utxo_flags = [&](const primitives::COutPoint& outpoint,
                              std::uint8_t flags) {
    for (auto& utxo : utxos_) {
      if (utxo.outpoint.txid == outpoint.txid && utxo.outpoint.index == outpoint.index) {
        utxo.coinbase = (flags & 0x01) != 0;
        utxo.is_change = (flags & 0x02) != 0;
        break;
      }
    }
  };

  while (offset < payload.size()) {
    const std::uint8_t tag = payload[offset++];
    if (tag == 0x01) {
      if (offset >= payload.size()) {
        return fail("wallet payload truncated (metadata flags)");
      }
      const std::uint8_t flags = payload[offset++];
      if (flags & 0x01) {
        std::uint32_t value = 0;
        if (!primitives::serialize::ReadUint32(payload, &offset, &value)) {
          return fail("wallet payload truncated (birth height)");
        }
        birth_height_ = value;
      }
      if (flags & 0x02) {
        std::uint32_t value = 0;
        if (!primitives::serialize::ReadUint32(payload, &offset, &value)) {
          return fail("wallet payload truncated (last scan height)");
        }
        last_scan_height_ = value;
      }
      continue;
    }
    if (tag == 0x02) {
      std::uint64_t count = 0;
      if (!read_varint(&count)) {
        return fail("wallet payload invalid varint (utxo flags count)");
      }
      for (std::uint64_t i = 0; i < count; ++i) {
        primitives::COutPoint outpoint;
        if (offset + outpoint.txid.size() > payload.size()) {
          return fail("wallet payload truncated (utxo flags txid)");
        }
        std::copy(payload.begin() + offset,
                  payload.begin() + offset + outpoint.txid.size(),
                  outpoint.txid.begin());
        offset += outpoint.txid.size();
        if (!primitives::serialize::ReadUint32(payload, &offset, &outpoint.index)) {
          return fail("wallet payload truncated (utxo flags index)");
        }
        if (offset >= payload.size()) {
          return fail("wallet payload truncated (utxo flags byte)");
        }
        const std::uint8_t flags = payload[offset++];
        apply_utxo_flags(outpoint, flags);
      }
      continue;
    }
    if (tag == 0x03) {
      std::uint64_t count = 0;
      if (!read_varint(&count)) {
        return fail("wallet payload invalid varint (burned keys count)");
      }
      if (count > (payload.size() - offset) / 4) {
        return fail("wallet payload truncated (burned keys)");
      }
      burned_key_indices_.reserve(static_cast<std::size_t>(count));
      for (std::uint64_t i = 0; i < count; ++i) {
        std::uint32_t key_index = 0;
        if (!primitives::serialize::ReadUint32(payload, &offset, &key_index)) {
          return fail("wallet payload truncated (burned key index)");
        }
        burned_key_indices_.push_back(key_index);
      }
      std::sort(burned_key_indices_.begin(), burned_key_indices_.end());
      auto dup = std::adjacent_find(burned_key_indices_.begin(), burned_key_indices_.end());
      if (dup != burned_key_indices_.end()) {
        return fail("wallet payload contains duplicate burned key indices");
      }
      continue;
    }
    if (tag == 0x04) {
      std::uint64_t count = 0;
      if (!read_varint(&count)) {
        return fail("wallet payload invalid varint (payment code reservations count)");
      }
      constexpr std::size_t kReservationBytes = 4 + 8 + 4 + 4 + 16 + 1;
      if (count > (payload.size() - offset) / kReservationBytes) {
        return fail("wallet payload truncated (payment code reservations)");
      }
      payment_code_reservations_.reserve(static_cast<std::size_t>(count));
      for (std::uint64_t i = 0; i < count; ++i) {
        PaymentCodeReservation r;
        if (!primitives::serialize::ReadUint32(payload, &offset, &r.key_index)) {
          return fail("wallet payload truncated (reservation key index)");
        }
        if (!primitives::serialize::ReadUint64(payload, &offset, &r.issued_time)) {
          return fail("wallet payload truncated (reservation issued time)");
        }
        if (!primitives::serialize::ReadUint32(payload, &offset, &r.issued_height)) {
          return fail("wallet payload truncated (reservation issued height)");
        }
        if (!primitives::serialize::ReadUint32(payload, &offset, &r.expiry_height)) {
          return fail("wallet payload truncated (reservation expiry height)");
        }
        if (offset + r.challenge.size() > payload.size()) {
          return fail("wallet payload truncated (reservation challenge)");
        }
        std::copy(payload.begin() + offset,
                  payload.begin() + offset + r.challenge.size(),
                  r.challenge.begin());
        offset += r.challenge.size();
        if (offset >= payload.size()) {
          return fail("wallet payload truncated (reservation status)");
        }
        const std::uint8_t status = payload[offset++];
        if (status > static_cast<std::uint8_t>(PaymentCodeReservationStatus::kExpired)) {
          return fail("wallet payload contains invalid reservation status");
        }
        r.status = static_cast<PaymentCodeReservationStatus>(status);
        payment_code_reservations_.push_back(r);
      }
      continue;
    }
    // Unknown tagged trailer; stop parsing for forward compatibility.
    break;
  }

  if (version < 7) {
    std::unordered_set<std::uint32_t> burned;
    burned.reserve(utxos_.size());
    for (const auto& utxo : utxos_) {
      if (utxo.spent && !utxo.watch_only) {
        burned.insert(utxo.key_index);
      }
    }
    if (!burned.empty()) {
      burned_key_indices_.assign(burned.begin(), burned.end());
      std::sort(burned_key_indices_.begin(), burned_key_indices_.end());
    }
  }

  if (wallet_format_version_ < kWalletVersion) {
    wallet_format_version_ = kWalletVersion;
  }
  last_error_.clear();
  return true;
}

bool HDWallet::EncryptAndWrite(const std::vector<std::uint8_t>& payload) const {
  last_error_.clear();
  // For new wallets, derive the encryption key with Argon2id; legacy wallets
  // that were written with the original HMAC-SHA3 KDF use reserved=0 and are
  // still readable via ReadAndDecrypt.
  std::vector<std::uint8_t> header_salt(32);
  std::vector<std::uint8_t> key;
  std::vector<std::uint8_t> nonce =
      RandomBytes(util::kChaCha20Poly1305NonceSize);

  const auto params = util::DefaultArgon2idParams();
  // First 16 bytes: random salt for Argon2id.
  auto argon_salt = RandomBytes(16);
  std::copy(argon_salt.begin(), argon_salt.end(), header_salt.begin());
  // Next 12 bytes encode Argon2 parameters (little-endian UInt32).
  auto encode_u32 = [&](std::uint32_t value, std::size_t offset) {
    header_salt[offset + 0] = static_cast<std::uint8_t>(value & 0xFF);
    header_salt[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    header_salt[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    header_salt[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
  };
  encode_u32(params.t_cost, 16);
  encode_u32(params.m_cost_kib, 20);
  encode_u32(params.parallelism, 24);
  // Remaining 4 bytes stay zero-reserved.

  if (!util::DeriveKeyArgon2id(password_,
                               std::span<const std::uint8_t>(argon_salt.data(),
                                                             argon_salt.size()),
                               params, &key)) {
    last_error_ = "wallet key derivation failed";
    util::SecureWipe(key);
    return false;
  }

  auto ciphertext = util::ChaCha20Poly1305Encrypt(
      std::span<const std::uint8_t>(key.data(), key.size()),
      std::span<const std::uint8_t>(nonce.data(), nonce.size()),
      std::span<const std::uint8_t>(header_salt.data(), header_salt.size()),
      std::span<const std::uint8_t>(payload.data(), payload.size()));
  if (ciphertext.size() > std::numeric_limits<std::uint32_t>::max()) {
    last_error_ = "wallet ciphertext too large";
    util::SecureWipe(key);
    return false;
  }
  std::vector<std::uint8_t> file;
  file.reserve(4 + 2 + 2 + header_salt.size() + nonce.size() + 4 + ciphertext.size());
  primitives::serialize::WriteUint32(&file, kWalletMagic);
  const auto version = wallet_format_version_;
  file.push_back(static_cast<std::uint8_t>(version & 0xFFu));
  file.push_back(static_cast<std::uint8_t>((version >> 8) & 0xFFu));
  const std::uint16_t reserved = static_cast<std::uint16_t>(WalletKdf::kArgon2id);
  file.push_back(static_cast<std::uint8_t>(reserved & 0xFFu));
  file.push_back(static_cast<std::uint8_t>((reserved >> 8) & 0xFFu));
  file.insert(file.end(), header_salt.begin(), header_salt.end());
  file.insert(file.end(), nonce.begin(), nonce.end());
  primitives::serialize::WriteUint32(&file, static_cast<std::uint32_t>(ciphertext.size()));
  file.insert(file.end(), ciphertext.begin(), ciphertext.end());

  std::string write_error;
  if (!util::AtomicWriteFileBytes(std::filesystem::path(wallet_path_), file, &write_error)) {
    last_error_ = write_error.empty() ? "wallet write failed" : write_error;
    util::SecureWipe(key);
    return false;
  }
  util::SecureWipe(key);
  last_error_.clear();
  return true;
}

bool HDWallet::ReadAndDecrypt(std::vector<std::uint8_t>* payload, std::uint16_t* out_version) const {
  last_error_.clear();
  if (wallet_path_.empty()) {
    last_error_ = "wallet path is empty";
    return false;
  }
  std::ifstream in(wallet_path_, std::ios::binary);
  if (!in.is_open()) {
    last_error_ = "wallet file not found or unreadable";
    return false;
  }
  in.seekg(0, std::ios::end);
  const auto file_size = in.tellg();
  if (file_size <= 0) {
    last_error_ = "wallet file is empty";
    return false;
  }
  in.seekg(0, std::ios::beg);
  std::vector<std::uint8_t> file(static_cast<std::size_t>(file_size));
  in.read(reinterpret_cast<char*>(file.data()), static_cast<std::streamsize>(file.size()));
  if (!in.good()) {
    last_error_ = "wallet file read failed";
    return false;
  }

  std::size_t offset = 0;
  std::uint32_t magic = 0;
  if (!primitives::serialize::ReadUint32(file, &offset, &magic) || magic != kWalletMagic) {
    last_error_ = "wallet file magic mismatch";
    return false;
  }
  if (offset + 2 + 2 > file.size()) {
    last_error_ = "wallet file truncated";
    return false;
  }
  const std::uint16_t version =
      static_cast<std::uint16_t>(file[offset] | (file[offset + 1] << 8));
  offset += 2;
  if (version < kMinWalletVersion || version > kWalletVersion) {
    last_error_ = "unsupported wallet format version " + std::to_string(version);
    return false;
  }
  const std::uint16_t reserved =
      static_cast<std::uint16_t>(file[offset] | (file[offset + 1] << 8));
  offset += 2;
  if (offset + 32 + util::kChaCha20Poly1305NonceSize + 4 > file.size()) {
    last_error_ = "wallet file truncated";
    return false;
  }
  std::vector<std::uint8_t> salt_field(32);
  std::copy_n(file.begin() + offset, salt_field.size(), salt_field.begin());
  offset += salt_field.size();
  std::vector<std::uint8_t> nonce(util::kChaCha20Poly1305NonceSize);
  std::copy_n(file.begin() + offset, nonce.size(), nonce.begin());
  offset += nonce.size();
  std::uint32_t cipher_len = 0;
  if (!primitives::serialize::ReadUint32(file, &offset, &cipher_len)) {
    last_error_ = "wallet file truncated";
    return false;
  }
  if (cipher_len > file.size() - offset) {
    last_error_ = "wallet file truncated";
    return false;
  }
  std::span<const std::uint8_t> ciphertext(file.data() + offset, cipher_len);
  offset += cipher_len;
  if (offset != file.size()) {
    last_error_ = "wallet file has trailing data";
    return false;
  }

  std::vector<std::uint8_t> key;
  const auto kdf = static_cast<WalletKdf>(reserved);
  if (kdf == WalletKdf::kArgon2id) {
    // Decode Argon2 parameters from the salt field.
    auto decode_u32 = [&](std::size_t offset) -> std::uint32_t {
      return static_cast<std::uint32_t>(salt_field[offset + 0]) |
             (static_cast<std::uint32_t>(salt_field[offset + 1]) << 8) |
             (static_cast<std::uint32_t>(salt_field[offset + 2]) << 16) |
             (static_cast<std::uint32_t>(salt_field[offset + 3]) << 24);
    };
    util::Argon2idParams params;
    params.t_cost = decode_u32(16);
    params.m_cost_kib = decode_u32(20);
    params.parallelism = decode_u32(24);
    if (params.t_cost == 0 || params.m_cost_kib == 0 || params.parallelism == 0) {
      params = util::DefaultArgon2idParams();
    }
    if (params.t_cost > kMaxWalletArgon2idT || params.m_cost_kib > kMaxWalletArgon2idMemoryKiB ||
        params.parallelism > kMaxWalletArgon2idParallelism) {
      last_error_ =
          "wallet Argon2id parameters exceed maximums (t_cost=" + std::to_string(params.t_cost) +
          ", m_cost_kib=" + std::to_string(params.m_cost_kib) +
          ", parallelism=" + std::to_string(params.parallelism) + ")";
      return false;
    }
    std::span<const std::uint8_t> salt(
        salt_field.data(), 16);  // first 16 bytes
    if (!util::DeriveKeyArgon2id(password_, salt, params, &key)) {
      last_error_ = "wallet key derivation failed";
      util::SecureWipe(key);
      return false;
    }
  } else {
    // Legacy wallets: entire 32-byte field is the PBKDF salt.
    key = DeriveEncryptionKey(password_, salt_field);
  }

  if (!util::ChaCha20Poly1305Decrypt(
          std::span<const std::uint8_t>(key.data(), key.size()),
          std::span<const std::uint8_t>(nonce.data(), nonce.size()),
          std::span<const std::uint8_t>(salt_field.data(), salt_field.size()),
          ciphertext, payload)) {
    last_error_ = "wallet decryption failed (wrong passphrase or corrupted file)";
    util::SecureWipe(key);
    return false;
  }
  util::SecureWipe(key);
  if (out_version) {
    *out_version = version;
  }
  last_error_.clear();
  return true;
}

}  // namespace qryptcoin::wallet
