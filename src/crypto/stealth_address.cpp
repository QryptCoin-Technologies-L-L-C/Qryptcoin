#include "crypto/stealth_address.hpp"

#include <algorithm>
#include <array>
#include <vector>

#include "crypto/deterministic_rng.hpp"
#include "crypto/hash.hpp"
#include "crypto/pq_engine.hpp"
#include "crypto/pq_params.hpp"

namespace qryptcoin::crypto {

namespace {

std::array<std::uint8_t, 4> StealthCounterV1(std::span<const std::uint8_t> ciphertext,
                                             std::span<const std::uint8_t> paycode_bytes) {
  constexpr std::string_view kTag = "QRY-STEALTH-COUNTER-V1";
  std::vector<std::uint8_t> preimage;
  preimage.reserve(kTag.size() + ciphertext.size() + paycode_bytes.size());
  preimage.insert(preimage.end(), kTag.begin(), kTag.end());
  preimage.insert(preimage.end(), ciphertext.begin(), ciphertext.end());
  preimage.insert(preimage.end(), paycode_bytes.begin(), paycode_bytes.end());
  const auto digest = Sha3_256(preimage);
  std::array<std::uint8_t, 4> counter{};
  std::copy_n(digest.begin(), counter.size(), counter.begin());
  return counter;
}

std::array<std::uint8_t, 32> StealthKeySeedV1(
    std::span<const std::uint8_t> shared_secret,
    std::span<const std::uint8_t, 32> spend_root_commitment,
    std::span<const std::uint8_t, 4> counter) {
  constexpr std::string_view kTag = "QRY-STEALTH-KEYSEED-V1";
  std::vector<std::uint8_t> preimage;
  preimage.reserve(kTag.size() + shared_secret.size() + spend_root_commitment.size() +
                   counter.size());
  preimage.insert(preimage.end(), kTag.begin(), kTag.end());
  preimage.insert(preimage.end(), shared_secret.begin(), shared_secret.end());
  preimage.insert(preimage.end(), spend_root_commitment.begin(), spend_root_commitment.end());
  preimage.insert(preimage.end(), counter.begin(), counter.end());
  return Sha3_256(preimage);
}

}  // namespace

bool DeriveStealthOutputV1(std::span<const std::uint8_t> shared_secret,
                           const PaymentCodeV2& recipient_code,
                           std::span<const std::uint8_t> ciphertext,
                           StealthDerivationV1* out,
                           std::string* error) {
  if (error) {
    error->clear();
  }
  if (!out) {
    if (error) *error = "invalid output pointer";
    return false;
  }
  if (shared_secret.size() != kMlkem768SharedSecretBytes) {
    if (error) *error = "invalid shared_secret size";
    return false;
  }
  if (ciphertext.size() != kMlkem768CiphertextBytes) {
    if (error) *error = "invalid ciphertext size";
    return false;
  }

  const auto paycode_bytes = SerializePaymentCodeV2(recipient_code);
  const auto counter = StealthCounterV1(ciphertext, paycode_bytes);
  const auto key_seed =
      StealthKeySeedV1(shared_secret, recipient_code.spend_root_commitment, counter);

  // Derive a deterministic one-time Dilithium keypair from the key seed and
  // map it into a canonical P2QH reveal + witness program.
  DeterministicOqsRng rng(std::span<const std::uint8_t>(key_seed.data(), key_seed.size()),
                          DeterministicOqsRng::Mode::kShake256Xof);
  auto key = QPqDilithiumKey::Generate();
  auto reveal = BuildP2QHReveal(key.PublicKey());
  auto descriptor = DescriptorFromReveal(reveal);

  out->counter = counter;
  out->key_seed = key_seed;
  out->reveal = std::move(reveal);
  out->descriptor = descriptor;
  return true;
}

}  // namespace qryptcoin::crypto

