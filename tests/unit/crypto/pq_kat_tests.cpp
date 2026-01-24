#include <algorithm>
#include <array>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <oqs/rand.h>

#include "crypto/deterministic_rng.hpp"
#include "crypto/hash.hpp"
#include "crypto/pq_engine.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/mnemonic.hpp"
#include "net/handshake.hpp"
#include "script/p2qh.hpp"
#include "util/aead.hpp"
#include "util/argon2_kdf.hpp"
#include "tests/unit/crypto/kat_values.hpp"

namespace {

using qryptcoin::crypto::DeterministicOqsRng;

std::string BytesToHex(std::span<const std::uint8_t> data) {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(data.size() * 2);
  for (auto byte : data) {
    hex.push_back(kHexDigits[byte >> 4]);
    hex.push_back(kHexDigits[byte & 0x0F]);
  }
  return hex;
}

std::span<const std::uint8_t> BytesFromString(std::string_view str) {
  return {reinterpret_cast<const std::uint8_t*>(str.data()), str.size()};
}

void OqsDeterministicRandombytes(uint8_t* out, size_t len) {
  if (out == nullptr || len == 0) {
    return;
  }
  if (auto* rng = qryptcoin::crypto::DeterministicOqsRng::CurrentInstance()) {
    rng->Generate(out, len);
    return;
  }
  std::fill(out, out + len, 0);
}

class ScopedOqsRandombytesOverride {
 public:
  ScopedOqsRandombytesOverride() { OQS_randombytes_custom_algorithm(&OqsDeterministicRandombytes); }
  ScopedOqsRandombytesOverride(const ScopedOqsRandombytesOverride&) = delete;
  ScopedOqsRandombytesOverride& operator=(const ScopedOqsRandombytesOverride&) = delete;
  ~ScopedOqsRandombytesOverride() { (void)OQS_randombytes_switch_algorithm(OQS_RAND_alg_system); }
};

void RequireEqual(const std::string& label, const std::string& got, std::string_view expected) {
  if (got != expected) {
    std::cerr << label << " mismatch\nexpected: " << expected << "\n got: " << got << '\n';
    std::exit(EXIT_FAILURE);
  }
}

bool ShouldUpdateKats() {
#ifdef _WIN32
  char* buffer = nullptr;
  size_t len = 0;
  if (_dupenv_s(&buffer, &len, "QRY_UPDATE_KATS") == 0 && buffer != nullptr) {
    free(buffer);
    return true;
  }
  if (buffer != nullptr) {
    free(buffer);
  }
  return false;
#else
  return std::getenv("QRY_UPDATE_KATS") != nullptr;
#endif
}

void MaybeDump(const std::string& label, const std::string& pk, const std::string& sk,
               const std::string& signature) {
  if (!ShouldUpdateKats()) {
    return;
  }
  std::cout << label << "\n  pk=" << pk << "\n  sk=" << sk << "\n  sig=" << signature << "\n";
}

void MaybeDumpKyber(const std::string& label, const std::string& pk, const std::string& ct,
                    const std::string& ss) {
  if (!ShouldUpdateKats()) {
    return;
  }
  std::cout << label << "\n  pk=" << pk << "\n  ct=" << ct << "\n  ss=" << ss << "\n";
}

void TestAead() {
  using qryptcoin::util::ChaCha20Poly1305Encrypt;
  using qryptcoin::util::ChaCha20Poly1305Decrypt;
  using qryptcoin::util::kChaCha20Poly1305KeySize;
  using qryptcoin::util::kChaCha20Poly1305NonceSize;

  std::array<std::uint8_t, kChaCha20Poly1305KeySize> key{};
  std::array<std::uint8_t, kChaCha20Poly1305NonceSize> nonce{};
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i);
  for (std::size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<std::uint8_t>(0xA0 + i);

  const std::vector<std::uint8_t> aad = {0x01, 0x02, 0x03, 0x04, 0x05};
  const std::vector<std::uint8_t> plaintext = {'Q', 'R', 'Y', '-', 'A', 'E', 'A', 'D'};

  auto ciphertext = ChaCha20Poly1305Encrypt(key, nonce, aad, plaintext);
  std::vector<std::uint8_t> decrypted;
  if (!ChaCha20Poly1305Decrypt(key, nonce, aad, ciphertext, &decrypted)) {
    std::cerr << "AEAD decrypt failed for valid inputs\n";
    std::exit(EXIT_FAILURE);
  }
  if (decrypted != plaintext) {
    std::cerr << "AEAD round-trip mismatch\n";
    std::exit(EXIT_FAILURE);
  }

  // Tamper the tag; decryption must fail.
  ciphertext.back() ^= 0x01;
  if (ChaCha20Poly1305Decrypt(key, nonce, aad, ciphertext, &decrypted)) {
    std::cerr << "AEAD accepted ciphertext with invalid tag\n";
    std::exit(EXIT_FAILURE);
  }

  // Re-encrypt and tamper the AAD; decryption must fail.
  ciphertext = ChaCha20Poly1305Encrypt(key, nonce, aad, plaintext);
  std::vector<std::uint8_t> bad_aad = aad;
  bad_aad[0] ^= 0xFF;
  if (ChaCha20Poly1305Decrypt(key, nonce, bad_aad, ciphertext, &decrypted)) {
    std::cerr << "AEAD accepted ciphertext with wrong AAD\n";
    std::exit(EXIT_FAILURE);
  }
}

void TestMnemonicSeedDerivation() {
  // PBKDF2-HMAC-SHA512 mnemonic seed derivation (2048 iterations).
  const std::string mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon art";
  const std::string passphrase = "QRYPTCOIN";

  const auto seed = qryptcoin::crypto::MnemonicSeedFromSentence(mnemonic, passphrase);
  const auto seed_hex = BytesToHex(std::span<const std::uint8_t>(seed.data(), seed.size()));

  // Expected seed for the above mnemonic/passphrase.
  const std::string expected =
      "f9e00a0936571ff3afe86ef8391615876fbae4208c8c91f7f3371c84ba819ede"
      "c0cc834d0ed22f5f0d798dd4715b24e97ba9ea388e7bde5a4a06996d4da90cd9";

  RequireEqual("mnemonic-seed", seed_hex, expected);
}

void TestArgon2id() {
  using qryptcoin::util::Argon2idParams;
  using qryptcoin::util::DefaultArgon2idParams;
  using qryptcoin::util::DeriveKeyArgon2id;

  const std::string password = "correct horse battery staple";
  Argon2idParams params = DefaultArgon2idParams();
  std::array<std::uint8_t, 16> salt{};
  for (std::size_t i = 0; i < salt.size(); ++i) {
    salt[i] = static_cast<std::uint8_t>(i);
  }

  std::vector<std::uint8_t> key1;
  std::vector<std::uint8_t> key2;
  std::vector<std::uint8_t> key3;
  if (!DeriveKeyArgon2id(password,
                         std::span<const std::uint8_t>(salt.data(), salt.size()),
                         params, &key1)) {
    std::cerr << "Argon2id derivation failed for valid inputs\n";
    std::exit(EXIT_FAILURE);
  }
  if (!DeriveKeyArgon2id(password,
                         std::span<const std::uint8_t>(salt.data(), salt.size()),
                         params, &key2)) {
    std::cerr << "Argon2id derivation failed on second invocation\n";
    std::exit(EXIT_FAILURE);
  }
  if (key1.size() != 32 || key2.size() != 32) {
    std::cerr << "Argon2id produced unexpected key length\n";
    std::exit(EXIT_FAILURE);
  }
  if (key1 != key2) {
    std::cerr << "Argon2id produced non-deterministic output\n";
    std::exit(EXIT_FAILURE);
  }
  if (!DeriveKeyArgon2id("different password",
                         std::span<const std::uint8_t>(salt.data(), salt.size()),
                         params, &key3)) {
    std::cerr << "Argon2id derivation failed for alternate password\n";
    std::exit(EXIT_FAILURE);
  }
  if (key3 == key1) {
    std::cerr << "Argon2id produced identical keys for different passwords\n";
    std::exit(EXIT_FAILURE);
  }
}

void TestDilithiumNegativeCases() {
  using qryptcoin::crypto::QPqDilithiumKey;
  using qryptcoin::crypto::SignatureAlgorithm;
  using qryptcoin::crypto::VerifySignature;

  QPqDilithiumKey key = QPqDilithiumKey::Generate();
  const auto message = BytesFromString("DILITHIUM|QRY|NEG");
  auto sig = key.Sign(message);
  auto pk = key.PublicKey();

  // Baseline sanity: valid signature must verify.
  if (!VerifySignature(SignatureAlgorithm::kDilithium, message, sig, pk)) {
    std::cerr << "dilithium-negative: baseline signature verification failed\n";
    std::exit(EXIT_FAILURE);
  }

  // Truncated signature must be rejected.
  std::vector<std::uint8_t> short_sig(sig.begin(), sig.end());
  if (!short_sig.empty()) {
    short_sig.pop_back();
    if (VerifySignature(SignatureAlgorithm::kDilithium, message, short_sig, pk)) {
      std::cerr << "dilithium-negative: accepted truncated signature\n";
      std::exit(EXIT_FAILURE);
    }
  }

  // Overlong signature must be rejected.
  std::vector<std::uint8_t> long_sig(sig.begin(), sig.end());
  long_sig.push_back(0x00);
  if (VerifySignature(SignatureAlgorithm::kDilithium, message, long_sig, pk)) {
    std::cerr << "dilithium-negative: accepted overlong signature\n";
    std::exit(EXIT_FAILURE);
  }

  // Bit-flipped signature must be rejected.
  std::vector<std::uint8_t> bad_sig(sig.begin(), sig.end());
  if (!bad_sig.empty()) {
    bad_sig[0] ^= 0x01;
    if (VerifySignature(SignatureAlgorithm::kDilithium, message, bad_sig, pk)) {
      std::cerr << "dilithium-negative: accepted corrupted signature\n";
      std::exit(EXIT_FAILURE);
    }
  }

  // Valid signature under the wrong public key must be rejected.
  std::vector<std::uint8_t> wrong_pk(pk.begin(), pk.end());
  if (!wrong_pk.empty()) {
    wrong_pk[0] ^= 0x01;
    if (VerifySignature(SignatureAlgorithm::kDilithium, message, sig, wrong_pk)) {
      std::cerr << "dilithium-negative: accepted signature for wrong public key\n";
      std::exit(EXIT_FAILURE);
    }
  }
}

void TestP2QHScriptNegativeCases() {
  using qryptcoin::crypto::QPqDilithiumKey;
  using qryptcoin::crypto::SignatureAlgorithm;
  using qryptcoin::crypto::BuildP2QHReveal;
  using qryptcoin::crypto::DescriptorFromReveal;

  QPqDilithiumKey key = QPqDilithiumKey::Generate();
  const auto message = BytesFromString("P2QH|NEG");
  auto sig = key.Sign(message);
  auto pk = key.PublicKey();

  (void)SignatureAlgorithm::kDilithium;
  auto reveal = BuildP2QHReveal(pk);
  qryptcoin::crypto::P2QHDescriptor descriptor = DescriptorFromReveal(reveal);
  qryptcoin::script::ScriptPubKey script =
      qryptcoin::script::CreateP2QHScript(descriptor);

  std::vector<qryptcoin::primitives::WitnessStackItem> witness(2);
  witness[0].data.assign(reveal.begin(), reveal.end());
  witness[1].data.assign(sig.begin(), sig.end());

  std::string error;
  if (!qryptcoin::script::VerifyP2QHWitness(
          script, witness,
          std::span<const std::uint8_t>(message.data(), message.size()),
          &error)) {
    std::cerr << "p2qh-negative: baseline witness verification failed: " << error
              << "\n";
    std::exit(EXIT_FAILURE);
  }

  // Malformed reveal: truncate the payload; ParseP2QHReveal must fail.
  auto bad_reveal = witness;
  if (!bad_reveal[0].data.empty()) {
    bad_reveal[0].data.pop_back();
  }
  if (qryptcoin::script::VerifyP2QHWitness(
          script, bad_reveal,
          std::span<const std::uint8_t>(message.data(), message.size()),
          &error)) {
    std::cerr << "p2qh-negative: accepted malformed reveal encoding\n";
    std::exit(EXIT_FAILURE);
  }

  // Wrong witness program: script commitment does not match reveal.
  auto bad_descriptor = descriptor;
  bad_descriptor.program[0] ^= 0x01;
  qryptcoin::script::ScriptPubKey bad_script =
      qryptcoin::script::CreateP2QHScript(bad_descriptor);
  if (qryptcoin::script::VerifyP2QHWitness(
          bad_script, witness,
          std::span<const std::uint8_t>(message.data(), message.size()),
          &error)) {
    std::cerr << "p2qh-negative: accepted witness for wrong witness program\n";
    std::exit(EXIT_FAILURE);
  }
}

}  // namespace

int main() {
  {
    std::array<std::uint8_t, 32> seed{};
    std::memcpy(seed.data(), "DIL-SEED-1", 10);
    DeterministicOqsRng rng(seed);
    auto key = qryptcoin::crypto::QPqDilithiumKey::Generate();
    const auto message = BytesFromString("DILITHIUM|QRY|KAT");
    ScopedOqsRandombytesOverride oqs_rng;
    auto sig = key.Sign(message);
    const auto pk_hex = BytesToHex(key.PublicKey());
    const auto sk_hex = BytesToHex(key.SecretKey());
    const auto sig_hex = BytesToHex(sig);
    MaybeDump("Dilithium", pk_hex, sk_hex, sig_hex);
    if (!ShouldUpdateKats()) {
      RequireEqual("dilithium pk", pk_hex, qryptcoin::kats::kDilithiumPk);
      RequireEqual("dilithium sk", sk_hex, qryptcoin::kats::kDilithiumSk);
      RequireEqual("dilithium sig", sig_hex, qryptcoin::kats::kDilithiumSig);
      if (!key.Verify(message, sig)) {
        std::cerr << "Dilithium verification failed\n";
        return EXIT_FAILURE;
      }
    }
  }

  {
    std::array<std::uint8_t, 32> seed{};
    std::memcpy(seed.data(), "KYBER-SEED-1", 12);
    DeterministicOqsRng rng(seed);
    ScopedOqsRandombytesOverride oqs_rng;
    auto responder = qryptcoin::crypto::QPqKyberKEM::Generate();
    qryptcoin::net::KyberSession initiator_session;
    const auto packet = initiator_session.Initiate(responder);
    qryptcoin::net::KyberSession responder_session;
    const auto shared = responder_session.Accept(responder, packet.ciphertext);
    const auto pk_hex = BytesToHex(responder.PublicKey());
    const auto ct_hex = BytesToHex(packet.ciphertext);
    const auto ss_hex = BytesToHex(packet.initiator_secret);
    MaybeDumpKyber("Kyber768", pk_hex, ct_hex, ss_hex);
    if (!ShouldUpdateKats()) {
      RequireEqual("kyber pk", pk_hex, qryptcoin::kats::kKyberPk);
      RequireEqual("kyber ct", ct_hex, qryptcoin::kats::kKyberCt);
      RequireEqual("kyber initiator secret", ss_hex, qryptcoin::kats::kKyberSs);
      RequireEqual("kyber responder secret", BytesToHex(shared), qryptcoin::kats::kKyberSs);
    }
  }

  const auto sha3_256_value = qryptcoin::crypto::Sha3_256Vector(BytesFromString("QryptCoin"));
  const auto sha3_256_hex = BytesToHex(std::span<const std::uint8_t>(sha3_256_value));
  const auto sha3_512_value = qryptcoin::crypto::Sha3_512(BytesFromString("QryptCoin"));
  const auto sha3_512_hex = BytesToHex(std::span<const std::uint8_t>(sha3_512_value));
  const auto double_sha_value = qryptcoin::crypto::DoubleSha3_256(BytesFromString("header"));
  const auto double_sha_hex = BytesToHex(std::span<const std::uint8_t>(double_sha_value));

  if (!ShouldUpdateKats()) {
    RequireEqual("sha3-256", sha3_256_hex,
                 "590d2f31ab0b13a66463f7855397df4060310b8131fd2d2b6147788e1ad2f986");
    RequireEqual("sha3-512",
                 sha3_512_hex,
                 "a6b1395f5a70f65d8dd603823923bf4b798516434f008454317c64ceeef7ca57621dc0e7dc22e599aee49bd84d774aac776221743d203abb7e6adbee931c199b");
    RequireEqual("double-sha3-256", double_sha_hex,
                 "a0ae673ed0495b57dd4d72ba4131a451497f0fb73b2a09778e6adc1c49af633b");
  }

  if (!ShouldUpdateKats()) {
    // Negative-path tests that exercise signature and script validation
    // for malformed and mismatched Dilithium/P2QH payloads.
    TestDilithiumNegativeCases();
    TestP2QHScriptNegativeCases();
  }

  if (ShouldUpdateKats()) {
    return EXIT_SUCCESS;
  }

  // AEAD self-tests (tag verification and AAD binding).
  TestAead();
  // Mnemonic PBKDF2/HMAC-SHA512 seed derivation.
  TestMnemonicSeedDerivation();
  // Argon2id KDF wrapper (determinism and basic separation).
  TestArgon2id();

  return EXIT_SUCCESS;
}
