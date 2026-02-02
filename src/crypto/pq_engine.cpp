#include "crypto/pq_engine.hpp"

#include <cstdint>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>

#include <oqs/rand.h>

#include "crypto/deterministic_rng.hpp"
#include "crypto/pq_params.hpp"
#include "util/csprng.hpp"
#include "util/secure_wipe.hpp"

namespace qryptcoin::crypto {

namespace {

constexpr std::string_view kErrKemInit = "Failed to initialize OQS KEM context";
constexpr std::string_view kErrSigInit = "Failed to initialize OQS signature context";
constexpr std::string_view kConsensusSignatureId = OQS_SIG_alg_ml_dsa_65;

thread_local bool g_allow_deterministic_randombytes = false;

class ScopedDeterministicRandombytesAllowance {
 public:
  ScopedDeterministicRandombytesAllowance() : previous_(g_allow_deterministic_randombytes) {
    g_allow_deterministic_randombytes = true;
  }
  ScopedDeterministicRandombytesAllowance(const ScopedDeterministicRandombytesAllowance&) = delete;
  ScopedDeterministicRandombytesAllowance& operator=(
      const ScopedDeterministicRandombytesAllowance&) = delete;
  ~ScopedDeterministicRandombytesAllowance() { g_allow_deterministic_randombytes = previous_; }

 private:
  bool previous_{false};
};

void OqsRandombytesShim(std::uint8_t* out, std::size_t outlen) {
  if (out == nullptr || outlen == 0) {
    return;
  }
  if (g_allow_deterministic_randombytes) {
    if (auto* rng = DeterministicOqsRng::CurrentInstance()) {
      rng->Generate(out, outlen);
      return;
    }
  }
  util::FillSecureRandomBytesOrAbort(std::span<std::uint8_t>(out, outlen));
}

void EnsureOqsRandombytesHookInstalled() {
  OQS_randombytes_custom_algorithm(&OqsRandombytesShim);
}

class KemContext {
 public:
  explicit KemContext(std::string_view algorithm) {
    handle_ = OQS_KEM_new(std::string(algorithm).c_str());
    if (handle_ == nullptr) {
      throw std::runtime_error(std::string(kErrKemInit));
    }
  }

  ~KemContext() { OQS_KEM_free(handle_); }
  KemContext(const KemContext&) = delete;
  KemContext& operator=(const KemContext&) = delete;
  KemContext(KemContext&&) = delete;
  KemContext& operator=(KemContext&&) = delete;

  OQS_KEM* get() const { return handle_; }

 private:
  OQS_KEM* handle_{nullptr};
};

class SigContext {
 public:
  explicit SigContext(std::string_view algorithm) {
    handle_ = OQS_SIG_new(std::string(algorithm).c_str());
    if (handle_ == nullptr) {
      throw std::runtime_error(std::string(kErrSigInit));
    }
  }

  ~SigContext() { OQS_SIG_free(handle_); }
  SigContext(const SigContext&) = delete;
  SigContext& operator=(const SigContext&) = delete;
  SigContext(SigContext&&) = delete;
  SigContext& operator=(SigContext&&) = delete;

  OQS_SIG* get() const { return handle_; }

 private:
  OQS_SIG* handle_{nullptr};
};

const OQS_SIG& SignatureContext() {
  static SigContext ctx(kConsensusSignatureId);
  const auto* sig = ctx.get();
  if (sig == nullptr) {
    throw std::runtime_error(std::string(kErrSigInit));
  }
  if (sig->length_public_key != kMldsa65PublicKeyBytes) {
    throw std::runtime_error("ML-DSA-65 public key size mismatch (liboqs build is incompatible)");
  }
  if (sig->length_secret_key != kMldsa65SecretKeyBytes) {
    throw std::runtime_error("ML-DSA-65 secret key size mismatch (liboqs build is incompatible)");
  }
  if (sig->length_signature != kMldsa65SignatureBytes) {
    throw std::runtime_error("ML-DSA-65 signature size mismatch (liboqs build is incompatible)");
  }
  return *sig;
}

template <typename T>
void EnsureSize(std::span<const std::uint8_t> buffer, T expected_size, std::string_view label) {
  if (buffer.size_bytes() != static_cast<std::size_t>(expected_size)) {
    throw std::runtime_error(std::string(label) + " size mismatch");
  }
}

void EnsureKyberSizes(const OQS_KEM* kem) {
  if (kem == nullptr) {
    throw std::runtime_error(std::string(kErrKemInit));
  }
  if (kem->length_public_key != kMlkem768PublicKeyBytes ||
      kem->length_secret_key != kMlkem768SecretKeyBytes ||
      kem->length_ciphertext != kMlkem768CiphertextBytes ||
      kem->length_shared_secret != kMlkem768SharedSecretBytes) {
    throw std::runtime_error("ML-KEM-768 size mismatch (liboqs build is incompatible)");
  }
}

}  // namespace

QPqDilithiumKey::QPqDilithiumKey(std::vector<std::uint8_t> secret_key,
                                 std::vector<std::uint8_t> public_key)
    : secret_key_(std::move(secret_key)), public_key_(std::move(public_key)) {}

QPqDilithiumKey::~QPqDilithiumKey() { util::SecureWipe(secret_key_); }

QPqDilithiumKey::QPqDilithiumKey(QPqDilithiumKey&& other) noexcept = default;

QPqDilithiumKey& QPqDilithiumKey::operator=(QPqDilithiumKey&& other) noexcept = default;

QPqDilithiumKey QPqDilithiumKey::Generate() {
  EnsureOqsRandombytesHookInstalled();
  const auto& sig = SignatureContext();
  ScopedDeterministicRandombytesAllowance allow_rng;
  std::vector<std::uint8_t> public_key(sig.length_public_key);
  std::vector<std::uint8_t> secret_key(sig.length_secret_key);
  if (OQS_SIG_keypair(&sig, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
    throw std::runtime_error("Failed to generate ML-DSA keypair");
  }
  return QPqDilithiumKey(std::move(secret_key), std::move(public_key));
}

QPqDilithiumKey QPqDilithiumKey::Import(std::span<const std::uint8_t> secret_key,
                                        std::span<const std::uint8_t> public_key) {
  const auto& sig = SignatureContext();
  EnsureSize(secret_key, sig.length_secret_key, "ML-DSA secret key");
  EnsureSize(public_key, sig.length_public_key, "ML-DSA public key");
  return QPqDilithiumKey(std::vector<std::uint8_t>(secret_key.begin(), secret_key.end()),
                         std::vector<std::uint8_t>(public_key.begin(), public_key.end()));
}

std::vector<std::uint8_t> QPqDilithiumKey::Sign(std::span<const std::uint8_t> message) const {
  const auto& sig = SignatureContext();
  EnsureSize(secret_key_, sig.length_secret_key, "ML-DSA secret key");
  std::vector<std::uint8_t> signature(sig.length_signature);
  size_t sig_len = 0;
  if (OQS_SIG_sign(&sig, signature.data(), &sig_len, message.data(), message.size(),
                   secret_key_.data()) != OQS_SUCCESS) {
    throw std::runtime_error("ML-DSA signing failure");
  }
  if (sig_len != signature.size()) {
    throw std::runtime_error("ML-DSA signature size mismatch");
  }
  return signature;
}

bool QPqDilithiumKey::Verify(std::span<const std::uint8_t> message,
                             std::span<const std::uint8_t> signature) const {
  const auto& sig = SignatureContext();
  EnsureSize(public_key_, sig.length_public_key, "ML-DSA public key");
  if (signature.size() != sig.length_signature) {
    return false;
  }
  return OQS_SIG_verify(&sig, message.data(), message.size(), signature.data(), signature.size(),
                        public_key_.data()) == OQS_SUCCESS;
}

QPqKyberKEM::QPqKyberKEM(std::vector<std::uint8_t> secret_key,
                         std::vector<std::uint8_t> public_key)
    : secret_key_(std::move(secret_key)), public_key_(std::move(public_key)) {}

QPqKyberKEM::~QPqKyberKEM() { util::SecureWipe(secret_key_); }

QPqKyberKEM::QPqKyberKEM(QPqKyberKEM&& other) noexcept = default;

QPqKyberKEM& QPqKyberKEM::operator=(QPqKyberKEM&& other) noexcept = default;

QPqKyberKEM QPqKyberKEM::Generate() {
  KemContext ctx(kConsensusKyberId);
  EnsureKyberSizes(ctx.get());
  std::vector<std::uint8_t> public_key(ctx.get()->length_public_key);
  std::vector<std::uint8_t> secret_key(ctx.get()->length_secret_key);
  if (OQS_KEM_keypair(ctx.get(), public_key.data(), secret_key.data()) != OQS_SUCCESS) {
    throw std::runtime_error("Failed to generate Kyber keypair");
  }
  return QPqKyberKEM(std::move(secret_key), std::move(public_key));
}

QPqKyberKEM QPqKyberKEM::GenerateDeterministic() {
  EnsureOqsRandombytesHookInstalled();
  if (DeterministicOqsRng::CurrentInstance() == nullptr) {
    throw std::runtime_error("deterministic Kyber keypair generation requires DeterministicOqsRng");
  }
  ScopedDeterministicRandombytesAllowance allow_rng;
  KemContext ctx(kConsensusKyberId);
  EnsureKyberSizes(ctx.get());
  std::vector<std::uint8_t> public_key(ctx.get()->length_public_key);
  std::vector<std::uint8_t> secret_key(ctx.get()->length_secret_key);
  if (OQS_KEM_keypair(ctx.get(), public_key.data(), secret_key.data()) != OQS_SUCCESS) {
    throw std::runtime_error("Failed to generate Kyber keypair");
  }
  return QPqKyberKEM(std::move(secret_key), std::move(public_key));
}

KyberEncapsulationResult QPqKyberKEM::Encapsulate(std::span<const std::uint8_t> peer_public_key) {
  KemContext ctx(kConsensusKyberId);
  EnsureKyberSizes(ctx.get());
  EnsureSize(peer_public_key, ctx.get()->length_public_key, "Kyber public key");
  KyberEncapsulationResult result{};
  result.ciphertext.resize(ctx.get()->length_ciphertext);
  result.shared_secret.resize(ctx.get()->length_shared_secret);
  if (OQS_KEM_encaps(ctx.get(), result.ciphertext.data(), result.shared_secret.data(),
                     peer_public_key.data()) != OQS_SUCCESS) {
    throw std::runtime_error("Kyber encapsulation failure");
  }
  return result;
}

std::vector<std::uint8_t> QPqKyberKEM::Decapsulate(
    std::span<const std::uint8_t> ciphertext) const {
  KemContext ctx(kConsensusKyberId);
  EnsureKyberSizes(ctx.get());
  EnsureSize(ciphertext, ctx.get()->length_ciphertext, "Kyber ciphertext");
  EnsureSize(secret_key_, ctx.get()->length_secret_key, "Kyber secret key");
  std::vector<std::uint8_t> shared_secret(ctx.get()->length_shared_secret);
  if (OQS_KEM_decaps(ctx.get(), shared_secret.data(), ciphertext.data(), secret_key_.data()) !=
      OQS_SUCCESS) {
    throw std::runtime_error("Kyber decapsulation failure");
  }
  return shared_secret;
}

std::size_t DilithiumPublicKeySize() {
  (void)SignatureContext();
  return kMldsa65PublicKeyBytes;
}

std::size_t DilithiumSecretKeySize() {
  (void)SignatureContext();
  return kMldsa65SecretKeyBytes;
}

std::size_t DilithiumSignatureSize() {
  (void)SignatureContext();
  return kMldsa65SignatureBytes;
}

bool VerifySignature(SignatureAlgorithm algorithm, std::span<const std::uint8_t> message,
                     std::span<const std::uint8_t> signature,
                     std::span<const std::uint8_t> public_key) {
  if (algorithm != SignatureAlgorithm::kDilithium) {
    return false;
  }
  const auto& sig = SignatureContext();
  if (public_key.size() != kMldsa65PublicKeyBytes || signature.size() != kMldsa65SignatureBytes) {
    return false;
  }
  return OQS_SIG_verify(&sig, message.data(), message.size(), signature.data(), signature.size(),
                        public_key.data()) == OQS_SUCCESS;
}

std::size_t KyberPublicKeySize() {
  KemContext ctx(kConsensusKyberId);
  EnsureKyberSizes(ctx.get());
  return kMlkem768PublicKeyBytes;
}

std::size_t KyberCiphertextSize() {
  KemContext ctx(kConsensusKyberId);
  EnsureKyberSizes(ctx.get());
  return kMlkem768CiphertextBytes;
}

std::size_t KyberSharedSecretSize() {
  KemContext ctx(kConsensusKyberId);
  EnsureKyberSizes(ctx.get());
  return kMlkem768SharedSecretBytes;
}

}  // namespace qryptcoin::crypto
