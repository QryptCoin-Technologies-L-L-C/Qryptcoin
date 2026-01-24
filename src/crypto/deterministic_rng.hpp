#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>

#include <oqs/sha3_ops.h>

namespace qryptcoin::crypto {

class DeterministicOqsRng {
 public:
  enum class Mode : std::uint8_t {
    kSha3Ctr = 0,
    kLegacyMt19937 = 1,
    kShake256Xof = 2,
  };

  explicit DeterministicOqsRng(std::span<const std::uint8_t> seed, Mode mode = Mode::kSha3Ctr);
  DeterministicOqsRng(const DeterministicOqsRng&) = delete;
  DeterministicOqsRng& operator=(const DeterministicOqsRng&) = delete;
  ~DeterministicOqsRng();

  // Expose the current instance so other PQ backends (e.g. the
  // standalone Dilithium reference implementation) can consume the
  // same deterministic byte stream when deriving wallet keys.
  static DeterministicOqsRng* CurrentInstance();

  // Fill |out| with |len| bytes from the deterministic stream. When
  // no instance is active this function is a no-op; callers should
  // fall back to system randomness in that case.
  void Generate(std::uint8_t* out, std::size_t len);

 private:
 static DeterministicOqsRng*& Instance();
  void Fill(std::uint8_t* out, std::size_t len);
  void Refill();

  Mode mode_{Mode::kSha3Ctr};
  DeterministicOqsRng* prev_instance_{nullptr};

  std::mt19937_64 engine_{};
  std::array<std::uint8_t, 32> buffer_{};
  std::size_t buffer_index_{0};
  std::uint64_t word_{0};
  std::size_t word_index_{0};
  std::array<std::uint8_t, 32> seed_material_{};
  std::uint64_t counter_{0};
  OQS_SHA3_shake256_inc_ctx shake_ctx_{};
  bool shake_initialized_{false};
};

}  // namespace qryptcoin::crypto
