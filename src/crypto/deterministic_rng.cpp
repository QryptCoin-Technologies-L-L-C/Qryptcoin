#include "crypto/deterministic_rng.hpp"

#include <algorithm>
#include <array>
#include <random>

#include <oqs/sha3.h>

#include "crypto/hash.hpp"
#include "util/secure_wipe.hpp"

namespace qryptcoin::crypto {

DeterministicOqsRng::DeterministicOqsRng(std::span<const std::uint8_t> seed, Mode mode)
    : mode_(mode), prev_instance_(Instance()) {
  std::array<std::uint8_t, 32> material{};
  const auto copy_len = std::min(seed.size(), material.size());
  std::copy_n(seed.begin(), copy_len, material.begin());

  if (mode_ == Mode::kLegacyMt19937) {
    seed_material_ = material;
    std::seed_seq seq(seed_material_.begin(), seed_material_.end());
    engine_.seed(seq);
    word_ = 0;
    word_index_ = 0;
  } else if (mode_ == Mode::kShake256Xof) {
    seed_material_ = material;
    OQS_SHA3_shake256_inc_init(&shake_ctx_);
    OQS_SHA3_shake256_inc_absorb(&shake_ctx_, seed_material_.data(), seed_material_.size());
    OQS_SHA3_shake256_inc_finalize(&shake_ctx_);
    shake_initialized_ = true;
  } else {
    seed_material_ =
        crypto::Sha3_256(std::span<const std::uint8_t>(material.data(), material.size()));
  }

  counter_ = 0;
  Refill();
  qryptcoin::util::SecureWipe(material);
  Instance() = this;
}

DeterministicOqsRng::~DeterministicOqsRng() {
  Instance() = prev_instance_;
  if (shake_initialized_) {
    OQS_SHA3_shake256_inc_ctx_release(&shake_ctx_);
    shake_initialized_ = false;
  }
  qryptcoin::util::SecureWipe(buffer_);
  qryptcoin::util::SecureWipe(seed_material_);
  qryptcoin::util::SecureWipe(&engine_, sizeof(engine_));
  qryptcoin::util::SecureWipe(&word_, sizeof(word_));
  qryptcoin::util::SecureWipe(&counter_, sizeof(counter_));
}

DeterministicOqsRng* DeterministicOqsRng::CurrentInstance() { return Instance(); }

DeterministicOqsRng*& DeterministicOqsRng::Instance() {
  thread_local DeterministicOqsRng* instance = nullptr;
  return instance;
}

void DeterministicOqsRng::Generate(std::uint8_t* out, std::size_t len) {
  if (out == nullptr || len == 0) {
    return;
  }
  auto* instance = Instance();
  if (instance == nullptr) {
    // Caller is expected to fall back to a system RNG when no
    // deterministic context is active; leave |out| unchanged here.
    return;
  }
  instance->Fill(out, len);
}

void DeterministicOqsRng::Fill(std::uint8_t* out, std::size_t len) {
  for (std::size_t i = 0; i < len; ++i) {
    if (buffer_index_ == buffer_.size()) {
      Refill();
    }
    out[i] = buffer_[buffer_index_++];
  }
}

void DeterministicOqsRng::Refill() {
  if (mode_ == Mode::kLegacyMt19937) {
    for (std::size_t i = 0; i < buffer_.size(); ++i) {
      if (i % 8 == 0) {
        word_ = engine_();
        word_index_ = 0;
      }
      buffer_[i] = static_cast<std::uint8_t>((word_ >> (word_index_ * 8)) & 0xFFu);
      word_index_ = (word_index_ + 1) % 8;
    }
    buffer_index_ = 0;
    return;
  }

  if (mode_ == Mode::kShake256Xof) {
    if (!shake_initialized_) {
      buffer_.fill(0);
      buffer_index_ = 0;
      return;
    }
    OQS_SHA3_shake256_inc_squeeze(buffer_.data(), buffer_.size(), &shake_ctx_);
    buffer_index_ = 0;
    return;
  }

  std::array<std::uint8_t, 40> input{};
  std::copy(seed_material_.begin(), seed_material_.end(), input.begin());
  for (int i = 0; i < 8; ++i) {
    input[32 + static_cast<std::size_t>(i)] =
        static_cast<std::uint8_t>((counter_ >> (8 * i)) & 0xFFu);
  }
  buffer_ = crypto::Sha3_256(std::span<const std::uint8_t>(input.data(), input.size()));
  buffer_index_ = 0;
  ++counter_;
}

}  // namespace qryptcoin::crypto
