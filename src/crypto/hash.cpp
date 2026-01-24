#include "crypto/hash.hpp"

#include <array>
#include <cstring>

#include <oqs/sha3.h>

namespace qryptcoin::crypto {

namespace {

template <std::size_t N>
std::array<std::uint8_t, N> MakeHashBuffer() {
  std::array<std::uint8_t, N> buffer{};
  buffer.fill(0);
  return buffer;
}

// Minimal self-contained SHA-256 implementation for proof-of-work and
// other double-hash constructions. The implementation follows FIPS-180-4
// and operates on big-endian words internally while accepting and
// emitting raw byte spans.

struct Sha256Context {
  std::uint32_t state[8];
  std::uint64_t bit_length;
  std::uint8_t buffer[64];
  std::size_t buffer_len;
};

constexpr std::uint32_t kSha256InitialState[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

inline std::uint32_t RotR(std::uint32_t x, std::uint32_t n) {
  return (x >> n) | (x << (32u - n));
}

inline std::uint32_t Ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & y) ^ (~x & z);
}

inline std::uint32_t Maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

inline std::uint32_t Sigma0(std::uint32_t x) {
  return RotR(x, 2u) ^ RotR(x, 13u) ^ RotR(x, 22u);
}

inline std::uint32_t Sigma1(std::uint32_t x) {
  return RotR(x, 6u) ^ RotR(x, 11u) ^ RotR(x, 25u);
}

inline std::uint32_t sigma0(std::uint32_t x) {
  return RotR(x, 7u) ^ RotR(x, 18u) ^ (x >> 3u);
}

inline std::uint32_t sigma1(std::uint32_t x) {
  return RotR(x, 17u) ^ RotR(x, 19u) ^ (x >> 10u);
}

void Sha256Init(Sha256Context* ctx) {
  if (!ctx) return;
  std::memcpy(ctx->state, kSha256InitialState, sizeof(kSha256InitialState));
  ctx->bit_length = 0;
  ctx->buffer_len = 0;
}

void Sha256Transform(Sha256Context* ctx, const std::uint8_t block[64]) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
           (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
           (static_cast<std::uint32_t>(block[i * 4 + 3]));
  }
  for (int i = 16; i < 64; ++i) {
    w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
  }

  std::uint32_t a = ctx->state[0];
  std::uint32_t b = ctx->state[1];
  std::uint32_t c = ctx->state[2];
  std::uint32_t d = ctx->state[3];
  std::uint32_t e = ctx->state[4];
  std::uint32_t f = ctx->state[5];
  std::uint32_t g = ctx->state[6];
  std::uint32_t h = ctx->state[7];

  for (int i = 0; i < 64; ++i) {
    const std::uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + kSha256K[i] + w[i];
    const std::uint32_t t2 = Sigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void Sha256Update(Sha256Context* ctx, const std::uint8_t* data, std::size_t len) {
  if (!ctx || (!data && len > 0)) return;
  ctx->bit_length += static_cast<std::uint64_t>(len) * 8u;
  std::size_t offset = 0;
  while (len > 0) {
    const std::size_t to_copy = std::min<std::size_t>(len, 64 - ctx->buffer_len);
    std::memcpy(ctx->buffer + ctx->buffer_len, data + offset, to_copy);
    ctx->buffer_len += to_copy;
    offset += to_copy;
    len -= to_copy;
    if (ctx->buffer_len == 64) {
      Sha256Transform(ctx, ctx->buffer);
      ctx->buffer_len = 0;
    }
  }
}

void Sha256Final(Sha256Context* ctx, std::uint8_t out[32]) {
  if (!ctx || !out) return;

  // Append the '1' bit.
  ctx->buffer[ctx->buffer_len++] = 0x80u;

  // Pad with zeros until we have room for the 64-bit length.
  if (ctx->buffer_len > 56) {
    while (ctx->buffer_len < 64) {
      ctx->buffer[ctx->buffer_len++] = 0u;
    }
    Sha256Transform(ctx, ctx->buffer);
    ctx->buffer_len = 0;
  }

  while (ctx->buffer_len < 56) {
    ctx->buffer[ctx->buffer_len++] = 0u;
  }

  // Total message length in bits (before padding).
  const std::uint64_t total_bits = ctx->bit_length;
  for (int i = 7; i >= 0; --i) {
    ctx->buffer[56 + (7 - i)] = static_cast<std::uint8_t>((total_bits >> (i * 8)) & 0xFFu);
  }

  Sha256Transform(ctx, ctx->buffer);

  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>((ctx->state[i] >> 24) & 0xFFu);
    out[i * 4 + 1] = static_cast<std::uint8_t>((ctx->state[i] >> 16) & 0xFFu);
    out[i * 4 + 2] = static_cast<std::uint8_t>((ctx->state[i] >> 8) & 0xFFu);
    out[i * 4 + 3] = static_cast<std::uint8_t>(ctx->state[i] & 0xFFu);
  }

  // Wipe the context to avoid accidentally leaking intermediate state.
  std::memset(ctx, 0, sizeof(Sha256Context));
}

}  // namespace

Sha3_256Hash Sha3_256(std::span<const std::uint8_t> data) {
  Sha3_256Hash buffer = MakeHashBuffer<32>();
  OQS_SHA3_sha3_256(buffer.data(), data.data(), data.size());
  return buffer;
}

Sha3_512Hash Sha3_512(std::span<const std::uint8_t> data) {
  Sha3_512Hash buffer = MakeHashBuffer<64>();
  OQS_SHA3_sha3_512(buffer.data(), data.data(), data.size());
  return buffer;
}

Sha3_256Hash DoubleSha3_256(std::span<const std::uint8_t> data) {
  const auto first = Sha3_256(data);
  return Sha3_256(first);
}

Sha256Hash Sha256(std::span<const std::uint8_t> data) {
  Sha256Context ctx{};
  Sha256Init(&ctx);
  if (!data.empty()) {
    Sha256Update(&ctx, data.data(), data.size());
  }
  std::uint8_t raw[32];
  Sha256Final(&ctx, raw);
  Sha256Hash out{};
  std::copy(std::begin(raw), std::end(raw), out.begin());
  return out;
}

Sha256Hash DoubleSha256(std::span<const std::uint8_t> data) {
  const auto first = Sha256(data);
  return Sha256(std::span<const std::uint8_t>(first.data(), first.size()));
}

std::vector<std::uint8_t> Sha3_256Vector(std::span<const std::uint8_t> data) {
  const auto hash = Sha3_256(data);
  return {hash.begin(), hash.end()};
}

}  // namespace qryptcoin::crypto
