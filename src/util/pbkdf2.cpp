#include "util/pbkdf2.hpp"

#include <array>
#include <cstring>

namespace qryptcoin::util {

namespace {

// Minimal SHA-512 implementation sufficient for PBKDF2/HMAC.

struct Sha512Ctx {
  std::array<std::uint64_t, 8> state{};
  std::uint64_t bitlen_high{0};
  std::uint64_t bitlen_low{0};
  std::array<std::uint8_t, 128> buffer{};
  std::size_t buffer_len{0};
};

constexpr std::uint64_t kSha512InitState[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

constexpr std::uint64_t kSha512RoundK[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

inline std::uint64_t RotR(std::uint64_t x, std::uint64_t n) {
  return (x >> n) | (x << (64 - n));
}

inline std::uint64_t Ch(std::uint64_t x, std::uint64_t y, std::uint64_t z) {
  return (x & y) ^ (~x & z);
}

inline std::uint64_t Maj(std::uint64_t x, std::uint64_t y, std::uint64_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

inline std::uint64_t BigSigma0(std::uint64_t x) {
  return RotR(x, 28) ^ RotR(x, 34) ^ RotR(x, 39);
}

inline std::uint64_t BigSigma1(std::uint64_t x) {
  return RotR(x, 14) ^ RotR(x, 18) ^ RotR(x, 41);
}

inline std::uint64_t SmallSigma0(std::uint64_t x) {
  return RotR(x, 1) ^ RotR(x, 8) ^ (x >> 7);
}

inline std::uint64_t SmallSigma1(std::uint64_t x) {
  return RotR(x, 19) ^ RotR(x, 61) ^ (x >> 6);
}

void Sha512Init(Sha512Ctx* ctx) {
  ctx->state = {kSha512InitState[0], kSha512InitState[1], kSha512InitState[2], kSha512InitState[3],
                kSha512InitState[4], kSha512InitState[5], kSha512InitState[6], kSha512InitState[7]};
  ctx->bitlen_high = 0;
  ctx->bitlen_low = 0;
  ctx->buffer_len = 0;
}

void Sha512Transform(Sha512Ctx* ctx, const std::uint8_t* block) {
  std::uint64_t w[80];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint64_t>(block[i * 8 + 0]) << 56) |
           (static_cast<std::uint64_t>(block[i * 8 + 1]) << 48) |
           (static_cast<std::uint64_t>(block[i * 8 + 2]) << 40) |
           (static_cast<std::uint64_t>(block[i * 8 + 3]) << 32) |
           (static_cast<std::uint64_t>(block[i * 8 + 4]) << 24) |
           (static_cast<std::uint64_t>(block[i * 8 + 5]) << 16) |
           (static_cast<std::uint64_t>(block[i * 8 + 6]) << 8) |
           (static_cast<std::uint64_t>(block[i * 8 + 7]) << 0);
  }
  for (int i = 16; i < 80; ++i) {
    w[i] = SmallSigma1(w[i - 2]) + w[i - 7] + SmallSigma0(w[i - 15]) + w[i - 16];
  }

  std::uint64_t a = ctx->state[0];
  std::uint64_t b = ctx->state[1];
  std::uint64_t c = ctx->state[2];
  std::uint64_t d = ctx->state[3];
  std::uint64_t e = ctx->state[4];
  std::uint64_t f = ctx->state[5];
  std::uint64_t g = ctx->state[6];
  std::uint64_t h = ctx->state[7];

  for (int i = 0; i < 80; ++i) {
    const auto T1 = h + BigSigma1(e) + Ch(e, f, g) + kSha512RoundK[i] + w[i];
    const auto T2 = BigSigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
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

void Sha512Update(Sha512Ctx* ctx, const std::uint8_t* data, std::size_t len) {
  while (len > 0) {
    const std::size_t to_copy =
        std::min<std::size_t>(len, ctx->buffer.size() - ctx->buffer_len);
    std::memcpy(ctx->buffer.data() + ctx->buffer_len, data, to_copy);
    ctx->buffer_len += to_copy;
    data += to_copy;
    len -= to_copy;

    // Update bit length (128-bit counter).
    std::uint64_t bits = static_cast<std::uint64_t>(to_copy) * 8;
    ctx->bitlen_low += bits;
    if (ctx->bitlen_low < bits) {
      ++ctx->bitlen_high;
    }

    if (ctx->buffer_len == ctx->buffer.size()) {
      Sha512Transform(ctx, ctx->buffer.data());
      ctx->buffer_len = 0;
    }
  }
}

void Sha512Final(Sha512Ctx* ctx, std::uint8_t out[64]) {
  // Append '1' bit.
  ctx->buffer[ctx->buffer_len++] = 0x80;

  // Pad with zeros until we have 112 bytes in buffer.
  if (ctx->buffer_len > 112) {
    while (ctx->buffer_len < ctx->buffer.size()) {
      ctx->buffer[ctx->buffer_len++] = 0x00;
    }
    Sha512Transform(ctx, ctx->buffer.data());
    ctx->buffer_len = 0;
  }
  while (ctx->buffer_len < 112) {
    ctx->buffer[ctx->buffer_len++] = 0x00;
  }

  // Append 128-bit length (big-endian).
  const std::uint64_t high = ctx->bitlen_high;
  const std::uint64_t low = ctx->bitlen_low;
  ctx->buffer[112] = static_cast<std::uint8_t>((high >> 56) & 0xFF);
  ctx->buffer[113] = static_cast<std::uint8_t>((high >> 48) & 0xFF);
  ctx->buffer[114] = static_cast<std::uint8_t>((high >> 40) & 0xFF);
  ctx->buffer[115] = static_cast<std::uint8_t>((high >> 32) & 0xFF);
  ctx->buffer[116] = static_cast<std::uint8_t>((high >> 24) & 0xFF);
  ctx->buffer[117] = static_cast<std::uint8_t>((high >> 16) & 0xFF);
  ctx->buffer[118] = static_cast<std::uint8_t>((high >> 8) & 0xFF);
  ctx->buffer[119] = static_cast<std::uint8_t>((high >> 0) & 0xFF);
  ctx->buffer[120] = static_cast<std::uint8_t>((low >> 56) & 0xFF);
  ctx->buffer[121] = static_cast<std::uint8_t>((low >> 48) & 0xFF);
  ctx->buffer[122] = static_cast<std::uint8_t>((low >> 40) & 0xFF);
  ctx->buffer[123] = static_cast<std::uint8_t>((low >> 32) & 0xFF);
  ctx->buffer[124] = static_cast<std::uint8_t>((low >> 24) & 0xFF);
  ctx->buffer[125] = static_cast<std::uint8_t>((low >> 16) & 0xFF);
  ctx->buffer[126] = static_cast<std::uint8_t>((low >> 8) & 0xFF);
  ctx->buffer[127] = static_cast<std::uint8_t>((low >> 0) & 0xFF);

  Sha512Transform(ctx, ctx->buffer.data());

  for (int i = 0; i < 8; ++i) {
    out[i * 8 + 0] = static_cast<std::uint8_t>((ctx->state[i] >> 56) & 0xFF);
    out[i * 8 + 1] = static_cast<std::uint8_t>((ctx->state[i] >> 48) & 0xFF);
    out[i * 8 + 2] = static_cast<std::uint8_t>((ctx->state[i] >> 40) & 0xFF);
    out[i * 8 + 3] = static_cast<std::uint8_t>((ctx->state[i] >> 32) & 0xFF);
    out[i * 8 + 4] = static_cast<std::uint8_t>((ctx->state[i] >> 24) & 0xFF);
    out[i * 8 + 5] = static_cast<std::uint8_t>((ctx->state[i] >> 16) & 0xFF);
    out[i * 8 + 6] = static_cast<std::uint8_t>((ctx->state[i] >> 8) & 0xFF);
    out[i * 8 + 7] = static_cast<std::uint8_t>((ctx->state[i] >> 0) & 0xFF);
  }
}

void Sha512(const std::uint8_t* data, std::size_t len, std::uint8_t out[64]) {
  Sha512Ctx ctx;
  Sha512Init(&ctx);
  Sha512Update(&ctx, data, len);
  Sha512Final(&ctx, out);
}

void HmacSha512(const std::uint8_t* key, std::size_t key_len,
                const std::uint8_t* data, std::size_t data_len,
                std::uint8_t out[64]) {
  constexpr std::size_t kBlockSize = 128;
  std::uint8_t key_block[kBlockSize];
  if (key_len > kBlockSize) {
    Sha512(key, key_len, key_block);
    std::memset(key_block + 64, 0, kBlockSize - 64);
  } else {
    std::memset(key_block, 0, kBlockSize);
    std::memcpy(key_block, key, key_len);
  }

  std::uint8_t o_key_pad[kBlockSize];
  std::uint8_t i_key_pad[kBlockSize];
  for (std::size_t i = 0; i < kBlockSize; ++i) {
    o_key_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x5c);
    i_key_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x36);
  }

  // inner = SHA512(i_key_pad || data)
  Sha512Ctx inner_ctx;
  Sha512Init(&inner_ctx);
  Sha512Update(&inner_ctx, i_key_pad, kBlockSize);
  Sha512Update(&inner_ctx, data, data_len);
  std::uint8_t inner_hash[64];
  Sha512Final(&inner_ctx, inner_hash);

  // outer = SHA512(o_key_pad || inner_hash)
  Sha512Ctx outer_ctx;
  Sha512Init(&outer_ctx);
  Sha512Update(&outer_ctx, o_key_pad, kBlockSize);
  Sha512Update(&outer_ctx, inner_hash, sizeof(inner_hash));
  Sha512Final(&outer_ctx, out);
}

}  // namespace

std::vector<std::uint8_t> Pbkdf2HmacSha512(const std::string& password,
                                           std::span<const std::uint8_t> salt,
                                           std::uint32_t iterations,
                                           std::size_t dk_len) {
  std::vector<std::uint8_t> dk(dk_len);
  const auto pw_bytes =
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(password.data()),
                                    password.size());

  const std::size_t hlen = 64;
  const std::uint32_t block_count =
      static_cast<std::uint32_t>((dk_len + hlen - 1) / hlen);

  std::vector<std::uint8_t> salt_block(salt.begin(), salt.end());
  salt_block.resize(salt.size() + 4);

  std::size_t offset = 0;
  for (std::uint32_t block_index = 1; block_index <= block_count; ++block_index) {
    // salt || INT_32_BE(block_index)
    salt_block[salt.size() + 0] =
        static_cast<std::uint8_t>((block_index >> 24) & 0xFF);
    salt_block[salt.size() + 1] =
        static_cast<std::uint8_t>((block_index >> 16) & 0xFF);
    salt_block[salt.size() + 2] =
        static_cast<std::uint8_t>((block_index >> 8) & 0xFF);
    salt_block[salt.size() + 3] =
        static_cast<std::uint8_t>((block_index >> 0) & 0xFF);

    std::uint8_t u[64];
    std::uint8_t t[64];
    HmacSha512(pw_bytes.data(), pw_bytes.size(),
               salt_block.data(), salt_block.size(), u);
    std::memcpy(t, u, sizeof(t));

    for (std::uint32_t i = 1; i < iterations; ++i) {
      HmacSha512(pw_bytes.data(), pw_bytes.size(), u, sizeof(u), u);
      for (std::size_t j = 0; j < sizeof(t); ++j) {
        t[j] ^= u[j];
      }
    }

    const std::size_t to_copy = std::min<std::size_t>(hlen, dk_len - offset);
    std::memcpy(dk.data() + offset, t, to_copy);
    offset += to_copy;
  }
  return dk;
}

}  // namespace qryptcoin::util

