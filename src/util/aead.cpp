#include "util/aead.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace qryptcoin::util {

namespace {

// --- Utility helpers --------------------------------------------------------

inline std::uint32_t Load32(const std::uint8_t* in) {
  return static_cast<std::uint32_t>(in[0]) |
         (static_cast<std::uint32_t>(in[1]) << 8) |
         (static_cast<std::uint32_t>(in[2]) << 16) |
         (static_cast<std::uint32_t>(in[3]) << 24);
}

inline void Store32(std::uint8_t* out, std::uint32_t value) {
  out[0] = static_cast<std::uint8_t>(value & 0xff);
  out[1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
  out[2] = static_cast<std::uint8_t>((value >> 16) & 0xff);
  out[3] = static_cast<std::uint8_t>((value >> 24) & 0xff);
}

inline void Store64(std::uint8_t* out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xff);
  }
}

// Constant‑time comparison of two tags.
bool ConstantTimeEqual(std::span<const std::uint8_t> a,
                       std::span<const std::uint8_t> b) {
  if (a.size() != b.size()) return false;
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
  }
  return diff == 0;
}

// --- ChaCha20 core (RFC 8439) ----------------------------------------------

void QuarterRound(std::uint32_t& a, std::uint32_t& b,
                  std::uint32_t& c, std::uint32_t& d) {
  a += b; d ^= a; d = (d << 16) | (d >> 16);
  c += d; b ^= c; b = (b << 12) | (b >> 20);
  a += b; d ^= a; d = (d << 8) | (d >> 24);
  c += d; b ^= c; b = (b << 7) | (b >> 25);
}

void ChaCha20Block(const std::uint32_t in[16], std::uint8_t out[64]) {
  std::uint32_t x[16];
  std::copy(in, in + 16, x);

  for (int i = 0; i < 10; ++i) {
    // Odd round.
    QuarterRound(x[0], x[4], x[8],  x[12]);
    QuarterRound(x[1], x[5], x[9],  x[13]);
    QuarterRound(x[2], x[6], x[10], x[14]);
    QuarterRound(x[3], x[7], x[11], x[15]);
    // Even round.
    QuarterRound(x[0], x[5], x[10], x[15]);
    QuarterRound(x[1], x[6], x[11], x[12]);
    QuarterRound(x[2], x[7], x[8],  x[13]);
    QuarterRound(x[3], x[4], x[9],  x[14]);
  }

  for (int i = 0; i < 16; ++i) {
    x[i] += in[i];
    Store32(out + 4 * i, x[i]);
  }
}

void InitChaCha20State(std::uint32_t state[16],
                       std::span<const std::uint8_t> key,
                       std::span<const std::uint8_t> nonce,
                       std::uint32_t counter) {
  // "expand 32-byte k"
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  // 256‑bit key.
  state[4] = Load32(key.data() + 0);
  state[5] = Load32(key.data() + 4);
  state[6] = Load32(key.data() + 8);
  state[7] = Load32(key.data() + 12);
  state[8] = Load32(key.data() + 16);
  state[9] = Load32(key.data() + 20);
  state[10] = Load32(key.data() + 24);
  state[11] = Load32(key.data() + 28);

  state[12] = counter;
  state[13] = Load32(nonce.data() + 0);
  state[14] = Load32(nonce.data() + 4);
  state[15] = Load32(nonce.data() + 8);
}

void ChaCha20Xor(std::span<const std::uint8_t> key,
                 std::span<const std::uint8_t> nonce,
                 std::uint32_t counter,
                 std::span<std::uint8_t> data) {
  std::uint32_t state[16];
  std::uint8_t block[64];

  std::size_t offset = 0;
  while (offset < data.size()) {
    InitChaCha20State(state, key, nonce, counter++);
    ChaCha20Block(state, block);
    const std::size_t chunk = std::min<std::size_t>(64, data.size() - offset);
    for (std::size_t i = 0; i < chunk; ++i) {
      data[offset + i] ^= block[i];
    }
    offset += chunk;
  }
}

// --- Poly1305 one‑time authenticator (26‑bit limbs, RFC 8439) --------------

struct Poly1305State {
  // r and h are represented as 26‑bit limbs.
  std::uint32_t r[5]{};
  std::uint32_t s[4]{};  // pad (s) as four 32‑bit words.
  std::uint32_t h[5]{};
};

void Poly1305Init(Poly1305State* st, const std::uint8_t key[32]) {
  const std::uint32_t t0 = Load32(key + 0);
  const std::uint32_t t1 = Load32(key + 4);
  const std::uint32_t t2 = Load32(key + 8);
  const std::uint32_t t3 = Load32(key + 12);

  // Clamp r as specified in RFC 8439.
  st->r[0] =  t0                      & 0x3ffffff;
  st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
  st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
  st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
  st->r[4] =  (t3 >> 8)                & 0x00fffff;

  st->s[0] = Load32(key + 16);
  st->s[1] = Load32(key + 20);
  st->s[2] = Load32(key + 24);
  st->s[3] = Load32(key + 28);

  std::fill(std::begin(st->h), std::end(st->h), 0);
}

void Poly1305Block(Poly1305State* st,
                   const std::uint8_t block[16],
                   std::uint32_t hibit) {
  const std::uint32_t r0 = st->r[0];
  const std::uint32_t r1 = st->r[1];
  const std::uint32_t r2 = st->r[2];
  const std::uint32_t r3 = st->r[3];
  const std::uint32_t r4 = st->r[4];

  const std::uint32_t r1_5 = r1 * 5;
  const std::uint32_t r2_5 = r2 * 5;
  const std::uint32_t r3_5 = r3 * 5;
  const std::uint32_t r4_5 = r4 * 5;

  std::uint32_t t0 = Load32(block + 0);
  std::uint32_t t1 = Load32(block + 4);
  std::uint32_t t2 = Load32(block + 8);
  std::uint32_t t3 = Load32(block + 12);

  std::uint64_t h0 = st->h[0];
  std::uint64_t h1 = st->h[1];
  std::uint64_t h2 = st->h[2];
  std::uint64_t h3 = st->h[3];
  std::uint64_t h4 = st->h[4];

  h0 +=  ( t0                    & 0x3ffffff);
  h1 += ((t0 >> 26) | (t1 << 6))  & 0x3ffffff;
  h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
  h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
  h4 +=  (t3 >> 8) | static_cast<std::uint64_t>(hibit);

  const std::uint64_t d0 = h0 * r0 + h1 * r4_5 + h2 * r3_5 + h3 * r2_5 + h4 * r1_5;
  const std::uint64_t d1 = h0 * r1 + h1 * r0   + h2 * r4_5 + h3 * r3_5 + h4 * r2_5;
  const std::uint64_t d2 = h0 * r2 + h1 * r1   + h2 * r0   + h3 * r4_5 + h4 * r3_5;
  const std::uint64_t d3 = h0 * r3 + h1 * r2   + h2 * r1   + h3 * r0   + h4 * r4_5;
  const std::uint64_t d4 = h0 * r4 + h1 * r3   + h2 * r2   + h3 * r1   + h4 * r0;

  std::uint64_t c;

  h0 = static_cast<std::uint32_t>(d0) & 0x3ffffff;
  c  = (d0 >> 26);
  h1 = static_cast<std::uint32_t>(d1 + c) & 0x3ffffff;
  c  = (d1 + c) >> 26;
  h2 = static_cast<std::uint32_t>(d2 + c) & 0x3ffffff;
  c  = (d2 + c) >> 26;
  h3 = static_cast<std::uint32_t>(d3 + c) & 0x3ffffff;
  c  = (d3 + c) >> 26;
  h4 = static_cast<std::uint32_t>(d4 + c) & 0x3ffffff;
  c  = (d4 + c) >> 26;

  h0 += c * 5;
  st->h[0] = static_cast<std::uint32_t>(h0);
  c = h0 >> 26;
  st->h[0] &= 0x3ffffff;
  st->h[1] = static_cast<std::uint32_t>(h1 + c);
  st->h[2] = static_cast<std::uint32_t>(h2);
  st->h[3] = static_cast<std::uint32_t>(h3);
  st->h[4] = static_cast<std::uint32_t>(h4);
}

void Poly1305Update(Poly1305State* st,
                    const std::uint8_t* m,
                    std::size_t bytes) {
  while (bytes >= 16) {
    Poly1305Block(st, m, (1u << 24));
    m += 16;
    bytes -= 16;
  }
  if (bytes > 0) {
    std::uint8_t block[16]{};
    std::memcpy(block, m, bytes);
    Poly1305Block(st, block, 0);
  }
}

void Poly1305Finish(Poly1305State* st, std::uint8_t mac[16]) {
  std::uint64_t h0 = st->h[0];
  std::uint64_t h1 = st->h[1];
  std::uint64_t h2 = st->h[2];
  std::uint64_t h3 = st->h[3];
  std::uint64_t h4 = st->h[4];

  std::uint64_t c = h1 >> 26;
  h1 &= 0x3ffffff;
  h2 += c;
  c = h2 >> 26;
  h2 &= 0x3ffffff;
  h3 += c;
  c = h3 >> 26;
  h3 &= 0x3ffffff;
  h4 += c;
  c = h4 >> 26;
  h4 &= 0x3ffffff;
  h0 += c * 5;
  c = h0 >> 26;
  h0 &= 0x3ffffff;
  h1 += c;

  // Compute h + -p.
  std::uint64_t g0 = h0 + 5;
  c = g0 >> 26;
  g0 &= 0x3ffffff;
  std::uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
  std::uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
  std::uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
  std::uint64_t g4 = h4 + c - (static_cast<std::uint64_t>(1) << 26);

  const std::uint64_t mask = (g4 >> 63) - 1;
  h0 = (h0 & ~mask) | (g0 & mask);
  h1 = (h1 & ~mask) | (g1 & mask);
  h2 = (h2 & ~mask) | (g2 & mask);
  h3 = (h3 & ~mask) | (g3 & mask);
  h4 = (h4 & ~mask) | (g4 & mask);

  std::uint64_t f0 = (h0      ) | (h1 << 26);
  std::uint64_t f1 = (h1 >> 38) | (h2 << 20);
  std::uint64_t f2 = (h2 >> 44) | (h3 << 14);
  std::uint64_t f3 = (h3 >> 50) | (h4 << 8);

  std::uint64_t t;

  t = f0 + st->s[0]; Store32(mac + 0, static_cast<std::uint32_t>(t)); t >>= 32;
  t += f1 + st->s[1]; Store32(mac + 4, static_cast<std::uint32_t>(t)); t >>= 32;
  t += f2 + st->s[2]; Store32(mac + 8, static_cast<std::uint32_t>(t)); t >>= 32;
  t += f3 + st->s[3]; Store32(mac + 12, static_cast<std::uint32_t>(t));
}

std::array<std::uint8_t, 16> Poly1305Mac(std::span<const std::uint8_t> one_time_key,
                                         std::span<const std::uint8_t> aad,
                                         std::span<const std::uint8_t> ciphertext) {
  Poly1305State st;
  std::uint8_t poly_key[32];
  std::memcpy(poly_key, one_time_key.data(), 32);
  Poly1305Init(&st, poly_key);

  // Process AAD.
  if (!aad.empty()) {
    Poly1305Update(&st, aad.data(), aad.size());
    const std::size_t pad = (16 - (aad.size() % 16)) % 16;
    if (pad) {
      static const std::uint8_t kZero[16]{};
      Poly1305Update(&st, kZero, pad);
    }
  }

  // Process ciphertext.
  if (!ciphertext.empty()) {
    Poly1305Update(&st, ciphertext.data(), ciphertext.size());
    const std::size_t pad = (16 - (ciphertext.size() % 16)) % 16;
    if (pad) {
      static const std::uint8_t kZero[16]{};
      Poly1305Update(&st, kZero, pad);
    }
  }

  // Length block: 64-bit little-endian lengths of AAD and ciphertext.
  std::uint8_t len_block[16];
  Store64(len_block + 0, static_cast<std::uint64_t>(aad.size()));
  Store64(len_block + 8, static_cast<std::uint64_t>(ciphertext.size()));
  Poly1305Update(&st, len_block, sizeof(len_block));

  std::uint8_t mac[16];
  Poly1305Finish(&st, mac);
  std::array<std::uint8_t, 16> out{};
  std::memcpy(out.data(), mac, 16);
  return out;
}

// --- AEAD glue --------------------------------------------------------------

// Derive Poly1305 one‑time key using ChaCha20 block 0; encrypt starting at block 1.
void DerivePolyKey(std::span<const std::uint8_t> key,
                   std::span<const std::uint8_t> nonce,
                   std::array<std::uint8_t, 32>* poly_key) {
  std::uint32_t state[16];
  std::uint8_t block0[64];
  InitChaCha20State(state, key, nonce, 0);
  ChaCha20Block(state, block0);
  std::memcpy(poly_key->data(), block0, 32);
}

}  // namespace

std::vector<std::uint8_t> ChaCha20Poly1305Encrypt(std::span<const std::uint8_t> key,
                                                  std::span<const std::uint8_t> nonce,
                                                  std::span<const std::uint8_t> aad,
                                                  std::span<const std::uint8_t> plaintext) {
  if (key.size() != kChaCha20Poly1305KeySize || nonce.size() != kChaCha20Poly1305NonceSize) {
    throw std::invalid_argument("invalid key/nonce length");
  }

  // Encrypt plaintext with ChaCha20 starting from counter = 1.
  std::vector<std::uint8_t> ciphertext(plaintext.begin(), plaintext.end());
  ChaCha20Xor(key, nonce, 1,
              std::span<std::uint8_t>(ciphertext.data(), ciphertext.size()));

  // Derive Poly1305 key and compute tag over AAD and ciphertext.
  std::array<std::uint8_t, 32> poly_key{};
  DerivePolyKey(key, nonce, &poly_key);
  const auto tag = Poly1305Mac(poly_key, aad, ciphertext);

  ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
  return ciphertext;
}

bool ChaCha20Poly1305Decrypt(std::span<const std::uint8_t> key,
                             std::span<const std::uint8_t> nonce,
                             std::span<const std::uint8_t> aad,
                             std::span<const std::uint8_t> ciphertext_and_tag,
                             std::vector<std::uint8_t>* plaintext) {
  if (key.size() != kChaCha20Poly1305KeySize || nonce.size() != kChaCha20Poly1305NonceSize) {
    return false;
  }
  if (ciphertext_and_tag.size() < kChaCha20Poly1305TagSize) {
    return false;
  }

  const std::size_t ct_len = ciphertext_and_tag.size() - kChaCha20Poly1305TagSize;
  std::span<const std::uint8_t> ciphertext(ciphertext_and_tag.data(), ct_len);
  std::span<const std::uint8_t> tag(ciphertext_and_tag.data() + ct_len,
                                    kChaCha20Poly1305TagSize);

  std::array<std::uint8_t, 32> poly_key{};
  DerivePolyKey(key, nonce, &poly_key);
  const auto computed_tag = Poly1305Mac(poly_key, aad, ciphertext);
  if (!ConstantTimeEqual(tag, computed_tag)) {
    return false;
  }

  plaintext->assign(ciphertext.begin(), ciphertext.end());
  ChaCha20Xor(key, nonce, 1,
              std::span<std::uint8_t>(plaintext->data(), plaintext->size()));
  return true;
}

}  // namespace qryptcoin::util

