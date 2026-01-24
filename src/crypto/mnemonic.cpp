#include "crypto/mnemonic.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <vector>

#include "crypto/mnemonic_wordlist_en.hpp"
#include "crypto/hash.hpp"
#include "util/pbkdf2.hpp"
#include "util/secure_wipe.hpp"

namespace qryptcoin::crypto {

namespace {

const std::unordered_map<std::string, std::uint16_t>& EnglishMnemonicWordIndex() {
  static const std::unordered_map<std::string, std::uint16_t> index = [] {
    std::unordered_map<std::string, std::uint16_t> out;
    const auto& wordlist = EnglishMnemonicWordlist();
    out.reserve(wordlist.size());
    for (std::size_t i = 0; i < wordlist.size(); ++i) {
      out.emplace(wordlist[i], static_cast<std::uint16_t>(i));
    }
    return out;
  }();
  return index;
}

bool IsSpace(char ch) {
  return std::isspace(static_cast<unsigned char>(ch)) != 0;
}

std::string LowercaseAscii(std::string_view input) {
  std::string out(input);
  for (char& ch : out) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return out;
}

}  // namespace

std::array<std::uint8_t, 64> MnemonicSeedFromSentence(const std::string& mnemonic_sentence,
                                                      const std::string& passphrase) {
  // salt = "mnemonic" + passphrase (UTF-8, no NUL terminator).
  std::string salt = "mnemonic";
  salt.append(passphrase);
  const auto salt_bytes = std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size());

  auto seed_vec = util::Pbkdf2HmacSha512(mnemonic_sentence, salt_bytes, 2048u, 64u);

  std::array<std::uint8_t, 64> seed{};
  std::copy_n(seed_vec.begin(), seed.size(), seed.begin());
  util::SecureWipe(seed_vec);
  util::SecureWipe(salt);
  return seed;
}

const std::vector<std::string>& EnglishMnemonicWordlist() {
  static const std::vector<std::string> wordlist = []() {
    std::vector<std::string> out;
    out.reserve(kEnglishMnemonicWordlistEn.size());
    for (const auto word : kEnglishMnemonicWordlistEn) {
      out.emplace_back(word);
    }
    return out;
  }();
  return wordlist;
}

bool ValidateMnemonic24(std::string_view mnemonic_sentence, std::string* error) {
  if (error) {
    error->clear();
  }
  const auto& wordlist = EnglishMnemonicWordlist();
  if (wordlist.size() != 2048) {
    if (error) {
      *error = "mnemonic wordlist is not initialized";
    }
    return false;
  }

  std::array<std::uint16_t, 24> indices{};
  std::size_t word_count = 0;
  std::size_t pos = 0;
  while (pos < mnemonic_sentence.size()) {
    while (pos < mnemonic_sentence.size() && IsSpace(mnemonic_sentence[pos])) {
      ++pos;
    }
    if (pos >= mnemonic_sentence.size()) {
      break;
    }
    const std::size_t start = pos;
    while (pos < mnemonic_sentence.size() && !IsSpace(mnemonic_sentence[pos])) {
      ++pos;
    }
    const auto word_view = mnemonic_sentence.substr(start, pos - start);
    if (word_view.empty()) {
      continue;
    }
    if (word_count >= indices.size()) {
      if (error) {
        *error = "mnemonic must contain exactly 24 words";
      }
      return false;
    }
    std::string word = LowercaseAscii(word_view);
    const auto& index = EnglishMnemonicWordIndex();
    auto it = index.find(word);
    if (it == index.end()) {
      if (error) {
        *error = "mnemonic contains a word not in the English wordlist";
      }
      util::SecureWipe(word);
      return false;
    }
    indices[word_count++] = it->second;
    util::SecureWipe(word);
  }

  if (word_count != indices.size()) {
    if (error) {
      *error = "mnemonic must contain exactly 24 words";
    }
    util::SecureWipe(indices);
    return false;
  }

  // Reconstruct the 264-bit sequence (256-bit entropy + 8-bit checksum).
  std::array<std::uint8_t, 33> packed{};
  std::size_t bit_pos = 0;
  for (std::uint16_t value : indices) {
    for (int bit = 10; bit >= 0; --bit) {
      const bool set = ((value >> bit) & 0x01u) != 0;
      if (set) {
        const std::size_t byte_index = bit_pos / 8;
        const std::size_t bit_index = 7 - (bit_pos % 8);
        packed[byte_index] =
            static_cast<std::uint8_t>(packed[byte_index] | (1u << bit_index));
      }
      ++bit_pos;
    }
  }
  util::SecureWipe(indices);
  if (bit_pos != 264) {
    if (error) {
      *error = "mnemonic encoding is invalid";
    }
    util::SecureWipe(packed);
    return false;
  }

  std::array<std::uint8_t, 32> entropy{};
  std::copy_n(packed.begin(), entropy.size(), entropy.begin());
  const std::uint8_t checksum_bits = packed[32];
  util::SecureWipe(packed);
  const auto expected_hash = Sha256(entropy);
  util::SecureWipe(entropy);
  if (expected_hash[0] != checksum_bits) {
    if (error) {
      *error = "mnemonic checksum mismatch";
    }
    return false;
  }
  return true;
}

}  // namespace qryptcoin::crypto
