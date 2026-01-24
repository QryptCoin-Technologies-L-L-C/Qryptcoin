#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace qryptcoin::crypto {

// Compute the 64-byte mnemonic seed from a 24-word sentence and optional
// passphrase using PBKDF2-HMAC-SHA512 with 2048 iterations:
//   seed = PBKDF2(mnemonic_sentence, "mnemonic" + passphrase, 2048, 64)
//
// Callers MUST validate the mnemonic first (see ValidateMnemonic24) and MUST
// pass the canonical encoding expected by the wallet: lowercase words joined
// by single ASCII spaces.
std::array<std::uint8_t, 64> MnemonicSeedFromSentence(const std::string& mnemonic_sentence,
                                                      const std::string& passphrase);

// Return the canonical 2048-word English mnemonic wordlist as UTF-8 strings.
// The returned reference is valid for the lifetime of the process.
const std::vector<std::string>& EnglishMnemonicWordlist();

// Validate a 24-word English mnemonic sentence with the SHA-256 checksum.
// This is a strict validator intended for wallet recovery:
// - exactly 24 whitespace-separated words
// - every word must exist in the canonical embedded English wordlist
// - checksum must match the derived 256-bit entropy
//
// Returns true if valid; on failure writes a human-readable reason to `error`.
bool ValidateMnemonic24(std::string_view mnemonic_sentence, std::string* error = nullptr);

}  // namespace qryptcoin::crypto
