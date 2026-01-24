#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "consensus/pow.hpp"
#include "util/hex.hpp"

using namespace qryptcoin;

namespace {

std::array<std::uint8_t, 32> ParseTargetHex(const std::string& hex) {
  std::array<std::uint8_t, 32> out{};
  std::vector<std::uint8_t> raw;
  if (!util::HexDecode(hex, &raw) || raw.size() != out.size()) {
    throw std::runtime_error("invalid target hex: " + hex);
  }
  std::copy(raw.begin(), raw.end(), out.begin());
  return out;
}

bool TestVector(std::uint32_t bits, const std::string& expected_hex) {
  auto expected = ParseTargetHex(expected_hex);
  auto target = consensus::CompactToTarget(bits);
  if (target != expected) {
    std::cerr << "CompactToTarget mismatch for bits=0x" << std::hex << bits
              << std::dec << "\n  expected=" << expected_hex
              << "\n  got=" << util::HexEncode(std::span<const std::uint8_t>(
                                  target.data(), target.size()))
              << "\n";
    return false;
  }
  const auto roundtrip = consensus::TargetToCompact(target);
  if (roundtrip != bits) {
    std::cerr << "TargetToCompact round-trip mismatch for bits=0x" << std::hex
              << bits << std::dec << "\n  got=0x" << std::hex << roundtrip
              << std::dec << "\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  try {
    // Baseline target value.
    if (!TestVector(0x1d00ffffu,
                    "00000000ffff0000000000000000000000000000000000000000000000000000")) {
      return EXIT_FAILURE;
    }

    // Additional compact-bits test vector.
    if (!TestVector(0x1b0404cbu,
                    "00000000000404cb000000000000000000000000000000000000000000000000")) {
      return EXIT_FAILURE;
    }

    // Zero target encodes as compact 0 and decodes back to all-zero.
    std::array<std::uint8_t, 32> zero_target{};
    const auto bits_zero = consensus::TargetToCompact(zero_target);
    if (bits_zero != 0u) {
      std::cerr << "TargetToCompact(all-zero) expected 0, got 0x" << std::hex
                << bits_zero << std::dec << "\n";
      return EXIT_FAILURE;
    }
    auto decoded_zero = consensus::CompactToTarget(0u);
    if (decoded_zero != zero_target) {
      std::cerr << "CompactToTarget(0) did not return all-zero target\n";
      return EXIT_FAILURE;
    }
  } catch (const std::exception& ex) {
    std::cerr << "compact_target_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << "compact_target_tests unknown exception\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
