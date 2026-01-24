#include <cstdint>
#include <iostream>
#include <vector>

#include "primitives/serialize.hpp"

namespace {

bool ExpectEq(const std::vector<std::uint8_t>& actual, const std::vector<std::uint8_t>& expected,
              const char* label) {
  if (actual != expected) {
    std::cerr << label << ": mismatch (size " << actual.size() << " vs " << expected.size()
              << ")\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  using namespace qryptcoin::primitives::serialize;

  {
    std::vector<std::uint8_t> out;
    WriteVarInt(&out, 0xFC);
    if (!ExpectEq(out, {0xFC}, "encode 0xFC")) return 1;
  }

  {
    std::vector<std::uint8_t> out;
    WriteVarInt(&out, 0xFD);
    if (!ExpectEq(out, {0xFD, 0xFD, 0x00}, "encode 0xFD")) return 1;
  }

  {
    std::vector<std::uint8_t> out;
    WriteVarInt(&out, 300);
    if (!ExpectEq(out, {0xFD, 0x2C, 0x01}, "encode 300")) return 1;
  }

  {
    std::vector<std::uint8_t> out;
    WriteVarIntLegacy(&out, 300);
    if (!ExpectEq(out, {0xFD, 0x2C, 0x01, 0x00, 0x00}, "encode legacy 300")) return 1;
    std::size_t offset = 0;
    std::uint64_t value = 0;
    if (!ReadVarIntLegacy(out, &offset, &value) || value != 300 || offset != out.size()) {
      std::cerr << "decode legacy 300 failed\n";
      return 1;
    }
  }

  // Non-canonical encodings should be rejected.
  {
    const std::vector<std::uint8_t> non_canonical = {0xFD, 0xFC, 0x00};  // 0xFC must be 1 byte
    std::size_t offset = 0;
    std::uint64_t value = 0;
    if (ReadVarInt(non_canonical, &offset, &value)) {
      std::cerr << "non-canonical 0xFC accepted\n";
      return 1;
    }
  }

  {
    const std::vector<std::uint8_t> non_canonical = {0xFE, 0xFF, 0xFF, 0x00, 0x00};  // 0xFFFF
    std::size_t offset = 0;
    std::uint64_t value = 0;
    if (ReadVarInt(non_canonical, &offset, &value)) {
      std::cerr << "non-canonical 0xFFFF accepted\n";
      return 1;
    }
  }

  {
    const std::vector<std::uint8_t> non_canonical = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};
    std::size_t offset = 0;
    std::uint64_t value = 0;
    if (ReadVarInt(non_canonical, &offset, &value)) {
      std::cerr << "non-canonical 0xFFFFFFFF accepted\n";
      return 1;
    }
  }

  return 0;
}

