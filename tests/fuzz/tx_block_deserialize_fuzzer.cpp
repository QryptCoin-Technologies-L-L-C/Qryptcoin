#include <cstddef>
#include <cstdint>
#include <exception>
#include <vector>

#include "tx/primitives/serialize.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  using qryptcoin::primitives::CBlock;
  using qryptcoin::primitives::CTransaction;
  using qryptcoin::primitives::serialize::DeserializeBlock;
  using qryptcoin::primitives::serialize::DeserializeTransaction;

  if (data == nullptr || size == 0) return 0;

  // Avoid pathological allocations/time on extremely large inputs.
  constexpr std::size_t kMaxInputBytes = 1u << 20;  // 1 MiB
  if (size > kMaxInputBytes) return 0;

  std::vector<std::uint8_t> buffer(data, data + size);

  const std::uint8_t mode = buffer[0];
  const bool parse_block = (mode & 0x01u) != 0;
  const bool legacy_varint = (mode & 0x02u) != 0;
  const bool allow_legacy_encoding = (mode & 0x04u) != 0;
  const bool expect_witness = (mode & 0x08u) == 0;

  // Catch allocation failures and parse errors - these are expected when
  // fuzzing malformed input and should not crash the harness.
  try {
    std::size_t offset = 1;
    if (parse_block) {
      CBlock block;
      (void)DeserializeBlock(buffer, &offset, &block, legacy_varint);
    } else {
      CTransaction tx;
      (void)DeserializeTransaction(buffer, &offset, &tx, expect_witness,
                                   allow_legacy_encoding, legacy_varint);
    }
  } catch (const std::exception&) {
    // Expected for malformed input (std::length_error, std::bad_alloc, etc.)
  }

  return 0;
}

