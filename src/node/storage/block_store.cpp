#include "storage/block_store.hpp"

#include <filesystem>
#include <fstream>
#include <limits>
#include <vector>

#include "crypto/hash.hpp"
#include "primitives/serialize.hpp"

namespace qryptcoin::storage {

namespace {

constexpr std::uint32_t kBlockMagicV1 = 0x51424C4B;  // legacy (little-endian uint32)
constexpr std::uint32_t kBlockMagicV2 = 0x324C4251;  // 'QBL2' (little-endian uint32)
constexpr std::uint32_t kMaxBlockRecordSize = 1 * 1024 * 1024;  // 1 MiB safety cap

enum class RecordReadStatus {
  kOk,
  kEndOfFile,
  kTruncatedTail,
  kError,
};

bool ReadAll(std::ifstream* in, std::uint8_t* data, std::size_t len) {
  if (!in || !in->is_open()) return false;
  in->read(reinterpret_cast<char*>(data), static_cast<std::streamsize>(len));
  return in->good();
}

bool WriteAll(std::ofstream* out, const std::uint8_t* data, std::size_t len) {
  if (!out || !out->is_open()) return false;
  out->write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
  return out->good();
}

std::uint32_t DecodeU32LE(const std::uint8_t* data) {
  return static_cast<std::uint32_t>(data[0]) |
         (static_cast<std::uint32_t>(data[1]) << 8) |
         (static_cast<std::uint32_t>(data[2]) << 16) |
         (static_cast<std::uint32_t>(data[3]) << 24);
}

void EncodeU32LE(std::uint32_t value, std::uint8_t* out) {
  out[0] = static_cast<std::uint8_t>(value & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  out[2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  out[3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
}

RecordReadStatus ReadNextRecord(std::ifstream* in, primitives::CBlock* out_block,
                                std::uint64_t* out_record_bytes) {
  if (!in || !in->is_open()) {
    return RecordReadStatus::kError;
  }
  std::uint8_t header[8] = {0};
  in->read(reinterpret_cast<char*>(header), sizeof(header));
  if (in->eof()) {
    return RecordReadStatus::kEndOfFile;
  }
  if (!in->good()) {
    // Truncated header (e.g. crash during append): ignore tail.
    return RecordReadStatus::kTruncatedTail;
  }

  const std::uint32_t magic = DecodeU32LE(header);
  const std::uint32_t size = DecodeU32LE(header + 4);
  if (size == 0 || size > kMaxBlockRecordSize) {
    return RecordReadStatus::kError;
  }
  if (out_record_bytes) {
    *out_record_bytes = static_cast<std::uint64_t>(sizeof(header)) +
                        static_cast<std::uint64_t>(size) +
                        (magic == kBlockMagicV2 ? static_cast<std::uint64_t>(crypto::Sha3_256Hash{}.size())
                                                : 0ull);
  }

  primitives::CBlock block;
  std::vector<std::uint8_t> buffer(size);

  if (magic == kBlockMagicV2) {
    crypto::Sha3_256Hash expected{};
    if (!ReadAll(in, expected.data(), expected.size())) {
      return RecordReadStatus::kTruncatedTail;
    }
    if (!ReadAll(in, buffer.data(), buffer.size())) {
      return RecordReadStatus::kTruncatedTail;
    }
    const auto actual = crypto::Sha3_256(buffer);
    if (actual != expected) {
      return RecordReadStatus::kError;
    }
    std::size_t cursor = 0;
    if (!primitives::serialize::DeserializeBlock(buffer, &cursor, &block, /*legacy_varint=*/false) ||
        cursor != buffer.size()) {
      return RecordReadStatus::kError;
    }
  } else if (magic == kBlockMagicV1) {
    if (!ReadAll(in, buffer.data(), buffer.size())) {
      return RecordReadStatus::kTruncatedTail;
    }
    std::size_t cursor = 0;
    if (!primitives::serialize::DeserializeBlock(buffer, &cursor, &block, /*legacy_varint=*/true) ||
        cursor != buffer.size()) {
      // If the legacy-varint parser fails (e.g. the file was produced by a
      // newer writer but kept the old record header), fall back to canonical.
      cursor = 0;
      if (!primitives::serialize::DeserializeBlock(buffer, &cursor, &block, /*legacy_varint=*/false) ||
          cursor != buffer.size()) {
        return RecordReadStatus::kError;
      }
    }
  } else {
    return RecordReadStatus::kError;
  }

  if (out_block) {
    *out_block = std::move(block);
  }
  return RecordReadStatus::kOk;
}

}  // namespace

BlockStore::BlockStore(std::string path) : path_(std::move(path)) {
  std::filesystem::create_directories(std::filesystem::path(path_).parent_path());
}

bool BlockStore::Append(const primitives::CBlock& block) {
  return Append(block, nullptr);
}

bool BlockStore::Append(const primitives::CBlock& block, std::uint64_t* out_offset) {
  std::vector<std::uint8_t> buffer;
  primitives::serialize::SerializeBlock(block, &buffer);
  if (buffer.empty() || buffer.size() > kMaxBlockRecordSize) {
    return false;
  }
  const auto checksum = crypto::Sha3_256(buffer);

  std::ofstream out(path_, std::ios::binary | std::ios::app);
  if (!out.is_open()) {
    return false;
  }
  if (out_offset) {
    const auto pos = out.tellp();
    if (pos >= 0) {
      *out_offset = static_cast<std::uint64_t>(pos);
    } else {
      *out_offset = std::numeric_limits<std::uint64_t>::max();
    }
  }
  std::uint8_t header[8];
  EncodeU32LE(kBlockMagicV2, header);
  EncodeU32LE(static_cast<std::uint32_t>(buffer.size()), header + 4);
  if (!WriteAll(&out, header, sizeof(header))) return false;
  if (!WriteAll(&out, checksum.data(), checksum.size())) return false;
  if (!WriteAll(&out, buffer.data(), buffer.size())) return false;
  out.flush();
  return out.good();
}

bool BlockStore::ForEach(
    const std::function<bool(const primitives::CBlock&, std::size_t height,
                             std::uint64_t offset)>& visitor) const {
  std::ifstream in(path_, std::ios::binary);
  if (!in.is_open()) {
    return false;
  }
  std::size_t height = 0;
  std::uint64_t offset = 0;
  while (true) {
    primitives::CBlock block;
    std::uint64_t record_bytes = 0;
    const auto status = ReadNextRecord(&in, &block, &record_bytes);
    if (status == RecordReadStatus::kEndOfFile ||
        status == RecordReadStatus::kTruncatedTail) {
      break;
    }
    if (status != RecordReadStatus::kOk) {
      return false;
    }
    if (!visitor(block, height, offset)) {
      break;
    }
    offset += record_bytes;
    ++height;
  }
  return true;
}

bool BlockStore::ReadAt(std::uint64_t offset, primitives::CBlock* block) const {
  std::ifstream in(path_, std::ios::binary);
  if (!in.is_open()) {
    return false;
  }
  in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  if (!in.good()) {
    return false;
  }
  primitives::CBlock out;
  const auto status = ReadNextRecord(&in, &out, nullptr);
  if (status != RecordReadStatus::kOk) {
    return false;
  }
  if (block) {
    *block = std::move(out);
  }
  return true;
}

bool BlockStore::Exists() const {
  return std::filesystem::exists(path_);
}

}  // namespace qryptcoin::storage
