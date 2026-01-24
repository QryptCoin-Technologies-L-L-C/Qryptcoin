#include "storage/revealed_pubkeys_snapshot.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <limits>
#include <vector>

#include "config/network.hpp"
#include "consensus/params.hpp"
#include "crypto/hash.hpp"
#include "primitives/serialize.hpp"
#include "util/atomic_file.hpp"

namespace qryptcoin::storage {

namespace {

constexpr std::uint32_t kPubkeysMagicV1 = 0x314B5051;  // 'QPK1' (little-endian uint32)
constexpr std::uint16_t kPubkeysVersionV1 = 1;

bool WriteAll(std::ofstream* out, const std::uint8_t* data, std::size_t len) {
  if (!out || !out->is_open()) return false;
  out->write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
  return out->good();
}

bool ReadAll(std::ifstream* in, std::uint8_t* data, std::size_t len) {
  if (!in || !in->is_open()) return false;
  in->read(reinterpret_cast<char*>(data), static_cast<std::streamsize>(len));
  return in->good();
}

bool WriteU16(std::ofstream* out, std::uint16_t value) {
  std::uint8_t buf[2] = {static_cast<std::uint8_t>(value & 0xFFu),
                         static_cast<std::uint8_t>((value >> 8) & 0xFFu)};
  return WriteAll(out, buf, sizeof(buf));
}

bool ReadU16(std::ifstream* in, std::uint16_t* out_value) {
  std::uint8_t buf[2] = {0};
  if (!ReadAll(in, buf, sizeof(buf))) return false;
  if (out_value) {
    *out_value =
        static_cast<std::uint16_t>(buf[0] | (static_cast<std::uint16_t>(buf[1]) << 8));
  }
  return true;
}

bool WriteU32(std::ofstream* out, std::uint32_t value) {
  std::uint8_t buf[4] = {static_cast<std::uint8_t>(value & 0xFFu),
                         static_cast<std::uint8_t>((value >> 8) & 0xFFu),
                         static_cast<std::uint8_t>((value >> 16) & 0xFFu),
                         static_cast<std::uint8_t>((value >> 24) & 0xFFu)};
  return WriteAll(out, buf, sizeof(buf));
}

bool ReadU32(std::ifstream* in, std::uint32_t* out_value) {
  std::uint8_t buf[4] = {0};
  if (!ReadAll(in, buf, sizeof(buf))) return false;
  if (out_value) {
    *out_value = static_cast<std::uint32_t>(buf[0]) |
                 (static_cast<std::uint32_t>(buf[1]) << 8) |
                 (static_cast<std::uint32_t>(buf[2]) << 16) |
                 (static_cast<std::uint32_t>(buf[3]) << 24);
  }
  return true;
}

bool WriteU64(std::ofstream* out, std::uint64_t value) {
  std::uint8_t buf[8] = {0};
  for (int i = 0; i < 8; ++i) {
    buf[i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFu);
  }
  return WriteAll(out, buf, sizeof(buf));
}

bool ReadU64(std::ifstream* in, std::uint64_t* out_value) {
  std::uint8_t buf[8] = {0};
  if (!ReadAll(in, buf, sizeof(buf))) return false;
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(buf[i]) << (8 * i);
  }
  if (out_value) {
    *out_value = value;
  }
  return true;
}

bool WriteVarInt(std::ofstream* out, std::uint64_t value) {
  std::vector<std::uint8_t> buf;
  buf.reserve(9);
  primitives::serialize::WriteVarInt(&buf, value);
  return WriteAll(out, buf.data(), buf.size());
}

bool ReadVarInt(std::ifstream* in, std::uint64_t* out_value) {
  std::uint8_t prefix = 0;
  if (!ReadAll(in, &prefix, 1)) return false;
  if (prefix < 0xFD) {
    if (out_value) *out_value = prefix;
    return true;
  }
  if (prefix == 0xFD) {
    std::uint16_t v16 = 0;
    if (!ReadU16(in, &v16)) return false;
    if (v16 < 0xFD) return false;
    if (out_value) *out_value = v16;
    return true;
  }
  if (prefix == 0xFE) {
    std::uint32_t v32 = 0;
    if (!ReadU32(in, &v32)) return false;
    if (v32 <= 0xFFFFu) return false;
    if (out_value) *out_value = v32;
    return true;
  }
  std::uint64_t v64 = 0;
  if (!ReadU64(in, &v64)) return false;
  if (v64 <= 0xFFFFFFFFULL) return false;
  if (out_value) *out_value = v64;
  return true;
}

std::vector<primitives::Hash256> SnapshotToSortedVector(const consensus::RevealedPubkeySet& set) {
  std::vector<primitives::Hash256> entries;
  entries.reserve(set.Size());
  set.ForEach([&](const primitives::Hash256& hash) {
    entries.push_back(hash);
    return true;
  });
  std::sort(entries.begin(), entries.end(),
            [](const primitives::Hash256& a, const primitives::Hash256& b) { return a < b; });
  return entries;
}

}  // namespace

bool SaveRevealedPubkeysSnapshot(const consensus::RevealedPubkeySet& set, const std::string& path) {
  std::string write_error;
  return util::AtomicWriteFile(
      std::filesystem::path(path),
      [&](std::ofstream& out) -> bool {
        if (!WriteU32(&out, kPubkeysMagicV1)) return false;
        if (!WriteU16(&out, kPubkeysVersionV1)) return false;

        const auto& cfg = config::GetNetworkConfig();
        const auto& genesis = consensus::Params(cfg.type).genesis_hash;
        if (!WriteVarInt(&out, cfg.network_id.size())) return false;
        if (!cfg.network_id.empty()) {
          if (!WriteAll(&out, reinterpret_cast<const std::uint8_t*>(cfg.network_id.data()),
                        cfg.network_id.size())) {
            return false;
          }
        }
        if (!WriteAll(&out, genesis.data(), genesis.size())) return false;

        const std::uint64_t entry_count = set.Size();
        if (!WriteU64(&out, entry_count)) return false;

        const auto entries = SnapshotToSortedVector(set);
        for (const auto& hash : entries) {
          if (!WriteAll(&out, hash.data(), hash.size())) return false;
          const auto digest =
              crypto::Sha3_256(std::span<const std::uint8_t>(hash.data(), hash.size()));
          if (!WriteAll(&out, digest.data(), digest.size())) return false;
        }
        return true;
      },
      &write_error);
}

bool LoadRevealedPubkeysSnapshot(consensus::RevealedPubkeySet* set, const std::string& path) {
  if (!set) {
    return false;
  }
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) {
    return false;
  }
  std::uint32_t magic = 0;
  if (!ReadU32(&in, &magic) || magic != kPubkeysMagicV1) {
    return false;
  }
  std::uint16_t version = 0;
  if (!ReadU16(&in, &version) || version != kPubkeysVersionV1) {
    return false;
  }

  std::uint64_t network_len = 0;
  if (!ReadVarInt(&in, &network_len) || network_len > 64) {
    return false;
  }
  std::string network_id;
  network_id.resize(static_cast<std::size_t>(network_len));
  if (network_len > 0) {
    if (!ReadAll(&in, reinterpret_cast<std::uint8_t*>(network_id.data()),
                 static_cast<std::size_t>(network_len))) {
      return false;
    }
  }
  primitives::Hash256 genesis{};
  if (!ReadAll(&in, genesis.data(), genesis.size())) return false;

  const auto& cfg = config::GetNetworkConfig();
  const auto& expected_genesis = consensus::Params(cfg.type).genesis_hash;
  if (network_id != cfg.network_id || genesis != expected_genesis) {
    return false;
  }

  std::uint64_t entry_count = 0;
  if (!ReadU64(&in, &entry_count)) return false;
  if (entry_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    return false;
  }

  set->Clear();
  set->Reserve(static_cast<std::size_t>(entry_count));

  for (std::uint64_t i = 0; i < entry_count; ++i) {
    primitives::Hash256 hash{};
    if (!ReadAll(&in, hash.data(), hash.size())) return false;
    crypto::Sha3_256Hash expected{};
    if (!ReadAll(&in, expected.data(), expected.size())) return false;
    const auto actual =
        crypto::Sha3_256(std::span<const std::uint8_t>(hash.data(), hash.size()));
    if (actual != expected) return false;
    if (!set->Insert(hash)) {
      return false;
    }
  }

  return true;
}

}  // namespace qryptcoin::storage

