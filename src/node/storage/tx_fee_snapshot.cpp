#include "storage/tx_fee_snapshot.hpp"

#include <filesystem>
#include <fstream>
#include <limits>
#include <type_traits>
#include <vector>

#include "config/network.hpp"
#include "consensus/params.hpp"
#include "primitives/serialize.hpp"
#include "util/atomic_file.hpp"

namespace qryptcoin::storage {

namespace {

static_assert(std::is_same_v<primitives::Amount, std::uint64_t>,
              "TxFeeSnapshot expects primitives::Amount to be a uint64_t-compatible type.");

constexpr std::uint32_t kTxFeeMagicV1 = 0x32454651;  // 'QFE2' (little-endian uint32)
constexpr std::uint16_t kTxFeeVersionV1 = 1;
constexpr std::uint64_t kMaxEntries = 50'000'000ULL;

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

}  // namespace

bool SaveTxFeeSnapshot(const TxFeeMap& fees, const std::string& path) {
  std::string write_error;
  return util::AtomicWriteFile(
      std::filesystem::path(path),
      [&](std::ofstream& out) -> bool {
        if (!WriteU32(&out, kTxFeeMagicV1)) return false;
        if (!WriteU16(&out, kTxFeeVersionV1)) return false;

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

        const std::uint64_t entry_count = static_cast<std::uint64_t>(fees.size());
        if (!WriteU64(&out, entry_count)) return false;

        for (const auto& [txid, fee] : fees) {
          if (!WriteAll(&out, txid.data(), txid.size())) return false;
          if (!WriteU64(&out, static_cast<std::uint64_t>(fee))) return false;
        }
        out.flush();
        return out.good();
      },
      &write_error);
}

bool LoadTxFeeSnapshot(TxFeeMap* fees, const std::string& path) {
  if (!fees) {
    return false;
  }
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) {
    return false;
  }

  std::uint32_t magic = 0;
  if (!ReadU32(&in, &magic) || magic != kTxFeeMagicV1) return false;

  std::uint16_t version = 0;
  if (!ReadU16(&in, &version) || version != kTxFeeVersionV1) return false;

  std::uint64_t network_len = 0;
  if (!ReadVarInt(&in, &network_len) || network_len > 64) return false;
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
  if (!ReadU64(&in, &entry_count) || entry_count > kMaxEntries) return false;
  fees->clear();
  fees->reserve(static_cast<std::size_t>(
      std::min<std::uint64_t>(entry_count, static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))));

  for (std::uint64_t i = 0; i < entry_count; ++i) {
    primitives::Hash256 txid{};
    if (!ReadAll(&in, txid.data(), txid.size())) return false;
    std::uint64_t fee_u64 = 0;
    if (!ReadU64(&in, &fee_u64)) return false;
    fees->emplace(txid, static_cast<primitives::Amount>(fee_u64));
  }

  return in.good() || in.eof();
}

}  // namespace qryptcoin::storage
