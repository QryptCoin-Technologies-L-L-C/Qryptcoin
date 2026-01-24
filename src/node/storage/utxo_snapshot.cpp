#include "storage/utxo_snapshot.hpp"

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

constexpr std::uint32_t kUtxoMagic = 0x5154584F;  // 'QTXO'
constexpr std::uint32_t kUtxoMagicV2 = 0x32585451;  // 'QTX2' (little-endian uint32)
constexpr std::uint16_t kUtxoVersionV2 = 2;
constexpr std::uint32_t kMaxCoinRecordSize = 4 * 1024 * 1024;  // 4 MiB safety cap

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

bool SaveUTXOSnapshot(const consensus::UTXOSet& view, const std::string& path) {
  std::string write_error;
  return util::AtomicWriteFile(
      std::filesystem::path(path),
      [&](std::ofstream& out) -> bool {
        if (!WriteU32(&out, kUtxoMagicV2)) return false;
        if (!WriteU16(&out, kUtxoVersionV2)) return false;

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

        const std::uint64_t entry_count = view.Size();
        if (!WriteU64(&out, entry_count)) return false;

        std::vector<std::uint8_t> buffer;
        buffer.reserve(512);
        std::vector<std::uint8_t> checksum_input;
        checksum_input.reserve(512 + 36);

        bool ok = true;
        view.ForEach([&](const primitives::COutPoint& outpoint, const consensus::Coin& coin) {
          if (!ok) return false;
          buffer.clear();
          primitives::serialize::WriteUint32(&buffer, coin.height);
          buffer.push_back(static_cast<std::uint8_t>(coin.coinbase));
          primitives::serialize::WriteUint64(&buffer, coin.out.value);
          primitives::serialize::WriteVarInt(&buffer, coin.out.locking_descriptor.size());
          buffer.insert(buffer.end(), coin.out.locking_descriptor.begin(),
                        coin.out.locking_descriptor.end());

          if (!WriteAll(&out, outpoint.txid.data(), outpoint.txid.size())) {
            ok = false;
            return false;
          }
          if (!WriteU32(&out, outpoint.index)) {
            ok = false;
            return false;
          }

          if (buffer.size() > kMaxCoinRecordSize) {
            ok = false;
            return false;
          }
          if (!WriteU32(&out, static_cast<std::uint32_t>(buffer.size()))) {
            ok = false;
            return false;
          }
          if (!WriteAll(&out, buffer.data(), buffer.size())) {
            ok = false;
            return false;
          }

          checksum_input.clear();
          checksum_input.insert(checksum_input.end(), outpoint.txid.begin(), outpoint.txid.end());
          primitives::serialize::WriteUint32(&checksum_input, outpoint.index);
          checksum_input.insert(checksum_input.end(), buffer.begin(), buffer.end());
          const auto digest = crypto::Sha3_256(checksum_input);
          if (!WriteAll(&out, digest.data(), digest.size())) {
            ok = false;
            return false;
          }
          return true;
        });
        return ok;
      },
      &write_error);
}

bool LoadUTXOSnapshot(consensus::UTXOSet* view, const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) {
    return false;
  }
  std::uint32_t magic = 0;
  if (!ReadU32(&in, &magic)) return false;

  if (magic == kUtxoMagicV2) {
    std::uint16_t version = 0;
    if (!ReadU16(&in, &version) || version != kUtxoVersionV2) return false;

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
    if (!ReadU64(&in, &entry_count)) return false;
    if (entry_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
      return false;
    }
    view->Reserve(static_cast<std::size_t>(entry_count));

    std::vector<std::uint8_t> checksum_input;
    checksum_input.reserve(512 + 36);

    for (std::uint64_t i = 0; i < entry_count; ++i) {
      primitives::COutPoint outpoint;
      if (!ReadAll(&in, outpoint.txid.data(), outpoint.txid.size())) return false;
      if (!ReadU32(&in, &outpoint.index)) return false;
      std::uint32_t coin_size = 0;
      if (!ReadU32(&in, &coin_size) || coin_size == 0 || coin_size > kMaxCoinRecordSize) {
        return false;
      }
      std::vector<std::uint8_t> buffer(coin_size);
      if (!ReadAll(&in, buffer.data(), buffer.size())) return false;
      crypto::Sha3_256Hash expected{};
      if (!ReadAll(&in, expected.data(), expected.size())) return false;

      checksum_input.clear();
      checksum_input.resize(outpoint.txid.size());
      for (std::size_t j = 0; j < outpoint.txid.size(); ++j) {
        checksum_input[j] = outpoint.txid[j];
      }
      primitives::serialize::WriteUint32(&checksum_input, outpoint.index);
      checksum_input.insert(checksum_input.end(), buffer.begin(), buffer.end());
      const auto actual = crypto::Sha3_256(checksum_input);
      if (actual != expected) return false;

      std::size_t offset = 0;
      consensus::Coin coin;
      if (!primitives::serialize::ReadUint32(buffer, &offset, &coin.height)) return false;
      if (offset >= buffer.size()) return false;
      coin.coinbase = buffer[offset++] != 0;
      std::uint64_t value = 0;
      if (!primitives::serialize::ReadUint64(buffer, &offset, &value)) return false;
      coin.out.value = static_cast<primitives::Amount>(value);
      std::uint64_t script_size = 0;
      if (!primitives::serialize::ReadVarInt(buffer, &offset, &script_size)) return false;
      if (script_size > buffer.size() - offset) return false;
      coin.out.locking_descriptor.assign(buffer.begin() + offset,
                                         buffer.begin() + offset + static_cast<std::size_t>(script_size));
      offset += static_cast<std::size_t>(script_size);
      if (offset != buffer.size()) return false;
      view->AddCoin(outpoint, coin);
    }
    return true;
  }

  if (magic != kUtxoMagic) {
    return false;
  }
  std::uint64_t entry_count = 0;
  if (!ReadU64(&in, &entry_count)) return false;
  if (entry_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    return false;
  }
  view->Reserve(static_cast<std::size_t>(entry_count));
  for (std::uint64_t i = 0; i < entry_count; ++i) {
    primitives::COutPoint outpoint;
    if (!ReadAll(&in, outpoint.txid.data(), outpoint.txid.size())) return false;
    if (!ReadU32(&in, &outpoint.index)) return false;
    std::uint32_t coin_size = 0;
    if (!ReadU32(&in, &coin_size) || coin_size == 0 || coin_size > kMaxCoinRecordSize) {
      return false;
    }
    std::vector<std::uint8_t> buffer(coin_size);
    if (!ReadAll(&in, buffer.data(), buffer.size())) return false;
    std::size_t offset = 0;
    consensus::Coin coin;
    if (!primitives::serialize::ReadUint32(buffer, &offset, &coin.height)) return false;
    if (offset >= buffer.size()) return false;
    coin.coinbase = buffer[offset++] != 0;
    std::uint64_t value = 0;
    if (!primitives::serialize::ReadUint64(buffer, &offset, &value)) return false;
    coin.out.value = static_cast<primitives::Amount>(value);
    std::uint64_t script_size = 0;
    if (!primitives::serialize::ReadVarInt(buffer, &offset, &script_size)) return false;
    if (script_size > buffer.size() - offset) return false;
    coin.out.locking_descriptor.assign(buffer.begin() + offset,
                                       buffer.begin() + offset + static_cast<std::size_t>(script_size));
    offset += static_cast<std::size_t>(script_size);
    view->AddCoin(outpoint, coin);
  }
  return true;
}

}  // namespace qryptcoin::storage
