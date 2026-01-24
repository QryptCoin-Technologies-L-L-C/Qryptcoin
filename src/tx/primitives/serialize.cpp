#include "primitives/serialize.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace qryptcoin::primitives::serialize {

namespace {

bool Require(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t needed) {
  return offset + needed <= data.size();
}

bool HasWitness(const primitives::CTransaction& tx) {
  for (const auto& in : tx.vin) {
    if (!in.witness_stack.empty()) return true;
  }
  return false;
}

void SerializeInputs(const primitives::CTransaction& tx, std::vector<std::uint8_t>* out) {
  for (const auto& in : tx.vin) {
    out->insert(out->end(), in.prevout.txid.begin(), in.prevout.txid.end());
    WriteUint32(out, in.prevout.index);
    WriteVarInt(out, in.unlocking_descriptor.size());
    out->insert(out->end(), in.unlocking_descriptor.begin(), in.unlocking_descriptor.end());
    WriteUint32(out, in.sequence);
  }
}

void SerializeOutputs(const primitives::CTransaction& tx, std::vector<std::uint8_t>* out) {
  for (const auto& out_tx : tx.vout) {
    WriteUint64(out, out_tx.value);
    WriteVarInt(out, out_tx.locking_descriptor.size());
    out->insert(out->end(), out_tx.locking_descriptor.begin(), out_tx.locking_descriptor.end());
  }
}

bool DeserializeInputs(const std::vector<std::uint8_t>& data, std::size_t* offset,
                       primitives::CTransaction* tx, bool legacy_varint) {
  const auto read_varint = legacy_varint ? ReadVarIntLegacy : ReadVarInt;
  for (auto& in : tx->vin) {
    if (!Require(data, *offset, in.prevout.txid.size())) return false;
    std::copy_n(data.begin() + *offset, in.prevout.txid.size(), in.prevout.txid.begin());
    *offset += in.prevout.txid.size();
    if (!ReadUint32(data, offset, &in.prevout.index)) return false;
    std::uint64_t desc_size = 0;
    if (!read_varint(data, offset, &desc_size) ||
        desc_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
        !Require(data, *offset, static_cast<std::size_t>(desc_size))) {
      return false;
    }
    const std::size_t desc_len = static_cast<std::size_t>(desc_size);
    in.unlocking_descriptor.assign(data.begin() + *offset, data.begin() + *offset + desc_len);
    *offset += desc_len;
    if (!ReadUint32(data, offset, &in.sequence)) return false;
  }
  return true;
}

bool DeserializeOutputs(const std::vector<std::uint8_t>& data, std::size_t* offset,
                        primitives::CTransaction* tx, bool legacy_varint) {
  const auto read_varint = legacy_varint ? ReadVarIntLegacy : ReadVarInt;
  for (auto& out_tx : tx->vout) {
    if (!ReadUint64(data, offset, reinterpret_cast<std::uint64_t*>(&out_tx.value))) return false;
    std::uint64_t script_size = 0;
    if (!read_varint(data, offset, &script_size) ||
        script_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
        !Require(data, *offset, static_cast<std::size_t>(script_size))) {
      return false;
    }
    const std::size_t script_len = static_cast<std::size_t>(script_size);
    out_tx.locking_descriptor.assign(data.begin() + *offset, data.begin() + *offset + script_len);
    *offset += script_len;
  }
  return true;
}

}  // namespace

void WriteUint32(std::vector<std::uint8_t>* out, std::uint32_t value) {
  out->push_back(static_cast<std::uint8_t>(value & 0xFF));
  out->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

void WriteUint64(std::vector<std::uint8_t>* out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out->push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
  }
}

void WriteVarInt(std::vector<std::uint8_t>* out, std::uint64_t value) {
  if (value < 0xFD) {
    out->push_back(static_cast<std::uint8_t>(value));
  } else if (value <= 0xFFFF) {
    out->push_back(0xFD);
    const std::uint16_t v16 = static_cast<std::uint16_t>(value);
    out->push_back(static_cast<std::uint8_t>(v16 & 0xFFu));
    out->push_back(static_cast<std::uint8_t>((v16 >> 8) & 0xFFu));
  } else if (value <= 0xFFFFFFFF) {
    out->push_back(0xFE);
    WriteUint32(out, static_cast<std::uint32_t>(value));
  } else {
    out->push_back(0xFF);
    WriteUint64(out, value);
  }
}

void WriteVarIntLegacy(std::vector<std::uint8_t>* out, std::uint64_t value) {
  if (value < 0xFD) {
    out->push_back(static_cast<std::uint8_t>(value));
  } else if (value <= 0xFFFF) {
    out->push_back(0xFD);
    WriteUint32(out, static_cast<std::uint16_t>(value));
  } else if (value <= 0xFFFFFFFF) {
    out->push_back(0xFE);
    WriteUint32(out, static_cast<std::uint32_t>(value));
  } else {
    out->push_back(0xFF);
    WriteUint64(out, value);
  }
}

bool ReadUint32(const std::vector<std::uint8_t>& data, std::size_t* offset, std::uint32_t* value) {
  if (!Require(data, *offset, 4)) return false;
  *value = data[*offset] | (data[*offset + 1] << 8) | (data[*offset + 2] << 16) |
           (data[*offset + 3] << 24);
  *offset += 4;
  return true;
}

bool ReadUint64(const std::vector<std::uint8_t>& data, std::size_t* offset, std::uint64_t* value) {
  if (!Require(data, *offset, 8)) return false;
  std::uint64_t result = 0;
  for (int i = 0; i < 8; ++i) {
    result |= static_cast<std::uint64_t>(data[*offset + i]) << (8 * i);
  }
  *value = result;
  *offset += 8;
  return true;
}

bool ReadVarInt(const std::vector<std::uint8_t>& data, std::size_t* offset, std::uint64_t* value) {
  if (!Require(data, *offset, 1)) return false;
  std::uint8_t prefix = data[(*offset)++];
  if (prefix < 0xFD) {
    *value = prefix;
    return true;
  }
  if (prefix == 0xFD) {
    if (!Require(data, *offset, 2)) return false;
    const std::uint64_t v16 = static_cast<std::uint64_t>(data[*offset]) |
                              (static_cast<std::uint64_t>(data[*offset + 1]) << 8);
    *offset += 2;
    if (v16 < 0xFD) {
      return false;
    }
    *value = v16;
    return true;
  }
  if (prefix == 0xFE) {
    std::uint32_t tmp = 0;
    if (!ReadUint32(data, offset, &tmp)) return false;
    if (tmp <= 0xFFFFu) {
      return false;
    }
    *value = tmp;
    return true;
  }
  std::uint64_t tmp = 0;
  if (!ReadUint64(data, offset, &tmp)) return false;
  if (tmp <= 0xFFFFFFFFULL) {
    return false;
  }
  *value = tmp;
  return true;
}

bool ReadVarIntLegacy(const std::vector<std::uint8_t>& data, std::size_t* offset,
                      std::uint64_t* value) {
  if (!Require(data, *offset, 1)) return false;
  std::uint8_t prefix = data[(*offset)++];
  if (prefix < 0xFD) {
    *value = prefix;
    return true;
  }
  if (prefix == 0xFD) {
    std::uint32_t tmp = 0;
    if (!ReadUint32(data, offset, &tmp)) return false;
    *value = tmp & 0xFFFFu;
    return true;
  }
  if (prefix == 0xFE) {
    std::uint32_t tmp = 0;
    if (!ReadUint32(data, offset, &tmp)) return false;
    *value = tmp;
    return true;
  }
  return ReadUint64(data, offset, value);
}

void SerializeTransactionBase(const CTransaction& tx, std::vector<std::uint8_t>* out) {
  WriteUint32(out, tx.version);
  WriteVarInt(out, tx.vin.size());
  SerializeInputs(tx, out);
  WriteVarInt(out, tx.vout.size());
  SerializeOutputs(tx, out);
  WriteUint32(out, tx.lock_time);
}

void SerializeTransactionWitness(const CTransaction& tx, std::vector<std::uint8_t>* out) {
  for (const auto& in : tx.vin) {
    WriteVarInt(out, in.witness_stack.size());
    for (const auto& item : in.witness_stack) {
      WriteVarInt(out, item.data.size());
      out->insert(out->end(), item.data.begin(), item.data.end());
    }
  }
}

void SerializeTransaction(const CTransaction& tx, std::vector<std::uint8_t>* out,
                          bool include_witness) {
  const bool has_witness = include_witness && HasWitness(tx);
  WriteUint32(out, tx.version);
  if (has_witness) {
    out->push_back(0x00);  // marker
    out->push_back(0x01);  // flag indicating witness is present
  }
  WriteVarInt(out, tx.vin.size());
  SerializeInputs(tx, out);
  WriteVarInt(out, tx.vout.size());
  SerializeOutputs(tx, out);
  if (has_witness) {
    SerializeTransactionWitness(tx, out);
  }
  WriteUint32(out, tx.lock_time);
}

TxSerializeSizes MeasureTransactionSizes(const CTransaction& tx) {
  std::vector<std::uint8_t> base;
  SerializeTransaction(tx, &base, /*include_witness=*/false);
  std::vector<std::uint8_t> full;
  SerializeTransaction(tx, &full, /*include_witness=*/true);
  TxSerializeSizes sizes;
  sizes.base_size = base.size();
  sizes.total_size = full.size();
  sizes.witness_size = (full.size() >= base.size()) ? full.size() - base.size() : 0;
  return sizes;
}

TxSerializeSizes MeasureBlockSizes(const CBlock& block) {
  TxSerializeSizes totals;
  std::vector<std::uint8_t> header_buf;
  SerializeBlockHeader(block.header, &header_buf);
  totals.base_size += header_buf.size();
  std::vector<std::uint8_t> count_buf;
  WriteVarInt(&count_buf, block.transactions.size());
  totals.base_size += count_buf.size();
  for (const auto& tx : block.transactions) {
    auto sizes = MeasureTransactionSizes(tx);
    totals.base_size += sizes.base_size;
    totals.witness_size += sizes.witness_size;
  }
  totals.total_size = totals.base_size + totals.witness_size;
  return totals;
}

bool DeserializeTransaction(const std::vector<std::uint8_t>& data, std::size_t* offset,
                            CTransaction* tx, bool expect_witness, bool allow_legacy_encoding,
                            bool legacy_varint) {
  const std::size_t start = *offset;
  constexpr std::uint64_t kMinInputBytes = 32 + 4 + 1 + 4;
  constexpr std::uint64_t kMinOutputBytes = 8 + 1;
  constexpr std::uint64_t kMaxWitnessItemsPerInput = 64;
  const auto read_varint = legacy_varint ? ReadVarIntLegacy : ReadVarInt;

  auto parse_v2 = [&](primitives::CTransaction* out, std::size_t* cursor) -> bool {
    if (!ReadUint32(data, cursor, &out->version)) return false;
    bool has_witness = false;
    if (Require(data, *cursor, 2) && data[*cursor] == 0x00) {
      // Witness-flagged encoding: marker=0x00, flag=0x01.
      if (!expect_witness) {
        return false;
      }
      if (data[*cursor + 1] != 0x01) {
        return false;
      }
      has_witness = true;
      *cursor += 2;
    }

    std::uint64_t vin_count = 0;
    if (!read_varint(data, cursor, &vin_count)) return false;
    if (has_witness && vin_count == 0) return false;
    if (vin_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
    const std::size_t remaining_inputs = (*cursor <= data.size()) ? data.size() - *cursor : 0;
    if (kMinInputBytes == 0 || vin_count > remaining_inputs / kMinInputBytes) return false;
    out->vin.resize(static_cast<std::size_t>(vin_count));
    if (!DeserializeInputs(data, cursor, out, legacy_varint)) return false;

    std::uint64_t vout_count = 0;
    if (!read_varint(data, cursor, &vout_count)) return false;
    if (vout_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
    const std::size_t remaining_outputs = (*cursor <= data.size()) ? data.size() - *cursor : 0;
    if (kMinOutputBytes == 0 || vout_count > remaining_outputs / kMinOutputBytes) return false;
    out->vout.resize(static_cast<std::size_t>(vout_count));
    if (!DeserializeOutputs(data, cursor, out, legacy_varint)) return false;

    if (has_witness) {
      for (auto& in : out->vin) {
        std::uint64_t witness_items = 0;
        if (!read_varint(data, cursor, &witness_items)) return false;
        if (witness_items > kMaxWitnessItemsPerInput) return false;
        if (witness_items > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
        in.witness_stack.resize(static_cast<std::size_t>(witness_items));
        for (auto& item : in.witness_stack) {
          std::uint64_t item_size = 0;
          if (!read_varint(data, cursor, &item_size) ||
              item_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
              !Require(data, *cursor, static_cast<std::size_t>(item_size))) {
            return false;
          }
          const std::size_t item_len = static_cast<std::size_t>(item_size);
          item.data.assign(data.begin() + *cursor, data.begin() + *cursor + item_len);
          *cursor += item_len;
        }
      }
    } else {
      for (auto& in : out->vin) {
        in.witness_stack.clear();
      }
    }

    return ReadUint32(data, cursor, &out->lock_time);
  };

  auto parse_legacy = [&](primitives::CTransaction* out, std::size_t* cursor) -> bool {
    if (!ReadUint32(data, cursor, &out->version)) return false;
    std::uint64_t vin_count = 0;
    if (!read_varint(data, cursor, &vin_count)) return false;
    if (vin_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
    const std::size_t remaining_inputs = (*cursor <= data.size()) ? data.size() - *cursor : 0;
    if (kMinInputBytes == 0 || vin_count > remaining_inputs / kMinInputBytes) return false;
    out->vin.resize(static_cast<std::size_t>(vin_count));
    for (auto& in : out->vin) {
      if (!Require(data, *cursor, in.prevout.txid.size())) return false;
      std::copy_n(data.begin() + *cursor, in.prevout.txid.size(), in.prevout.txid.begin());
      *cursor += in.prevout.txid.size();
      if (!ReadUint32(data, cursor, &in.prevout.index)) return false;
      std::uint64_t desc_size = 0;
      if (!read_varint(data, cursor, &desc_size) ||
          desc_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
          !Require(data, *cursor, static_cast<std::size_t>(desc_size))) {
        return false;
      }
      const std::size_t desc_len = static_cast<std::size_t>(desc_size);
      in.unlocking_descriptor.assign(data.begin() + *cursor, data.begin() + *cursor + desc_len);
      *cursor += desc_len;
      std::uint64_t witness_items = 0;
      if (!read_varint(data, cursor, &witness_items)) return false;
      if (witness_items > kMaxWitnessItemsPerInput) return false;
      if (witness_items > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
      in.witness_stack.resize(static_cast<std::size_t>(witness_items));
      for (auto& item : in.witness_stack) {
        std::uint64_t item_size = 0;
        if (!read_varint(data, cursor, &item_size) ||
            item_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
            !Require(data, *cursor, static_cast<std::size_t>(item_size))) {
          return false;
        }
        const std::size_t item_len = static_cast<std::size_t>(item_size);
        item.data.assign(data.begin() + *cursor, data.begin() + *cursor + item_len);
        *cursor += item_len;
      }
      if (!ReadUint32(data, cursor, &in.sequence)) return false;
    }
    std::uint64_t vout_count = 0;
    if (!read_varint(data, cursor, &vout_count)) return false;
    if (vout_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
    const std::size_t remaining_outputs = (*cursor <= data.size()) ? data.size() - *cursor : 0;
    if (kMinOutputBytes == 0 || vout_count > remaining_outputs / kMinOutputBytes) return false;
    out->vout.resize(static_cast<std::size_t>(vout_count));
    if (!DeserializeOutputs(data, cursor, out, legacy_varint)) return false;
    return ReadUint32(data, cursor, &out->lock_time);
  };

  std::size_t cursor = start;
  primitives::CTransaction candidate;
  if (parse_v2(&candidate, &cursor)) {
    *tx = std::move(candidate);
    *offset = cursor;
    return true;
  }

  if (allow_legacy_encoding && expect_witness) {
    cursor = start;
    primitives::CTransaction legacy;
    if (parse_legacy(&legacy, &cursor)) {
      *tx = std::move(legacy);
      *offset = cursor;
      return true;
    }
  }
  return false;
}

void SerializeBlockHeader(const CBlockHeader& header, std::vector<std::uint8_t>* out) {
  WriteUint32(out, header.version);
  out->insert(out->end(), header.previous_block_hash.begin(), header.previous_block_hash.end());
  out->insert(out->end(), header.merkle_root.begin(), header.merkle_root.end());
  // Wire-format header is fixed to 80 bytes: serialize only the low
  // 32 bits of timestamp and nonce.
  WriteUint32(out, static_cast<std::uint32_t>(header.timestamp));
  WriteUint32(out, header.difficulty_bits);
  WriteUint32(out, header.nonce);
}

bool DeserializeBlockHeader(const std::vector<std::uint8_t>& data, std::size_t* offset,
  CBlockHeader* header) {
  if (!ReadUint32(data, offset, &header->version)) return false;
  if (!Require(data, *offset, header->previous_block_hash.size())) return false;
  std::copy_n(data.begin() + *offset, header->previous_block_hash.size(),
              header->previous_block_hash.begin());
  *offset += header->previous_block_hash.size();
  if (!Require(data, *offset, header->merkle_root.size())) return false;
  std::copy_n(data.begin() + *offset, header->merkle_root.size(), header->merkle_root.begin());
  *offset += header->merkle_root.size();
  std::uint32_t ts32 = 0;
  if (!ReadUint32(data, offset, &ts32)) return false;
  header->timestamp = ts32;
  if (!ReadUint32(data, offset, &header->difficulty_bits)) return false;
  std::uint32_t nonce32 = 0;
  if (!ReadUint32(data, offset, &nonce32)) return false;
  header->nonce = nonce32;
  return true;
}

void SerializeBlock(const CBlock& block, std::vector<std::uint8_t>* out) {
  SerializeBlockHeader(block.header, out);
  WriteVarInt(out, block.transactions.size());
  for (const auto& tx : block.transactions) {
    SerializeTransaction(tx, out, /*include_witness=*/true);
  }
}

bool DeserializeBlock(const std::vector<std::uint8_t>& data, std::size_t* offset, CBlock* block,
                      bool legacy_varint) {
  if (!DeserializeBlockHeader(data, offset, &block->header)) return false;
  std::uint64_t tx_count = 0;
  const auto read_varint = legacy_varint ? ReadVarIntLegacy : ReadVarInt;
  if (!read_varint(data, offset, &tx_count)) return false;
  if (tx_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    return false;
  }
  constexpr std::uint64_t kMinTransactionBytes = 10;
  const std::size_t remaining = (*offset <= data.size()) ? data.size() - *offset : 0;
  if (kMinTransactionBytes == 0 || tx_count > remaining / kMinTransactionBytes) {
    return false;
  }
  block->transactions.resize(static_cast<std::size_t>(tx_count));
  for (auto& tx : block->transactions) {
    if (!DeserializeTransaction(data, offset, &tx, /*expect_witness=*/true, /*allow_legacy_encoding=*/false,
                                legacy_varint)) {
      return false;
    }
  }
  return true;
}

}  // namespace qryptcoin::primitives::serialize
