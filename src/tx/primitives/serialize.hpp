#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <vector>

#include "primitives/block.hpp"
#include "primitives/transaction.hpp"

namespace qryptcoin::primitives::serialize {

void WriteUint32(std::vector<std::uint8_t>* out, std::uint32_t value);
void WriteUint64(std::vector<std::uint8_t>* out, std::uint64_t value);
void WriteVarInt(std::vector<std::uint8_t>* out, std::uint64_t value);
// Legacy varint encoding used by early QryptCoin builds where the 0xFD
// branch incorrectly serialized a 16-bit value using 4 bytes.
void WriteVarIntLegacy(std::vector<std::uint8_t>* out, std::uint64_t value);
bool ReadUint32(const std::vector<std::uint8_t>& data, std::size_t* offset,
                std::uint32_t* value);
bool ReadUint64(const std::vector<std::uint8_t>& data, std::size_t* offset,
                std::uint64_t* value);
bool ReadVarInt(const std::vector<std::uint8_t>& data, std::size_t* offset,
                std::uint64_t* value);
// Legacy varint parser compatible with the early 0xFD bug.
bool ReadVarIntLegacy(const std::vector<std::uint8_t>& data, std::size_t* offset,
                      std::uint64_t* value);

struct TxSerializeSizes {
  std::size_t base_size{0};
  std::size_t witness_size{0};
  std::size_t total_size{0};
};

void SerializeTransaction(const CTransaction& tx, std::vector<std::uint8_t>* out,
                          bool include_witness = true);
void SerializeTransactionBase(const CTransaction& tx, std::vector<std::uint8_t>* out);
void SerializeTransactionWitness(const CTransaction& tx, std::vector<std::uint8_t>* out);
bool DeserializeTransaction(const std::vector<std::uint8_t>& data, std::size_t* offset,
                            CTransaction* tx, bool expect_witness = true,
                            bool allow_legacy_encoding = false,
                            bool legacy_varint = false);
TxSerializeSizes MeasureTransactionSizes(const CTransaction& tx);
TxSerializeSizes MeasureBlockSizes(const CBlock& block);
void SerializeBlockHeader(const CBlockHeader& header, std::vector<std::uint8_t>* out);
bool DeserializeBlockHeader(const std::vector<std::uint8_t>& data, std::size_t* offset,
                            CBlockHeader* header);
void SerializeBlock(const CBlock& block, std::vector<std::uint8_t>* out);
bool DeserializeBlock(const std::vector<std::uint8_t>& data, std::size_t* offset, CBlock* block,
                      bool legacy_varint = false);

}  // namespace qryptcoin::primitives::serialize
