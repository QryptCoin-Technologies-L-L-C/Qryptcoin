#include "consensus/sighash.hpp"

#include <array>
#include <stdexcept>
#include <vector>

#include "crypto/hash.hpp"

namespace qryptcoin::consensus {

namespace {

void AppendUint16(std::vector<std::uint8_t>* buffer, std::uint16_t value) {
  buffer->push_back(static_cast<std::uint8_t>(value & 0xFF));
  buffer->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
}

void AppendUint32(std::vector<std::uint8_t>* buffer, std::uint32_t value) {
  buffer->push_back(static_cast<std::uint8_t>(value & 0xFF));
  buffer->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
  buffer->push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
  buffer->push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

void AppendUint64(std::vector<std::uint8_t>* buffer, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    buffer->push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF));
  }
}

void WriteVarInt(std::vector<std::uint8_t>* buffer, std::uint64_t value) {
  if (value < 0xFD) {
    buffer->push_back(static_cast<std::uint8_t>(value));
  } else if (value <= 0xFFFF) {
    buffer->push_back(0xFD);
    AppendUint16(buffer, static_cast<std::uint16_t>(value));
  } else if (value <= 0xFFFFFFFF) {
    buffer->push_back(0xFE);
    AppendUint32(buffer, static_cast<std::uint32_t>(value));
  } else {
    buffer->push_back(0xFF);
    AppendUint64(buffer, value);
  }
}

std::array<std::uint8_t, 32> HashPrevouts(const primitives::CTransaction& tx) {
  std::vector<std::uint8_t> buffer;
  buffer.reserve(tx.vin.size() * (32 + 4));
  for (const auto& input : tx.vin) {
    buffer.insert(buffer.end(), input.prevout.txid.begin(), input.prevout.txid.end());
    AppendUint32(&buffer, input.prevout.index);
  }
  return crypto::Sha3_256(buffer);
}

std::array<std::uint8_t, 32> HashSequences(const primitives::CTransaction& tx) {
  std::vector<std::uint8_t> buffer;
  buffer.reserve(tx.vin.size() * 4);
  for (const auto& input : tx.vin) {
    AppendUint32(&buffer, input.sequence);
  }
  return crypto::Sha3_256(buffer);
}

std::array<std::uint8_t, 32> HashOutputs(const primitives::CTransaction& tx) {
  std::vector<std::uint8_t> buffer;
  for (const auto& output : tx.vout) {
    AppendUint64(&buffer, output.value);
    WriteVarInt(&buffer, output.locking_descriptor.size());
    buffer.insert(buffer.end(), output.locking_descriptor.begin(),
                  output.locking_descriptor.end());
  }
  return crypto::Sha3_256(buffer);
}

}  // namespace

std::array<std::uint8_t, 32> ComputeSighash(const primitives::CTransaction& tx,
                                            std::size_t input_index, const Coin& spent_coin) {
  if (input_index >= tx.vin.size()) {
    throw std::runtime_error("sighash input index out of range");
  }
  constexpr std::string_view kSighashTag = "QRY-SIGHASH-V1";
  const auto hash_prevouts = HashPrevouts(tx);
  const auto hash_sequences = HashSequences(tx);
  const auto hash_outputs = HashOutputs(tx);
  std::vector<std::uint8_t> preimage;
  preimage.reserve(128);
  preimage.insert(preimage.end(), kSighashTag.begin(), kSighashTag.end());
  AppendUint32(&preimage, tx.version);
  preimage.insert(preimage.end(), hash_prevouts.begin(), hash_prevouts.end());
  preimage.insert(preimage.end(), hash_sequences.begin(), hash_sequences.end());

  const auto& input = tx.vin[input_index];
  preimage.insert(preimage.end(), input.prevout.txid.begin(), input.prevout.txid.end());
  AppendUint32(&preimage, input.prevout.index);
  WriteVarInt(&preimage, spent_coin.out.locking_descriptor.size());
  preimage.insert(preimage.end(), spent_coin.out.locking_descriptor.begin(),
                  spent_coin.out.locking_descriptor.end());
  AppendUint64(&preimage, spent_coin.out.value);
  AppendUint32(&preimage, input.sequence);
  preimage.insert(preimage.end(), hash_outputs.begin(), hash_outputs.end());
  AppendUint32(&preimage, tx.lock_time);
  return crypto::Sha3_256(preimage);
}

}  // namespace qryptcoin::consensus

