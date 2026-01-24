#include "consensus/tx_validator.hpp"

#include <algorithm>
#include <span>
#include <sstream>
#include <unordered_set>
#include <vector>

#include "consensus/monetary.hpp"
#include "consensus/sighash.hpp"
#include "crypto/hash.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "script/p2qh.hpp"

namespace qryptcoin::consensus {

namespace {

bool AllInputsFinal(const primitives::CTransaction& tx) {
  for (const auto& in : tx.vin) {
    if (in.sequence != 0xFFFFFFFFu) {
      return false;
    }
  }
  return true;
}

}  // namespace

bool ValidateTransaction(const primitives::CTransaction& tx, const UTXOSet& view,
                         const RevealedPubkeySet& revealed_pubkeys,
                         std::uint32_t spending_height, std::uint64_t lock_time_cutoff_time,
                         std::vector<primitives::Hash256>* revealed_pubkeys_out,
                         std::string* error) {
  if (revealed_pubkeys_out) {
    revealed_pubkeys_out->clear();
  }
  if (tx.IsCoinbase()) {
    if (error) *error = "coinbase validation not implemented";
    return false;
  }
  if (tx.vin.empty()) {
    if (error) *error = "transaction has no inputs";
    return false;
  }
  if (tx.vout.empty()) {
    if (error) *error = "transaction has no outputs";
    return false;
  }

  primitives::Amount value_out = 0;
  for (const auto& out : tx.vout) {
    if (!primitives::MoneyRange(out.value)) {
      if (error) *error = "output value out of range";
      return false;
    }
    primitives::Amount next = 0;
    if (!primitives::CheckedAdd(value_out, out.value, &next)) {
      if (error) *error = "output total out of range";
      return false;
    }
    value_out = next;
  }

  // Enforce duplicate-input rules.
  std::unordered_set<primitives::COutPoint, OutPointHasher> seen;
  for (const auto& in : tx.vin) {
    if (!seen.insert(in.prevout).second) {
      if (error) *error = "transaction has duplicate inputs";
      return false;
    }
  }

  std::unordered_set<primitives::Hash256, Hash256Hasher> revealed_this_tx;
  revealed_this_tx.reserve(tx.vin.size());

  // Absolute lock-time semantics: lock_time is ignored if all inputs are
  // final; otherwise the block height or time must be strictly greater
  // than the encoded value.
  if (tx.lock_time != 0 && !AllInputsFinal(tx)) {
    const bool lock_is_height = tx.lock_time < 500'000'000u;
    if (lock_is_height) {
      if (spending_height <= tx.lock_time) {
        if (error) *error = "non-final due to absolute height lock_time";
        return false;
      }
    } else {
      if (lock_time_cutoff_time <= tx.lock_time) {
        if (error) *error = "non-final due to absolute time lock_time";
        return false;
      }
    }
  }

  for (std::size_t input_index = 0; input_index < tx.vin.size(); ++input_index) {
    const auto& input = tx.vin[input_index];
    if (!input.unlocking_descriptor.empty()) {
      if (error) *error = "unlocking_descriptor must be empty for P2QH";
      return false;
    }
    const Coin* coin = view.GetCoin(input.prevout);
    if (coin == nullptr) {
      if (error) *error = "missing UTXO";
      return false;
    }
    if (!primitives::MoneyRange(coin->out.value)) {
      if (error) *error = "input value out of range";
      return false;
    }

    // Relative lock-time semantics (height-based). Time-based sequence
    // locks are reserved for future activation; transactions that use
    // them are rejected today to avoid ambiguous behavior.
    const std::uint32_t seq = input.sequence;
    if ((seq & 0x80000000u) == 0u && seq != 0xFFFFFFFFu) {
      const std::uint32_t unit = (seq >> 16) & 0x7Fu;
      const std::uint32_t value = seq & 0xFFFFu;
      if (value != 0) {
        if (unit == 0) {
          const std::uint64_t required_height =
              static_cast<std::uint64_t>(coin->height) + static_cast<std::uint64_t>(value);
          if (static_cast<std::uint64_t>(spending_height) < required_height) {
            if (error) *error = "relative height lock_time not yet satisfied";
            return false;
          }
        } else {
          if (error) *error = "unsupported relative time-based sequence lock";
          return false;
        }
      }
    }

    if (coin->coinbase) {
      const std::uint64_t required_height =
          static_cast<std::uint64_t>(coin->height) + kCoinbaseMaturity;
      if (static_cast<std::uint64_t>(spending_height) < required_height) {
        if (error) *error = "coinbase maturity not reached";
        return false;
      }
    }
    if (input.witness_stack.empty()) {
      if (error) *error = "empty witness stack";
      return false;
    }
    const auto& reveal = input.witness_stack.front().data;
    crypto::P2QHRevealData reveal_data{};
    if (!crypto::ParseP2QHReveal(reveal, &reveal_data)) {
      if (error) *error = "invalid descriptor reveal";
      return false;
    }
    const auto pk_hash = crypto::Sha3_256(std::span<const std::uint8_t>(
        reveal_data.mldsa_public_key.data(), reveal_data.mldsa_public_key.size()));
    primitives::Hash256 pk_hash256{};
    std::copy(pk_hash.begin(), pk_hash.end(), pk_hash256.begin());
    if (!revealed_this_tx.insert(pk_hash256).second) {
      if (error) *error = "public key reused within transaction";
      return false;
    }
    if (revealed_pubkeys.Contains(pk_hash256)) {
      if (error) *error = "public key already revealed";
      return false;
    }
    if (revealed_pubkeys_out) {
      revealed_pubkeys_out->push_back(pk_hash256);
    }
    script::ScriptPubKey script_pubkey{coin->out.locking_descriptor};
    const auto sighash = ComputeSighash(tx, input_index, *coin);
    if (!script::VerifyP2QHWitness(
            script_pubkey, input.witness_stack,
            std::span<const std::uint8_t>(sighash.data(), sighash.size()), error)) {
      return false;
    }
  }
  return true;
}

}  // namespace qryptcoin::consensus
