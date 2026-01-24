#include "primitives/txid.hpp"

#include <vector>

#include "crypto/hash.hpp"
#include "primitives/serialize.hpp"

namespace qryptcoin::primitives {

Hash256 ComputeTxId(const CTransaction& tx) {
  std::vector<std::uint8_t> buffer;
  serialize::SerializeTransaction(tx, &buffer, /*include_witness=*/false);
  auto hash = crypto::Sha3_256(buffer);
  Hash256 result{};
  std::copy(hash.begin(), hash.end(), result.begin());
  return result;
}

Hash256 ComputeWTxId(const CTransaction& tx) {
  std::vector<std::uint8_t> buffer;
  serialize::SerializeTransaction(tx, &buffer, /*include_witness=*/true);
  auto hash = crypto::Sha3_256(buffer);
  Hash256 result{};
  std::copy(hash.begin(), hash.end(), result.begin());
  return result;
}

}  // namespace qryptcoin::primitives
