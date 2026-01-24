#include "util/argon2_kdf.hpp"

#include <argon2.h>

namespace qryptcoin::util {

Argon2idParams DefaultArgon2idParams() {
  // 3 iterations, 64 MiB, single lane.
  Argon2idParams params;
  params.t_cost = 3;
  params.m_cost_kib = 64 * 1024;  // 64 MiB
  params.parallelism = 1;
  return params;
}

bool DeriveKeyArgon2id(const std::string& password,
                       std::span<const std::uint8_t> salt,
                       const Argon2idParams& params,
                       std::vector<std::uint8_t>* key_out) {
  if (!key_out) return false;
  key_out->assign(32, 0);

  const int rc = argon2id_hash_raw(
      params.t_cost,
      params.m_cost_kib,
      params.parallelism,
      password.data(), static_cast<std::size_t>(password.size()),
      salt.data(), salt.size(),
      key_out->data(), key_out->size());

  return rc == ARGON2_OK;
}

}  // namespace qryptcoin::util

