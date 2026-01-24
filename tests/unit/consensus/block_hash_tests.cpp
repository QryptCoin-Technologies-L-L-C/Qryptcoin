#include <cstdlib>
#include <iostream>
#include <vector>

#include "config/network.hpp"
#include "consensus/block_hash.hpp"
#include "consensus/params.hpp"
#include "crypto/hash.hpp"
#include "primitives/block.hpp"
#include "primitives/serialize.hpp"

using namespace qryptcoin;

int main() {
  try {
    primitives::CBlockHeader header;
    header.version = 0x12345678u;
    header.previous_block_hash.fill(0x11u);
    header.merkle_root.fill(0x22u);
    // High bits of timestamp are ignored by the 80-byte PoW header.
    header.timestamp = (0x00000001ull << 32) | 0x00000002ull;
    header.difficulty_bits = 0x1d00ffffu;
    header.nonce = 0xA1B2C3D4u;

    std::vector<std::uint8_t> full_header;
    primitives::serialize::SerializeBlockHeader(header, &full_header);
    if (full_header.size() != 80) {
      std::cerr << "block_hash_tests: expected serialized header size 80, got "
                << full_header.size() << "\n";
      return EXIT_FAILURE;
    }

    // Manually construct the 80-byte PoW header to assert that both the
    // serialization and ComputeBlockHash agree on the layout.
    std::vector<std::uint8_t> pow_header;
    pow_header.reserve(80);
    primitives::serialize::WriteUint32(&pow_header, header.version);
    pow_header.insert(pow_header.end(), header.previous_block_hash.begin(),
                      header.previous_block_hash.end());
    pow_header.insert(pow_header.end(), header.merkle_root.begin(),
                      header.merkle_root.end());
    primitives::serialize::WriteUint32(
        &pow_header, static_cast<std::uint32_t>(header.timestamp));
    primitives::serialize::WriteUint32(&pow_header, header.difficulty_bits);
    primitives::serialize::WriteUint32(&pow_header, header.nonce);
    if (pow_header.size() != 80) {
      std::cerr << "block_hash_tests: expected PoW header size 80, got "
                << pow_header.size() << "\n";
      return EXIT_FAILURE;
    }

    const auto expected_sha = crypto::DoubleSha256(pow_header);
    primitives::Hash256 expected_hash{};
    std::copy(expected_sha.begin(), expected_sha.end(), expected_hash.begin());

    const auto computed = consensus::ComputeBlockHash(header);
    if (computed != expected_hash) {
      std::cerr << "block_hash_tests: ComputeBlockHash did not match "
                   "DoubleSha256 of 80-byte header\n";
      return EXIT_FAILURE;
    }

    const auto wrong_sha = crypto::DoubleSha3_256(full_header);
    primitives::Hash256 wrong_hash{};
    std::copy(wrong_sha.begin(), wrong_sha.end(), wrong_hash.begin());
    if (wrong_hash == computed) {
      std::cerr << "block_hash_tests: PoW hash unexpectedly matches hash of "
                   "header hashed with SHA3-256\n";
      return EXIT_FAILURE;
    }

    // Known-answer test: mainnet genesis header must hash to the
    // expected value via Double-SHA256 over the canonical 80-byte
    // serialization.
    config::SelectNetwork(config::NetworkType::kMainnet);
    const auto& params = consensus::Params(config::NetworkType::kMainnet);
    std::vector<std::uint8_t> genesis_header;
    primitives::serialize::SerializeBlockHeader(params.genesis_block.header,
                                                &genesis_header);
    if (genesis_header.size() != 80) {
      std::cerr << "block_hash_tests: expected genesis header size 80, got "
                << genesis_header.size() << "\n";
      return EXIT_FAILURE;
    }
    const auto genesis_sha = crypto::DoubleSha256(genesis_header);
    primitives::Hash256 genesis_hash{};
    std::copy(genesis_sha.begin(), genesis_sha.end(), genesis_hash.begin());
    if (genesis_hash != params.genesis_hash) {
      std::cerr << "block_hash_tests: genesis KAT mismatch\n";
      return EXIT_FAILURE;
    }
  } catch (const std::exception& ex) {
    std::cerr << "block_hash_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << "block_hash_tests unknown exception\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
