#include "consensus/params.hpp"

#include <array>
#include <vector>

#include "consensus/block_hash.hpp"
#include "consensus/monetary.hpp"
#include "consensus/witness_commitment.hpp"
#include "primitives/merkle.hpp"
#include "primitives/serialize.hpp"
#include "primitives/transaction.hpp"
#include "primitives/txid.hpp"
#include "script/script.hpp"

namespace qryptcoin::consensus {

namespace {

constexpr std::uint32_t kMaxBlockSerializedBytes = 1u * 1024u * 1024u;  // 1 MiB

inline constexpr std::array<primitives::Hash256, 4> kGenesisPayoutPrograms = {{
    // program = H3("QRY-GENESIS-PAYOUT-PROGRAM-V1|mainnet")
    primitives::Hash256{{
        0xe6, 0x53, 0xd4, 0x85, 0xc1, 0x8e, 0x55, 0x7e,
        0x67, 0x0d, 0x22, 0x17, 0x5d, 0x89, 0xd3, 0xab,
        0x63, 0x44, 0x44, 0x6f, 0xa1, 0xb9, 0xcc, 0x61,
        0xd7, 0x6d, 0xfc, 0xe1, 0x5b, 0x55, 0xe7, 0x42,
    }},
    // program = H3("QRY-GENESIS-PAYOUT-PROGRAM-V1|testnet")
    primitives::Hash256{{
        0x91, 0xe2, 0xa3, 0x32, 0xcf, 0x29, 0x15, 0x5a,
        0xf5, 0xb8, 0x35, 0x8d, 0xea, 0x91, 0xfe, 0x05,
        0xaf, 0x83, 0x2f, 0x5e, 0x48, 0x83, 0x24, 0x3e,
        0x9a, 0x18, 0x15, 0x27, 0x11, 0xa9, 0xf2, 0xc4,
    }},
    // program = H3("QRY-GENESIS-PAYOUT-PROGRAM-V1|regtest")
    primitives::Hash256{{
        0xdd, 0x8b, 0x15, 0x8c, 0x01, 0xe0, 0x2b, 0xb3,
        0xd4, 0xf1, 0x2d, 0x67, 0xc9, 0xfc, 0x23, 0x4d,
        0x77, 0x44, 0xd5, 0x21, 0x82, 0x76, 0x6e, 0x06,
        0xce, 0xdb, 0xda, 0x9f, 0x35, 0xdf, 0x24, 0x5d,
    }},
    // program = H3("QRY-GENESIS-PAYOUT-PROGRAM-V1|signet")
    primitives::Hash256{{
        0x3d, 0x9d, 0xb9, 0x31, 0x0a, 0x6c, 0x8b, 0x41,
        0x38, 0x8b, 0xb6, 0x54, 0xbc, 0x4f, 0x0a, 0x55,
        0xa6, 0x25, 0xab, 0x73, 0xe1, 0x64, 0x1a, 0xfa,
        0x7e, 0x1a, 0xb0, 0x99, 0xf2, 0xfc, 0xb8, 0xb5,
    }},
}};

const primitives::Hash256& GenesisPayoutProgram(config::NetworkType network) {
  switch (network) {
    case config::NetworkType::kMainnet:
      return kGenesisPayoutPrograms[0];
    case config::NetworkType::kTestnet:
      return kGenesisPayoutPrograms[1];
    case config::NetworkType::kRegtest:
      return kGenesisPayoutPrograms[2];
    case config::NetworkType::kSignet:
      return kGenesisPayoutPrograms[3];
  }
  return kGenesisPayoutPrograms[0];
}

primitives::CTransaction BuildGenesisCoinbase(config::NetworkType network,
                                             primitives::Amount reward) {
  primitives::CTransaction tx;
  tx.version = 1;
  tx.vin.resize(1);
  tx.vin[0].prevout = primitives::COutPoint::Null();
  tx.vin[0].sequence = 0xFFFFFFFF;
  tx.vin[0].unlocking_descriptor.clear();
  primitives::serialize::WriteVarInt(&tx.vin[0].unlocking_descriptor, /*value=*/0);
  primitives::serialize::WriteUint64(&tx.vin[0].unlocking_descriptor, 0);
  tx.vin[0].unlocking_descriptor.insert(tx.vin[0].unlocking_descriptor.end(),
                                        consensus::kWitnessCommitmentTag.begin(),
                                        consensus::kWitnessCommitmentTag.end());
  primitives::Hash256 witness_root{};
  tx.vin[0].unlocking_descriptor.insert(tx.vin[0].unlocking_descriptor.end(),
                                        witness_root.begin(), witness_root.end());
  tx.vout.resize(1);
  tx.vout[0].value = reward;
  tx.vout[0].locking_descriptor.clear();
  tx.vout[0].locking_descriptor.reserve(2 + primitives::Hash256{}.size());
  tx.vout[0].locking_descriptor.push_back(script::kOp1);
  tx.vout[0].locking_descriptor.push_back(
      static_cast<std::uint8_t>(script::kP2QHWitnessProgramSize));
  const auto& program = GenesisPayoutProgram(network);
  tx.vout[0].locking_descriptor.insert(tx.vout[0].locking_descriptor.end(),
                                       program.begin(), program.end());
  return tx;
}

primitives::CBlock CreateGenesisBlock(config::NetworkType network, primitives::Amount reward,
                                      std::uint32_t timestamp, std::uint32_t nonce,
                                      std::uint32_t bits) {
  primitives::CBlock genesis;
  auto coinbase = BuildGenesisCoinbase(network, reward);
  genesis.transactions = {coinbase};
  genesis.header.version = 1;
  genesis.header.timestamp = timestamp;
  genesis.header.difficulty_bits = bits;
  genesis.header.nonce = nonce;
  genesis.header.previous_block_hash.fill(0);
  genesis.header.merkle_root = primitives::ComputeMerkleRoot(genesis.transactions);
  return genesis;
}

ChainParams BuildParams(config::NetworkType network, std::string network_id, std::string hrp,
                        std::uint32_t p2p_port, std::uint32_t rpc_port, std::uint32_t bits,
                        std::uint32_t timestamp, std::uint32_t nonce, std::string timestamp_msg) {
  ChainParams params{};
  params.network = network;
  params.network_id = std::move(network_id);
  params.hrp = std::move(hrp);
  params.target_block_time_seconds = kTargetBlockSpacingSeconds;
  params.p2p_default_port = p2p_port;
  params.rpc_default_port = rpc_port;
  params.max_supply_miks = primitives::kMaxMoney;
  params.initial_subsidy_miks = kInitialSubsidy;
  params.halving_interval_blocks = kHalvingIntervalBlocks;
  params.coinbase_maturity = kCoinbaseMaturity;
  params.pow_function = "Double SHA256 (80-byte PoW header)";
  params.max_block_serialized_bytes = kMaxBlockSerializedBytes;
  // Cap the easiest allowed difficulty at the genesis target for each network.
  params.difficulty_adjustment_interval = 2016;
  params.difficulty_adjustment_activation_height = 0;
  // Witness commitment is mandatory from genesis.
  params.witness_commitment_activation_height = 0;
  params.pow_limit_bits = bits;
  params.genesis_bits = bits;
  params.genesis_time = timestamp;
  params.genesis_nonce = nonce;
  params.genesis_message = std::move(timestamp_msg);
  params.genesis_block = CreateGenesisBlock(network, params.initial_subsidy_miks,
                                            timestamp, nonce, bits);
  params.genesis_hash = ComputeBlockHash(params.genesis_block.header);
  return params;
}

}  // namespace

const ChainParams& Params(config::NetworkType type) {
  static ChainParams mainnet = [] {
    ChainParams p = BuildParams(config::NetworkType::kMainnet, "mainnet", "qry", 9375, 19735,
                                0x1f0fffff, 1767698282, 3363,
                                "QryptCoin genesis - mainnet");
    // Example deployment wiring for future soft-fork activation. No
    // consensus behavior depends on this yet; it is only used for
    // monitoring and version-bits metrics.
    DeploymentParams testdummy{
        "testdummy",
        0,  // bit 0
        p.genesis_time,               // start at genesis
        p.genesis_time + 31536000u,   // 1 year window
        144,                          // ~1 day of blocks at 10 min
        100,                          // ~70% threshold
    };
    p.deployments.push_back(testdummy);
    return p;
  }();

  static ChainParams testnet = [] {
    ChainParams p = BuildParams(config::NetworkType::kTestnet, "testnet", "tqry", 19375, 29735,
                                0x1f1fffff, 1767698283, 2533,
                                "QryptCoin genesis - testnet");
    DeploymentParams testdummy{
        "testdummy",
        0,
        p.genesis_time,
        p.genesis_time + 31536000u,
        72,   // shorter windows on testnet
        50,
    };
    p.deployments.push_back(testdummy);
    return p;
  }();

  static ChainParams regtest = [] {
    ChainParams p = BuildParams(config::NetworkType::kRegtest, "regtest", "rqry", 18444, 18445,
                                0x207ffffe, 1760000000, 1,
                                "QryptCoin genesis - regtest");
    // Very small windows and thresholds so tests can exercise state
    // transitions quickly.
    DeploymentParams testdummy{
        "testdummy",
        0,
        p.genesis_time,
        p.genesis_time + 31536000u,
        16,
        8,
    };
    p.deployments.push_back(testdummy);
    return p;
  }();

  static ChainParams signet = [] {
    ChainParams p = BuildParams(config::NetworkType::kSignet, "signet", "sqry", 39735, 49735,
                                0x1f2fffff, 1767698285, 462,
                                "QryptCoin genesis - signet");
    DeploymentParams testdummy{
        "testdummy",
        0,
        p.genesis_time,
        p.genesis_time + 31536000u,
        144,
        100,
    };
    p.deployments.push_back(testdummy);
    return p;
  }();

  switch (type) {
    case config::NetworkType::kMainnet:
      return mainnet;
    case config::NetworkType::kTestnet:
      return testnet;
    case config::NetworkType::kRegtest:
      return regtest;
    case config::NetworkType::kSignet:
      return signet;
  }
  return mainnet;
}

}  // namespace qryptcoin::consensus
