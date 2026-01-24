#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <vector>

#include "rpc/server.hpp"
#include "node/chain_state.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/pq_engine.hpp"
#include "script/p2qh.hpp"
#include "primitives/serialize.hpp"
#include "primitives/txid.hpp"
#include "policy/standardness.hpp"
#include "tests/unit/util/deterministic_rng.hpp"

using namespace qryptcoin;

primitives::CTransaction MakeStandardTx(std::uint8_t tag) {
  test::ScopedDeterministicRng rng(tag);
  auto key = crypto::QPqDilithiumKey::Generate();
  const auto reveal = crypto::BuildP2QHReveal(key.PublicKey());
  const auto descriptor = crypto::DescriptorFromReveal(reveal);

  primitives::CTransaction tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.vin.resize(1);
  tx.vout.resize(1);

  // Non-coinbase input with arbitrary prevout.
  tx.vin[0].prevout.txid.fill(tag);
  tx.vin[0].prevout.index = 0;
  tx.vin[0].unlocking_descriptor.clear();
  tx.vin[0].sequence = 0xFFFFFFFFu;
  primitives::WitnessStackItem reveal_item;
  reveal_item.data = reveal;
  primitives::WitnessStackItem sig_item;
  sig_item.data.assign(crypto::DilithiumSignatureSize(), tag);
  tx.vin[0].witness_stack = {reveal_item, sig_item};

  // Simple P2QH output so the transaction is considered standard.
  script::ScriptPubKey script_pub = script::CreateP2QHScript(descriptor);
  tx.vout[0].value = 1;
  tx.vout[0].locking_descriptor = script_pub.data;

  return tx;
}

int main() {
  try {
    std::filesystem::create_directories("testdata");

    node::ChainState chain("testdata/mempool-blocks.dat",
                           "testdata/mempool-utxo.dat");

    // Measure a baseline transaction size to calibrate the mempool limit.
    primitives::CTransaction proto = MakeStandardTx(0x01);
    std::vector<std::uint8_t> raw_proto;
    primitives::serialize::SerializeTransaction(proto, &raw_proto);
    const std::uint64_t proto_bytes =
        static_cast<std::uint64_t>(raw_proto.size());

    // Eviction test: limit set so that only one transaction fits.
    rpc::RpcServer server_eviction(/*wallet=*/nullptr,
                                   /*wallet_enabled=*/false,
                                   chain,
                                   /*peers=*/nullptr,
                                   /*sync=*/nullptr,
                                   /*addrman=*/nullptr,
                                   /*dns_seeds=*/nullptr,
                                   /*is_seed_node=*/false,
                                   /*default_mining_address=*/"",
                                   /*allow_generate=*/false,
                                   /*read_only=*/false,
                                   /*mempool_limit_bytes=*/proto_bytes);

    primitives::CTransaction low = MakeStandardTx(0x02);
    primitives::CTransaction high = MakeStandardTx(0x03);

    if (!server_eviction.AddToMempoolForTest(low, /*feerate_miks_per_vb=*/1.0)) {
      std::cerr << "Failed to add low-fee tx to mempool\n";
      return EXIT_FAILURE;
    }
    if (!server_eviction.AddToMempoolForTest(high, /*feerate_miks_per_vb=*/10.0)) {
      std::cerr << "Failed to add high-fee tx to mempool\n";
      return EXIT_FAILURE;
    }

    const auto low_id = primitives::ComputeTxId(low);
    const auto high_id = primitives::ComputeTxId(high);

    // With a limit equal to a single tx size, the lower-fee transaction
    // should have been evicted when the second tx was admitted.
    if (server_eviction.HasMempoolTransaction(low_id)) {
      std::cerr << "Expected low-fee tx to be evicted\n";
      return EXIT_FAILURE;
    }
    if (!server_eviction.HasMempoolTransaction(high_id)) {
      std::cerr << "High-fee tx missing from mempool after eviction\n";
      return EXIT_FAILURE;
    }

    // RBF test: opt-in replacement of a single transaction.
    rpc::RpcServer server_rbf(/*wallet=*/nullptr,
                              /*wallet_enabled=*/false,
                              chain,
                              /*peers=*/nullptr,
                              /*sync=*/nullptr,
                              /*addrman=*/nullptr,
                              /*dns_seeds=*/nullptr,
                              /*is_seed_node=*/false,
                              /*default_mining_address=*/"",
                              /*allow_generate=*/false,
                              /*read_only=*/false,
                              /*mempool_limit_bytes=*/10 * proto_bytes);

    primitives::CTransaction orig = MakeStandardTx(0x04);
    orig.vin[0].sequence = 0xFFFFFFFEu;  // opt-in RBF
    if (!server_rbf.AddToMempoolForTest(orig, /*feerate_miks_per_vb=*/5.0)) {
      std::cerr << "Failed to add original RBF tx\n";
      return EXIT_FAILURE;
    }
    const auto orig_id = primitives::ComputeTxId(orig);

    primitives::CTransaction rep = orig;
    // Change a field so that the replacement has a different txid but
    // spends the same prevout.
    rep.lock_time = 1;
    const auto rep_id = primitives::ComputeTxId(rep);

    if (!server_rbf.AddToMempoolForTest(rep, /*feerate_miks_per_vb=*/8.0)) {
      std::cerr << "Expected higher-fee replacement to be accepted\n";
      return EXIT_FAILURE;
    }
    if (server_rbf.HasMempoolTransaction(orig_id)) {
      std::cerr << "Original RBF tx still present after replacement\n";
      return EXIT_FAILURE;
    }
    if (!server_rbf.HasMempoolTransaction(rep_id)) {
      std::cerr << "Replacement tx missing after RBF\n";
      return EXIT_FAILURE;
    }

    // RBF must reject replacement of non-opt-in transactions.
    rpc::RpcServer server_no_rbf(/*wallet=*/nullptr,
                                 /*wallet_enabled=*/false,
                                 chain,
                                 /*peers=*/nullptr,
                                 /*sync=*/nullptr,
                                 /*addrman=*/nullptr,
                                 /*dns_seeds=*/nullptr,
                                 /*is_seed_node=*/false,
                                 /*default_mining_address=*/"",
                                 /*allow_generate=*/false,
                                 /*read_only=*/false,
                                 /*mempool_limit_bytes=*/10 * proto_bytes);

    primitives::CTransaction orig2 = MakeStandardTx(0x05);
    orig2.vin[0].sequence = 0xFFFFFFFFu;  // final, no RBF
    if (!server_no_rbf.AddToMempoolForTest(orig2, /*feerate_miks_per_vb=*/5.0)) {
      std::cerr << "Failed to add non-RBF original tx\n";
      return EXIT_FAILURE;
    }
    const auto orig2_id = primitives::ComputeTxId(orig2);

    primitives::CTransaction rep2 = orig2;
    rep2.lock_time = 1;
    const auto rep2_id = primitives::ComputeTxId(rep2);

    if (server_no_rbf.AddToMempoolForTest(rep2, /*feerate_miks_per_vb=*/8.0)) {
      std::cerr << "Unexpectedly accepted replacement of non-RBF tx\n";
      return EXIT_FAILURE;
    }
    if (!server_no_rbf.HasMempoolTransaction(orig2_id)) {
      std::cerr << "Original non-RBF tx missing after failed replacement\n";
      return EXIT_FAILURE;
    }
    if (server_no_rbf.HasMempoolTransaction(rep2_id)) {
      std::cerr << "Replacement of non-RBF tx leaked into mempool\n";
      return EXIT_FAILURE;
    }

    // Multi-conflict RBF: a replacement spending two opt-in transactions.
    rpc::RpcServer server_multi_rbf(/*wallet=*/nullptr,
                                    /*wallet_enabled=*/false,
                                    chain,
                                    /*peers=*/nullptr,
                                    /*sync=*/nullptr,
                                    /*addrman=*/nullptr,
                                    /*dns_seeds=*/nullptr,
                                    /*is_seed_node=*/false,
                                    /*default_mining_address=*/"",
                                    /*allow_generate=*/false,
                                    /*read_only=*/false,
                                    /*mempool_limit_bytes=*/20 * proto_bytes);

    primitives::CTransaction a = MakeStandardTx(0x10);
    a.vin[0].sequence = 0xFFFFFFFEu;  // opt-in RBF
    a.vin[0].prevout.index = 0;
    primitives::CTransaction b = MakeStandardTx(0x11);
    b.vin[0].sequence = 0xFFFFFFFEu;
    b.vin[0].prevout.index = 1;

    if (!server_multi_rbf.AddToMempoolForTest(a, /*feerate_miks_per_vb=*/2.0)) {
      std::cerr << "Failed to add first multi-RBF tx\n";
      return EXIT_FAILURE;
    }
    if (!server_multi_rbf.AddToMempoolForTest(b, /*feerate_miks_per_vb=*/3.0)) {
      std::cerr << "Failed to add second multi-RBF tx\n";
      return EXIT_FAILURE;
    }

    primitives::CTransaction rep_multi;
    rep_multi.version = 1;
    rep_multi.lock_time = 0;
    rep_multi.vin.resize(2);
    rep_multi.vout.resize(1);
    rep_multi.vin[0] = a.vin[0];
    rep_multi.vin[1] = b.vin[0];
    rep_multi.vout[0] = a.vout[0];

    const auto a_id = primitives::ComputeTxId(a);
    const auto b_id = primitives::ComputeTxId(b);
    const auto rep_multi_id = primitives::ComputeTxId(rep_multi);

    if (!server_multi_rbf.AddToMempoolForTest(rep_multi,
                                              /*feerate_miks_per_vb=*/6.0)) {
      std::cerr << "Expected multi-conflict replacement to be accepted\n";
      return EXIT_FAILURE;
    }
    if (server_multi_rbf.HasMempoolTransaction(a_id) ||
        server_multi_rbf.HasMempoolTransaction(b_id)) {
      std::cerr << "Original multi-RBF txs still present after replacement\n";
      return EXIT_FAILURE;
    }
    if (!server_multi_rbf.HasMempoolTransaction(rep_multi_id)) {
      std::cerr << "Multi-conflict replacement missing from mempool\n";
      return EXIT_FAILURE;
    }

    // Too many conflicts: create a replacement that touches more than
    // the allowed number of conflicting transactions and ensure it is
    // rejected while originals remain intact.
    rpc::RpcServer server_too_many(/*wallet=*/nullptr,
                                   /*wallet_enabled=*/false,
                                   chain,
                                   /*peers=*/nullptr,
                                   /*sync=*/nullptr,
                                   /*addrman=*/nullptr,
                                   /*dns_seeds=*/nullptr,
                                   /*is_seed_node=*/false,
                                   /*default_mining_address=*/"",
                                   /*allow_generate=*/false,
                                   /*read_only=*/false,
                                   /*mempool_limit_bytes=*/100 * proto_bytes);

    std::vector<primitives::CTransaction> conflicts;
    for (std::uint8_t tag = 0x20; tag < 0x20 + 6; ++tag) {
      primitives::CTransaction tx = MakeStandardTx(tag);
      tx.vin[0].sequence = 0xFFFFFFFEu;
      tx.vin[0].prevout.index = static_cast<std::uint32_t>(tag - 0x20);
      if (!server_too_many.AddToMempoolForTest(tx, /*feerate=*/4.0)) {
        std::cerr << "Failed to add conflict tx with tag " << static_cast<int>(tag)
                  << "\n";
        return EXIT_FAILURE;
      }
      conflicts.push_back(tx);
    }

    primitives::CTransaction rep_many;
    rep_many.version = 1;
    rep_many.lock_time = 0;
    rep_many.vin.resize(conflicts.size());
    rep_many.vout.resize(1);
    rep_many.vout[0] = conflicts.front().vout[0];
    for (std::size_t i = 0; i < conflicts.size(); ++i) {
      rep_many.vin[i] = conflicts[i].vin[0];
    }
    const auto rep_many_id = primitives::ComputeTxId(rep_many);

    if (server_too_many.AddToMempoolForTest(rep_many, /*feerate=*/10.0)) {
      std::cerr << "Unexpectedly accepted replacement that conflicts with "
                << conflicts.size() << " transactions\n";
      return EXIT_FAILURE;
    }
    for (const auto& tx : conflicts) {
      const auto id = primitives::ComputeTxId(tx);
      if (!server_too_many.HasMempoolTransaction(id)) {
        std::cerr << "Conflict tx disappeared after failed multi-conflict RBF\n";
        return EXIT_FAILURE;
      }
    }
    if (server_too_many.HasMempoolTransaction(rep_many_id)) {
      std::cerr << "Multi-conflict replacement leaked into mempool\n";
      return EXIT_FAILURE;
    }

    // Dependent transaction chain: when a parent is replaced/evicted, any
    // descendants that spend its outputs must also be removed so the mempool
    // does not retain orphaned entries.
    rpc::RpcServer server_desc(/*wallet=*/nullptr,
                               /*wallet_enabled=*/false,
                               chain,
                               /*peers=*/nullptr,
                               /*sync=*/nullptr,
                               /*addrman=*/nullptr,
                               /*dns_seeds=*/nullptr,
                               /*is_seed_node=*/false,
                               /*default_mining_address=*/"",
                               /*allow_generate=*/false,
                               /*read_only=*/false,
                               /*mempool_limit_bytes=*/100 * proto_bytes);

    primitives::CTransaction parent = MakeStandardTx(0x40);
    parent.vin[0].sequence = 0xFFFFFFFEu;  // opt-in RBF
    if (!server_desc.AddToMempoolForTest(parent, /*feerate=*/2.0)) {
      std::cerr << "Failed to add parent tx for descendant eviction test\n";
      return EXIT_FAILURE;
    }
    const auto parent_id = primitives::ComputeTxId(parent);

    primitives::CTransaction child = MakeStandardTx(0x41);
    child.vin[0].prevout.txid = parent_id;
    child.vin[0].prevout.index = 0;
    if (!server_desc.AddToMempoolForTest(child, /*feerate=*/3.0)) {
      std::cerr << "Failed to add child tx for descendant eviction test\n";
      return EXIT_FAILURE;
    }
    const auto child_id = primitives::ComputeTxId(child);

    primitives::CTransaction replacement = parent;
    replacement.lock_time = 1;  // mutate txid while keeping the same prevout
    const auto replacement_id = primitives::ComputeTxId(replacement);
    if (!server_desc.AddToMempoolForTest(replacement, /*feerate=*/6.0)) {
      std::cerr << "Expected parent replacement to be accepted\n";
      return EXIT_FAILURE;
    }
    if (server_desc.HasMempoolTransaction(parent_id)) {
      std::cerr << "Parent tx still present after replacement\n";
      return EXIT_FAILURE;
    }
    if (server_desc.HasMempoolTransaction(child_id)) {
      std::cerr << "Child tx still present after parent replacement\n";
      return EXIT_FAILURE;
    }
    if (!server_desc.HasMempoolTransaction(replacement_id)) {
      std::cerr << "Replacement tx missing after parent replacement\n";
      return EXIT_FAILURE;
    }
    // Ensure descendant removal cleaned up the outpoint spend index by
    // admitting a new orphan spend of the removed parent's output.
    primitives::CTransaction orphan = MakeStandardTx(0x42);
    orphan.vin[0].prevout.txid = parent_id;
    orphan.vin[0].prevout.index = 0;
    if (!server_desc.AddToMempoolForTest(orphan, /*feerate=*/1.0)) {
      std::cerr << "Expected orphan spend to be accepted after descendant removal\n";
      return EXIT_FAILURE;
    }

    // Simple package-aware admission example: standard package should
    // be accepted by policy and can then be inserted tx-by-tx.
    std::vector<primitives::CTransaction> pkg;
    pkg.push_back(MakeStandardTx(0x30));
    pkg.push_back(MakeStandardTx(0x31));
    std::string pkg_reason;
    if (!policy::IsStandardPackage(pkg, &pkg_reason)) {
      std::cerr << "Expected standard package to pass policy checks: "
                << pkg_reason << "\n";
      return EXIT_FAILURE;
    }

    rpc::RpcServer server_pkg(/*wallet=*/nullptr,
                              /*wallet_enabled=*/false,
                              chain,
                              /*peers=*/nullptr,
                              /*sync=*/nullptr,
                              /*addrman=*/nullptr,
                              /*dns_seeds=*/nullptr,
                              /*is_seed_node=*/false,
                              /*default_mining_address=*/"",
                              /*allow_generate=*/false,
                              /*read_only=*/false,
                              /*mempool_limit_bytes=*/100 * proto_bytes);
    for (const auto& tx : pkg) {
      if (!server_pkg.AddToMempoolForTest(tx, /*feerate=*/1.0)) {
        std::cerr << "Failed to add package tx to mempool\n";
        return EXIT_FAILURE;
      }
    }

    std::filesystem::remove("testdata/mempool-blocks.dat");
    std::filesystem::remove("testdata/mempool-utxo.dat");
  } catch (const std::exception& ex) {
    std::cerr << "mempool_rbf_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
