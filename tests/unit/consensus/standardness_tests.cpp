#include <cstdlib>
#include <iostream>

#include "policy/standardness.hpp"
#include "script/l2_anchor.hpp"
#include "script/p2qh.hpp"

using namespace qryptcoin;

primitives::CTransaction MakeBaseTx() {
  primitives::CTransaction tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.vin.resize(1);
  tx.vin[0].prevout = primitives::COutPoint::Null();
  tx.vin[0].sequence = 0xFFFFFFFFu;
  tx.vout.resize(1);
  tx.vout[0].value = 1;
  return tx;
}

bool TestScriptClassification() {
  // P2QH script
  crypto::P2QHDescriptor descriptor{};
  descriptor.program.fill(0xAA);
  script::ScriptPubKey p2qh_script = script::CreateP2QHScript(descriptor);
  if (policy::ClassifyScriptPubKey(p2qh_script) != policy::ScriptType::kP2QH) {
    std::cerr << "P2QH script misclassified\n";
    return false;
  }

  // L2 anchor script
  script::Layer2Commitment anchor{};
  anchor.version = 1;
  anchor.commitment.fill(0xBB);
  script::ScriptPubKey l2_script = script::CreateL2AnchorScript(anchor);
  if (policy::ClassifyScriptPubKey(l2_script) != policy::ScriptType::kL2Anchor) {
    std::cerr << "L2 anchor script misclassified\n";
    return false;
  }

  // Non-standard script
  script::ScriptPubKey junk;
  junk.data = {0x6A, 0x01, 0x02};  // OP_RETURN-like
  if (policy::ClassifyScriptPubKey(junk) != policy::ScriptType::kNonStandard) {
    std::cerr << "Non-standard script misclassified\n";
    return false;
  }

  return true;
}

bool TestIsStandardTransaction() {
  // Standard P2QH spend.
  crypto::P2QHDescriptor descriptor{};
  descriptor.program.fill(0x11);
  script::ScriptPubKey p2qh_script = script::CreateP2QHScript(descriptor);

  primitives::CTransaction tx = MakeBaseTx();
  tx.vin[0].prevout.index = 0;
  tx.vout[0].locking_descriptor = p2qh_script.data;

  std::string reason;
  if (!policy::IsStandardTransaction(tx, &reason)) {
    std::cerr << "Expected standard P2QH tx to pass: " << reason << "\n";
    return false;
  }

  // Non-standard output script.
  primitives::CTransaction nonstd = MakeBaseTx();
  nonstd.vout[0].locking_descriptor = {0x6A, 0x01, 0x02};
  if (policy::IsStandardTransaction(nonstd, &reason)) {
    std::cerr << "Expected non-standard script to be rejected\n";
    return false;
  }

  // Non-empty unlocking_descriptor should be rejected.
  primitives::CTransaction bad_unlock = MakeBaseTx();
  bad_unlock.vout[0].locking_descriptor = p2qh_script.data;
  bad_unlock.vin[0].unlocking_descriptor = {0x01};
  if (policy::IsStandardTransaction(bad_unlock, &reason)) {
    std::cerr << "Expected non-empty unlocking_descriptor to be rejected\n";
    return false;
  }

  return true;
}

bool TestStandardPackage() {
  // Build a simple two-transaction package with distinct inputs.
  crypto::P2QHDescriptor descriptor{};
  descriptor.program.fill(0x22);
  script::ScriptPubKey script_pub = script::CreateP2QHScript(descriptor);

  primitives::CTransaction tx1 = MakeBaseTx();
  tx1.vin[0].prevout.index = 0;
  tx1.vout[0].locking_descriptor = script_pub.data;

  primitives::CTransaction tx2 = MakeBaseTx();
  tx2.vin[0].prevout.index = 1;
  tx2.vout[0].locking_descriptor = script_pub.data;

  std::vector<primitives::CTransaction> pkg{tx1, tx2};
  std::string reason;
  if (!policy::IsStandardPackage(pkg, &reason)) {
    std::cerr << "Expected standard package to pass: " << reason << "\n";
    return false;
  }

  // Introduce a double-spend within the package.
  pkg[1].vin[0].prevout.index = 0;
  if (policy::IsStandardPackage(pkg, &reason)) {
    std::cerr << "Expected package with double-spend to be rejected\n";
    return false;
  }
  return true;
}

bool TestSignalsOptInRbf() {
  primitives::CTransaction tx = MakeBaseTx();
  // All inputs final -> no RBF signaling.
  if (policy::SignalsOptInRbf(tx)) {
    std::cerr << "Final transaction should not signal RBF\n";
    return false;
  }
  // Lower sequence should opt-in.
  tx.vin[0].sequence = 0xFFFFFFFEu;
  if (!policy::SignalsOptInRbf(tx)) {
    std::cerr << "Lower sequence should signal RBF\n";
    return false;
  }
  return true;
}

int main() {
  if (!TestScriptClassification()) {
    return EXIT_FAILURE;
  }
  if (!TestIsStandardTransaction()) {
    return EXIT_FAILURE;
  }
  if (!TestSignalsOptInRbf()) {
    return EXIT_FAILURE;
  }
  if (!TestStandardPackage()) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
