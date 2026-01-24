#include <cstdlib>
#include <iostream>
#include <vector>

#include "consensus/params.hpp"
#include "consensus/versionbits.hpp"

using namespace qryptcoin;

struct FakeBlock {
  std::uint32_t time;
  std::uint32_t version;
};

int main() {
  // Construct a tiny synthetic chain so that version-bits evaluation
  // can be exercised without depending on real headers.
  std::vector<FakeBlock> chain;
  const std::uint32_t start_time = 1'000'000u;
  const std::uint32_t window = 4;

  consensus::DeploymentParams dep{
      "testdummy",
      1,  // use bit 1 so version=0b10 signals.
      start_time,
      start_time + 1000,
      window,
      3,  // 3 of 4 blocks per window.
  };

  consensus::ChainParams params{};

  consensus::BlockLookupFn lookup = [&chain](std::uint32_t height,
                                             std::uint32_t* out_time,
                                             std::uint32_t* out_version) -> bool {
    if (height >= chain.size()) return false;
    if (out_time) *out_time = chain[height].time;
    if (out_version) *out_version = chain[height].version;
    return true;
  };

  // Initially there are no blocks; state must be defined.
  auto status = consensus::EvaluateDeployment(dep, params, lookup, 0);
  if (status.state != consensus::DeploymentState::kDefined) {
    std::cerr << "Expected initial state=defined\n";
    return EXIT_FAILURE;
  }

  // Build a first window with timestamps before start_time.
  for (std::uint32_t i = 0; i < window; ++i) {
    chain.push_back(FakeBlock{start_time - 10, 0});
  }
  status = consensus::EvaluateDeployment(dep, params, lookup,
                                         static_cast<std::uint32_t>(chain.size() - 1));
  if (status.state != consensus::DeploymentState::kDefined) {
    std::cerr << "Expected state=defined before start_time\n";
    return EXIT_FAILURE;
  }

  // Second window: timestamps past start_time, with insufficient
  // signaling (only 2 of 4 blocks signal).
  for (std::uint32_t i = 0; i < window; ++i) {
    const bool signal = (i < 2);
    const std::uint32_t ver = signal ? (1u << dep.bit) : 0u;
    chain.push_back(FakeBlock{start_time + 10, ver});
  }
  status = consensus::EvaluateDeployment(
      dep, params, lookup, static_cast<std::uint32_t>(chain.size() - 1));
  if (status.state != consensus::DeploymentState::kStarted) {
    std::cerr << "Expected state=started when past start_time with insufficient signaling\n";
    return EXIT_FAILURE;
  }

  // Third window: 3 of 4 blocks signal, reaching the threshold and
  // transitioning to LOCKED_IN.
  for (std::uint32_t i = 0; i < window; ++i) {
    const bool signal = (i < 3);
    const std::uint32_t ver = signal ? (1u << dep.bit) : 0u;
    chain.push_back(FakeBlock{start_time + 20, ver});
  }
  status = consensus::EvaluateDeployment(
      dep, params, lookup, static_cast<std::uint32_t>(chain.size() - 1));
  if (status.state != consensus::DeploymentState::kLockedIn) {
    std::cerr << "Expected state=locked_in after threshold reached\n";
    return EXIT_FAILURE;
  }

  // Fourth window: once a new period begins after LOCKED_IN, the
  // deployment becomes ACTIVE.
  for (std::uint32_t i = 0; i < window; ++i) {
    chain.push_back(FakeBlock{start_time + 30, 0});
  }
  status = consensus::EvaluateDeployment(
      dep, params, lookup, static_cast<std::uint32_t>(chain.size() - 1));
  if (status.state != consensus::DeploymentState::kActive) {
    std::cerr << "Expected state=active after locked_in period\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

