#pragma once

#include <cstdint>
#include <functional>

#include "consensus/params.hpp"

namespace qryptcoin::consensus {

enum class DeploymentState {
  kDefined,
  kStarted,
  kLockedIn,
  kActive,
  kFailed,
};

struct DeploymentStatus {
  DeploymentState state{DeploymentState::kDefined};
  std::uint32_t since_height{0};         // First height where this state applies.
  std::uint32_t period_start_height{0};  // Start height of the current statistics window.
  std::uint32_t period_signals{0};       // Blocks signaling in the current window.
  std::uint32_t period_length{0};        // Blocks observed in the current window.
};

// Lightweight adapter: callers provide a lookup function that, given a
// height in the active chain, returns the header timestamp and version.
using BlockLookupFn = std::function<bool(std::uint32_t height,
                                         std::uint32_t* out_time,
                                         std::uint32_t* out_version)>;

DeploymentStatus EvaluateDeployment(const DeploymentParams& dep,
                                    const ChainParams& params,
                                    BlockLookupFn lookup,
                                    std::uint32_t tip_height);

const char* DeploymentStateToString(DeploymentState state);

}  // namespace qryptcoin::consensus

