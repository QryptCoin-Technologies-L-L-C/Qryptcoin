#include "consensus/versionbits.hpp"

namespace qryptcoin::consensus {

namespace {

bool BlockSignalsBit(std::uint32_t version, int bit) {
  if (bit < 0 || bit >= 32) {
    return false;
  }
  const std::uint32_t mask = (1u << static_cast<std::uint32_t>(bit));
  return (version & mask) != 0;
}

}  // namespace

DeploymentStatus EvaluateDeployment(const DeploymentParams& dep,
                                    const ChainParams& /*params*/,
                                    BlockLookupFn lookup,
                                    std::uint32_t tip_height) {
  DeploymentStatus status;
  if (dep.window_size == 0 || dep.threshold == 0) {
    status.state = DeploymentState::kFailed;
    status.since_height = 0;
    return status;
  }
  if (tip_height == static_cast<std::uint32_t>(-1)) {
    status.state = DeploymentState::kDefined;
    status.since_height = 0;
    return status;
  }

  const std::uint32_t window = dep.window_size;
  const std::uint32_t last_height = tip_height;
  const std::uint32_t current_period = (last_height + 1) / window;

  DeploymentState state = DeploymentState::kDefined;
  std::uint32_t state_since = 0;

  for (std::uint32_t period = 0; period <= current_period; ++period) {
    const std::uint32_t period_start = period * window;
    if (period_start > last_height) break;
    const std::uint32_t period_end =
        std::min(period_start + window - 1, last_height);

    std::uint32_t end_time = 0;
    std::uint32_t end_version = 0;
    if (!lookup(period_end, &end_time, &end_version)) {
      break;
    }

    switch (state) {
      case DeploymentState::kDefined:
        if (end_time >= dep.timeout) {
          state = DeploymentState::kFailed;
          state_since = period_start;
        } else if (end_time >= dep.start_time) {
          state = DeploymentState::kStarted;
          state_since = period_start;
        }
        break;
      case DeploymentState::kStarted:
        if (end_time >= dep.timeout) {
          state = DeploymentState::kFailed;
          state_since = period_start;
          break;
        } else {
          std::uint32_t signals = 0;
          std::uint32_t total = 0;
          for (std::uint32_t h = period_start; h <= period_end; ++h) {
            std::uint32_t t = 0;
            std::uint32_t v = 0;
            if (!lookup(h, &t, &v)) {
              break;
            }
            ++total;
            if (BlockSignalsBit(v, dep.bit)) {
              ++signals;
            }
          }
          if (signals >= dep.threshold) {
            state = DeploymentState::kLockedIn;
            state_since = period_end + 1;
          }
        }
        break;
      case DeploymentState::kLockedIn:
        // The next period after LOCKED_IN is ACTIVE.
        state = DeploymentState::kActive;
        state_since = period_start;
        break;
      case DeploymentState::kActive:
      case DeploymentState::kFailed:
        // Stable terminal states.
        break;
    }
  }

  status.state = state;
  status.since_height = state_since;

  // Compute statistics for the current window.
  const std::uint32_t current_start = (last_height + 1) / window * window;
  if (current_start <= last_height) {
    status.period_start_height = current_start;
    std::uint32_t signals = 0;
    std::uint32_t total = 0;
    for (std::uint32_t h = current_start; h <= last_height; ++h) {
      std::uint32_t t = 0;
      std::uint32_t v = 0;
      if (!lookup(h, &t, &v)) {
        break;
      }
      ++total;
      if (BlockSignalsBit(v, dep.bit)) {
        ++signals;
      }
    }
    status.period_signals = signals;
    status.period_length = total;
  }

  return status;
}

const char* DeploymentStateToString(DeploymentState state) {
  switch (state) {
    case DeploymentState::kDefined:
      return "defined";
    case DeploymentState::kStarted:
      return "started";
    case DeploymentState::kLockedIn:
      return "locked_in";
    case DeploymentState::kActive:
      return "active";
    case DeploymentState::kFailed:
      return "failed";
  }
  return "unknown";
}

}  // namespace qryptcoin::consensus

