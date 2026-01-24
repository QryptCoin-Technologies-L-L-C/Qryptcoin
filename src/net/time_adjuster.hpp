#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

namespace qryptcoin::net {

// TimeAdjuster maintains a trimmed-median view of the difference between
// local system time and peer-reported times. The offset is expressed in
// seconds and is intended as a diagnostic/telemetry aid rather than a
// consensus primitive.
class TimeAdjuster {
 public:
  // Record a new time offset sample (peer_time - local_time, in seconds).
  void AddSample(std::int64_t offset_seconds);

  // Return the current trimmed-median offset (in seconds). If no samples
  // are available, returns 0.
  std::int64_t OffsetSeconds() const;

 private:
  static constexpr std::size_t kMaxSamples = 200;

  mutable std::mutex mutex_;
  std::vector<std::int64_t> samples_;
};

// Global singleton accessor used by networking and RPC layers.
TimeAdjuster& GlobalTimeAdjuster();

// Convenience helpers.
void AddTimeDataSample(std::int64_t offset_seconds);
std::int64_t GetTimeOffsetSeconds();

}  // namespace qryptcoin::net
