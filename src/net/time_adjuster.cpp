#include "net/time_adjuster.hpp"

#include <algorithm>
#include <mutex>
#include <vector>

namespace qryptcoin::net {

namespace {

TimeAdjuster g_time_adjuster;

}  // namespace

void TimeAdjuster::AddSample(std::int64_t offset_seconds) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (samples_.size() >= kMaxSamples) {
    // Drop the oldest sample to keep memory bounded.
    samples_.erase(samples_.begin());
  }
  samples_.push_back(offset_seconds);
}

std::int64_t TimeAdjuster::OffsetSeconds() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (samples_.empty()) {
    return 0;
  }
  std::vector<std::int64_t> sorted = samples_;
  std::sort(sorted.begin(), sorted.end());
  // Trim the top and bottom 20% of samples to reduce the impact of outliers.
  // This follows a trimmed-median strategy to keep time offset estimates
  // stable under adversarial or faulty peers.
  const std::size_t n = sorted.size();
  if (n >= 5) {
    const std::size_t trim = n / 5;
    sorted.erase(sorted.begin(), sorted.begin() + static_cast<std::ptrdiff_t>(trim));
    sorted.erase(sorted.end() - static_cast<std::ptrdiff_t>(trim), sorted.end());
  }
  const std::size_t mid = sorted.size() / 2;
  if (sorted.size() % 2 == 1) {
    return sorted[mid];
  }
  // Even number of samples: average the two middle values.
  const std::int64_t a = sorted[mid - 1];
  const std::int64_t b = sorted[mid];
  return (a + b) / 2;
}

TimeAdjuster& GlobalTimeAdjuster() { return g_time_adjuster; }

void AddTimeDataSample(std::int64_t offset_seconds) {
  GlobalTimeAdjuster().AddSample(offset_seconds);
}

std::int64_t GetTimeOffsetSeconds() {
  return GlobalTimeAdjuster().OffsetSeconds();
}

}  // namespace qryptcoin::net
