#include <cstdint>
#include <iostream>

#include "net/time_adjuster.hpp"

int main() {
  using qryptcoin::net::TimeAdjuster;

  TimeAdjuster adj;
  if (adj.OffsetSeconds() != 0) {
    std::cerr << "expected zero offset with no samples\n";
    return 1;
  }

  // Offsets in seconds: deliberately include outliers.
  adj.AddSample(-10);  // low outlier
  adj.AddSample(0);
  adj.AddSample(5);
  adj.AddSample(20);
  adj.AddSample(100);  // high outlier

  const std::int64_t offset = adj.OffsetSeconds();
  // With the current trimmed-median logic, this should land on 5:
  // sorted = [-10, 0, 5, 20, 100]
  // trim 20% from each side -> [0, 5, 20], median = 5.
  if (offset != 5) {
    std::cerr << "unexpected trimmed-median offset: " << offset << " (expected 5)\n";
    return 1;
  }

  std::cout << "time_adjuster_tests: OK\n";
  return 0;
}

