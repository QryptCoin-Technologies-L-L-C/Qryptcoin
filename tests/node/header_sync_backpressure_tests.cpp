// Verifies that header sync backpressure constants and instrumentation fields remain sane.

#include <cstdint>
#include <cstdlib>
#include <iostream>

#include "node/block_sync.hpp"

namespace {

// Keep these in sync with the production constants in `src/node/block_sync.cpp`.
constexpr std::size_t kMaxStoredHeadersTotal = 8192;
constexpr std::size_t kMaxStoredHeadersPerPeer = 4096;
constexpr std::size_t kHeadersAheadHighWater = 1500;
constexpr std::size_t kHeadersAheadLowWater = 500;
constexpr std::size_t kDownloadQueueHighWater = 512;

bool ThresholdsAreSane() {
  if (!(kHeadersAheadHighWater > kHeadersAheadLowWater)) {
    std::cerr << "expected high-water > low-water\n";
    return false;
  }
  if (!(kMaxStoredHeadersPerPeer < kMaxStoredHeadersTotal)) {
    std::cerr << "expected per-peer header cap < total cap\n";
    return false;
  }
  if (kDownloadQueueHighWater == 0) {
    std::cerr << "expected download queue high-water to be non-zero\n";
    return false;
  }
  return true;
}

bool SyncStatsHasHeaderMetrics() {
  qryptcoin::node::BlockSyncManager::SyncStats stats;
  if (stats.headers_pruned_total != 0 ||
      stats.headers_dropped_duplicate != 0 ||
      stats.getheaders_paused_backpressure != 0 ||
      stats.header_highwater_events != 0 ||
      stats.pending_headers != 0) {
    std::cerr << "unexpected non-zero header instrumentation defaults\n";
    return false;
  }
  if (stats.headers_gap != 0 ||
      stats.active_outbound_peers != 0 ||
      stats.frontier_height != 0 ||
      stats.inflight_blocks != 0 ||
      stats.requestable_blocks != 0 ||
      stats.orphan_pool_size != 0 ||
      stats.block_stall_recoveries != 0 ||
      stats.inflight_block_timeouts != 0 ||
      stats.unsolicited_headers_ignored != 0 ||
      stats.parent_ready_blocked != 0 ||
      stats.scheduler_no_requestable_cycles != 0 ||
      stats.stall_breaker_activations != 0) {
    std::cerr << "unexpected non-zero sync instrumentation defaults\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  if (!ThresholdsAreSane()) {
    return EXIT_FAILURE;
  }
  if (!SyncStatsHasHeaderMetrics()) {
    return EXIT_FAILURE;
  }
  std::cout << "header_sync_backpressure_tests: OK\n";
  return EXIT_SUCCESS;
}
