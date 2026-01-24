#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace qryptcoin::net {

// DnsSeedManager owns a small cache of DNS seed resolution
// results. It is intentionally simple: qryptd calls Tick() from its
// main loop to refresh seeds periodically, while RPC handlers query
// snapshots for operator telemetry.
class DnsSeedManager {
 public:
  struct SeedSnapshot {
    std::string host;
    std::uint64_t resolve_attempts{0};
    std::uint64_t resolve_failures{0};
    // Seconds since UNIX epoch; zero when no successful lookup has
    // completed yet.
    std::uint64_t last_resolve_time{0};
    std::vector<std::string> last_addresses;
  };

  explicit DnsSeedManager(bool allow_private_peers);

  // Initialize the managed seed set. Safe to call only once during
  // startup, before any Tick() or Snapshot*() calls.
  void Initialize(const std::vector<std::string>& hosts);

  // Periodic maintenance hook; performs DNS resolutions when they are
  // due. Intended to be called from qryptd's main loop.
  void Tick();

  // Mark all seeds as immediately due for refresh. Used by the
  // refreshdnsseeds RPC and at startup.
  void ForceRefresh();

  // Aggregated view of all cached addresses across seeds.
  std::vector<std::string> SnapshotAllAddresses() const;

  // Per-seed telemetry for RPC and operator tools.
  std::vector<SeedSnapshot> SnapshotSeeds() const;

  std::size_t CachedPeerCount() const;

 private:
  struct Entry {
    std::string host;
    std::uint64_t resolve_attempts{0};
    std::uint64_t resolve_failures{0};
    std::chrono::system_clock::time_point last_resolve{};
    std::chrono::steady_clock::time_point next_resolve{};
    std::vector<std::string> cached_addresses;
  };

  bool allow_private_peers_{false};
  mutable std::mutex mutex_;
  std::vector<Entry> entries_;
};

}  // namespace qryptcoin::net

