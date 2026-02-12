#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace qryptcoin::net {

// AddrManager is a lightweight, in-memory address manager. It keeps track of
// known peer addresses, basic success/failure history, and provides randomized
// candidates for outbound connection attempts. The intent is to keep the
// design simple and telemetry-focused rather than perfectly replicate a
// bucketed selection scheme.
class AddrManager {
 public:
  struct SeedStats {
    std::uint64_t dns_lookups{0};
    std::uint64_t dns_addresses{0};
    std::uint64_t dns_failures{0};
    std::uint64_t static_seeds{0};
  };
  struct Entry {
    std::string host;
    std::uint16_t port{0};
    std::uint64_t last_success{0};
    std::uint64_t last_attempt{0};
    std::uint32_t attempts{0};
    bool permanent{false};
  };

  // Add or update a known address. Permanent entries are seeded from
  // configuration (static seeds, manual connect targets) and are
  // never pruned automatically.
  void Add(const std::string& host, std::uint16_t port, bool permanent);

  // Mark the outcome of a connection attempt so future selection can
  // prefer recently successful peers and deprioritize persistent
  // failures.
  void MarkResult(const std::string& host, std::uint16_t port, bool success);

  // Select the next candidate for an outbound connection. Returns
  // std::nullopt when there is nothing suitable to try at the moment.
  // An optional set of hosts to exclude (already-connected peers) can
  // be provided to avoid selecting addresses that already have active
  // outbound connections.
  std::optional<Entry> Select(
      const std::unordered_set<std::string>& exclude_hosts = {}) const;

  // Age-out failure counters so temporarily bad addresses can be retried.
  void DecayFailureCounts(std::uint64_t max_age_seconds = 3600);
  // Clear failure counters for every entry.
  void ResetAllFailureCounts();
  // Returns true when every known address has exceeded the consecutive-failure cap.
  bool AllEntriesDemoted() const;

  // Persist the address table to disk in a simple JSON format.
  bool Save(const std::filesystem::path& path, std::string* error) const;

  // Load the address table from disk. Fails softly if the file does
  // not exist; hard failures only occur for malformed data.
  bool Load(const std::filesystem::path& path, std::string* error);

  // Lightweight introspection helpers used for telemetry and
  // bootstrapping decisions.
  std::size_t EntryCount() const;
  SeedStats GetSeedStats() const;
  void RecordDnsLookup(std::size_t addresses, std::size_t failures);
  void RecordStaticSeeds(std::size_t count);

 private:
  static std::uint64_t NowSeconds();
  static std::string Key(const std::string& host, std::uint16_t port);

  mutable std::mutex mutex_;
  std::vector<Entry> entries_;
  std::unordered_map<std::string, std::size_t> index_;

  // Seed resolution telemetry (protected by mutex_).
  std::uint64_t dns_lookups_{0};
  std::uint64_t dns_addresses_{0};
  std::uint64_t dns_failures_{0};
  std::uint64_t static_seeds_{0};
};

}  // namespace qryptcoin::net

