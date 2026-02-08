#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_set>

#include "net/addr_manager.hpp"
#include "nlohmann/json.hpp"

namespace {

std::filesystem::path MakeTempPeersPath() {
  const auto base = std::filesystem::temp_directory_path();
  const auto suffix = static_cast<std::uint64_t>(std::random_device{}());
  return base / ("qryptcoin_addr_manager_tests_" + std::to_string(suffix) + ".json");
}

nlohmann::json ReadJsonFile(const std::filesystem::path& path) {
  std::ifstream in(path);
  if (!in) {
    throw std::runtime_error("failed to open json file for read: " + path.string());
  }
  nlohmann::json json;
  in >> json;
  return json;
}

}  // namespace

int main() {
  using qryptcoin::net::AddrManager;

  try {
    AddrManager manager;

    manager.RecordDnsLookup(5, 1);
    manager.RecordDnsLookup(2, 0);
    manager.RecordStaticSeeds(3);
    const auto stats = manager.GetSeedStats();
    if (stats.dns_lookups != 2 || stats.dns_addresses != 7 || stats.dns_failures != 1 ||
        stats.static_seeds != 3) {
      std::cerr << "unexpected seed stats counters\n";
      return 1;
    }

    manager.Add("203.0.113.5", 9375, false);
    manager.Add("203.0.113.5", 9375, false);
    if (manager.EntryCount() != 1u) {
      std::cerr << "expected duplicate address to be de-duplicated\n";
      return 1;
    }

    manager.MarkResult("203.0.113.5", 9375, false);

    const auto peers_path = MakeTempPeersPath();
    std::string error;
    if (!manager.Save(peers_path, &error)) {
      std::cerr << "save failed: " << error << "\n";
      return 1;
    }

    auto json = ReadJsonFile(peers_path);
    if (!json.is_array() || json.size() != 1u) {
      std::cerr << "expected peers json to contain one entry\n";
      return 1;
    }
    const auto& entry0 = json.at(0);
    if (entry0.value("host", "") != "203.0.113.5" ||
        entry0.value("port", 0) != 9375 ||
        entry0.value("attempts", 0) != 1 ||
        entry0.value("last_attempt", 0ULL) == 0ULL ||
        entry0.value("last_success", 0ULL) != 0ULL) {
      std::cerr << "unexpected fields after failure mark\n";
      return 1;
    }

    manager.MarkResult("203.0.113.5", 9375, true);
    if (!manager.Save(peers_path, &error)) {
      std::cerr << "save failed: " << error << "\n";
      return 1;
    }
    json = ReadJsonFile(peers_path);
    const auto& entry1 = json.at(0);
    if (entry1.value("attempts", 0) != 0 ||
        entry1.value("last_success", 0ULL) == 0ULL) {
      std::cerr << "expected success mark to reset attempts and set last_success\n";
      return 1;
    }

    AddrManager loaded;
    if (!loaded.Load(peers_path, &error)) {
      std::cerr << "load failed: " << error << "\n";
      return 1;
    }
    if (loaded.EntryCount() != 1u) {
      std::cerr << "expected one entry after reload\n";
      return 1;
    }
    const auto selected = loaded.Select();
    if (!selected || selected->host != "203.0.113.5" || selected->port != 9375) {
      std::cerr << "unexpected selection after reload\n";
      return 1;
    }

    // Test: Select() with exclude_hosts skips already-connected IPs.
    {
      AddrManager excl_mgr;
      excl_mgr.Add("198.51.100.1", 9375, false);
      excl_mgr.Add("198.51.100.2", 9375, false);

      // Excluding the only two hosts should return nullopt.
      std::unordered_set<std::string> exclude_both{"198.51.100.1", "198.51.100.2"};
      if (excl_mgr.Select(exclude_both).has_value()) {
        std::cerr << "expected nullopt when all hosts are excluded\n";
        return 1;
      }

      // Excluding one host should return the other.
      std::unordered_set<std::string> exclude_one{"198.51.100.1"};
      const auto pick = excl_mgr.Select(exclude_one);
      if (!pick || pick->host != "198.51.100.2") {
        std::cerr << "expected non-excluded host to be selected\n";
        return 1;
      }

      // Empty exclude set should work normally.
      if (!excl_mgr.Select().has_value()) {
        std::cerr << "expected a candidate with empty exclusion set\n";
        return 1;
      }
    }

    std::error_code ec;
    std::filesystem::remove(peers_path, ec);

    std::cout << "addr_manager_tests: OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "addr_manager_tests: " << ex.what() << "\n";
    return 1;
  }
}
