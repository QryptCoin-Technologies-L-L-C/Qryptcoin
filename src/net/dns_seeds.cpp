#include "net/dns_seeds.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <string_view>
#include <unordered_set>

#include "net/socket.hpp"

namespace qryptcoin::net {

namespace {

constexpr std::chrono::minutes kBaseRefreshInterval{15};
constexpr std::chrono::minutes kMaxRefreshInterval{120};

bool ParseIpv4(const std::string& host, int* a, int* b, int* c, int* d) {
  std::string_view view(host);
  int parts[4] = {0, 0, 0, 0};
  std::size_t offset = 0;

  for (int i = 0; i < 4; ++i) {
    if (offset >= view.size()) {
      return false;
    }
    const std::size_t dot = view.find('.', offset);
    const bool is_last = (i == 3);
    if (!is_last && dot == std::string_view::npos) {
      return false;
    }
    if (is_last && dot != std::string_view::npos) {
      return false;
    }

    const std::size_t end = is_last ? view.size() : dot;
    const std::string_view token = view.substr(offset, end - offset);
    if (token.empty()) {
      return false;
    }

    unsigned value = 0;
    const auto* first = token.data();
    const auto* last = token.data() + token.size();
    const auto res = std::from_chars(first, last, value);
    if (res.ec != std::errc{} || res.ptr != last || value > 255) {
      return false;
    }
    parts[i] = static_cast<int>(value);
    offset = is_last ? view.size() : dot + 1;
  }

  if (a) *a = parts[0];
  if (b) *b = parts[1];
  if (c) *c = parts[2];
  if (d) *d = parts[3];
  return true;
}

bool IsPrivateOrReservedIpv4(const std::string& host) {
  int a = 0, b = 0, c = 0, d = 0;
  if (!ParseIpv4(host, &a, &b, &c, &d)) {
    return false;
  }
  // RFC1918 private ranges plus obvious reserved space commonly used
  // in home networks. This intentionally does not try to be perfect;
  // the goal is to avoid bootstrapping from obviously non-public
  // addresses when DNS seeds are misconfigured or malicious.
  if (a == 10) return true;                // 10.0.0.0/8
  if (a == 127) return true;               // 127.0.0.0/8 loopback
  if (a == 192 && b == 168) return true;   // 192.168.0.0/16
  if (a == 169 && b == 254) return true;   // 169.254.0.0/16 link-local
  if (a == 172 && (b >= 16 && b <= 31)) {  // 172.16.0.0/12
    return true;
  }
  if (a == 0 || a == 255) {
    return true;
  }
  return false;
}

std::uint64_t ToUnixSeconds(const std::chrono::system_clock::time_point& tp) {
  if (tp.time_since_epoch().count() == 0) {
    return 0;
  }
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch())
          .count());
}

}  // namespace

DnsSeedManager::DnsSeedManager(bool allow_private_peers)
    : allow_private_peers_(allow_private_peers) {}

void DnsSeedManager::Initialize(const std::vector<std::string>& hosts) {
  std::lock_guard<std::mutex> lock(mutex_);
  entries_.clear();
  entries_.reserve(hosts.size());
  const auto now = std::chrono::steady_clock::now();
  for (const auto& host : hosts) {
    if (host.empty()) continue;
    Entry e;
    e.host = host;
    e.next_resolve = now;  // due immediately
    entries_.push_back(std::move(e));
  }
}

void DnsSeedManager::Tick() {
  using clock = std::chrono::steady_clock;
  const auto now = clock::now();
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& entry : entries_) {
    if (entry.host.empty()) continue;
    if (entry.next_resolve.time_since_epoch().count() != 0 &&
        now < entry.next_resolve) {
      continue;
    }
    ++entry.resolve_attempts;
    auto addresses = ResolveHostAddresses(entry.host);
    std::vector<std::string> filtered;
    filtered.reserve(addresses.size());
    std::unordered_set<std::string> unique;
    for (const auto& ip : addresses) {
      if (!allow_private_peers_ && IsPrivateOrReservedIpv4(ip)) {
        continue;
      }
      if (unique.insert(ip).second) {
        filtered.push_back(ip);
      }
    }
    if (filtered.empty()) {
      ++entry.resolve_failures;
    } else {
      entry.cached_addresses = std::move(filtered);
      entry.last_resolve = std::chrono::system_clock::now();
    }
    // Simple backoff: start at 15 minutes and double up to a ceiling
    // when lookups repeatedly fail.
    auto interval = kBaseRefreshInterval;
    if (entry.resolve_failures > 3 && entry.cached_addresses.empty()) {
      const auto factor =
          std::min<std::uint64_t>(entry.resolve_failures, 4);  // up to x16
      for (std::uint64_t i = 1; i < factor; ++i) {
        if (interval < kMaxRefreshInterval / 2) {
          interval *= 2;
        } else {
          interval = kMaxRefreshInterval;
          break;
        }
      }
    }
    entry.next_resolve = now + interval;
  }
}

void DnsSeedManager::ForceRefresh() {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto now = std::chrono::steady_clock::now();
  for (auto& entry : entries_) {
    entry.next_resolve = now;
  }
}

std::vector<std::string> DnsSeedManager::SnapshotAllAddresses() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::unordered_set<std::string> unique;
  for (const auto& entry : entries_) {
    for (const auto& ip : entry.cached_addresses) {
      unique.insert(ip);
    }
  }
  std::vector<std::string> out;
  out.reserve(unique.size());
  for (const auto& ip : unique) {
    out.push_back(ip);
  }
  std::sort(out.begin(), out.end());
  return out;
}

std::vector<DnsSeedManager::SeedSnapshot> DnsSeedManager::SnapshotSeeds() const {
  std::vector<SeedSnapshot> out;
  std::lock_guard<std::mutex> lock(mutex_);
  out.reserve(entries_.size());
  for (const auto& entry : entries_) {
    SeedSnapshot snap;
    snap.host = entry.host;
    snap.resolve_attempts = entry.resolve_attempts;
    snap.resolve_failures = entry.resolve_failures;
    snap.last_resolve_time = ToUnixSeconds(entry.last_resolve);
    snap.last_addresses = entry.cached_addresses;
    out.push_back(std::move(snap));
  }
  return out;
}

std::size_t DnsSeedManager::CachedPeerCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::size_t count = 0;
  for (const auto& entry : entries_) {
    count += entry.cached_addresses.size();
  }
  return count;
}

}  // namespace qryptcoin::net
