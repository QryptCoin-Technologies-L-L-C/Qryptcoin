#include "net/addr_manager.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <random>

#include "nlohmann/json.hpp"

namespace qryptcoin::net {

namespace {

constexpr std::uint64_t kMinRetryIntervalSeconds = 30;
constexpr std::size_t kMaxStoredAddresses = 2048;
constexpr std::uint32_t kMaxConsecutiveFailures = 16;
// Soft per-subnet cap to encourage diversity in the address table and
// avoid a single /24 dominating outbound candidates.
constexpr std::size_t kMaxAddressesPerGroup = 64;

std::string SubnetKey(const std::string& host) {
  // Very simple IPv4 parsing: a.b.c.d -> a.b.c.0/24. Non-IPv4 hosts
  // reuse the host string as the group key.
  std::istringstream iss(host);
  std::string part;
  std::vector<int> octets;
  while (std::getline(iss, part, '.')) {
    try {
      int value = std::stoi(part);
      if (value < 0 || value > 255) {
        octets.clear();
        break;
      }
      octets.push_back(value);
    } catch (...) {
      octets.clear();
      break;
    }
  }
  if (octets.size() == 4) {
    std::ostringstream key;
    key << octets[0] << "." << octets[1] << "." << octets[2] << ".0/24";
    return key.str();
  }
  return host;
}

}  // namespace

std::uint64_t AddrManager::NowSeconds() {
  using clock = std::chrono::system_clock;
  const auto now = clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

std::string AddrManager::Key(const std::string& host, std::uint16_t port) {
  return host + ":" + std::to_string(port);
}

void AddrManager::Add(const std::string& host, std::uint16_t port, bool permanent) {
  if (host.empty() || port == 0) {
    return;
  }
  const std::string key = Key(host, port);
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = index_.find(key);
  if (it != index_.end()) {
    auto& entry = entries_[it->second];
    entry.permanent = entry.permanent || permanent;
    return;
  }

  // Compute a simple per-group histogram to bias eviction toward
  // overrepresented subnets and keep the table diverse.
  const std::string group = SubnetKey(host);
  if (entries_.size() >= kMaxStoredAddresses) {
    std::unordered_map<std::string, std::size_t> group_counts;
    group_counts.reserve(entries_.size());
    for (const auto& e : entries_) {
      ++group_counts[SubnetKey(e.host)];
    }

    auto is_candidate = [&](const Entry& e) {
      if (e.permanent) return false;
      const auto g = SubnetKey(e.host);
      // Prefer evicting from the same group when it is already dense,
      // otherwise any non-permanent entry is eligible.
      if (g == group && group_counts[g] > kMaxAddressesPerGroup) {
        return true;
      }
      return group_counts[g] > 1 && e.last_success == 0;
    };

    auto victim = std::find_if(entries_.begin(), entries_.end(), is_candidate);
    if (victim == entries_.end()) {
      // Fall back to dropping the oldest non-permanent entry.
      victim = std::find_if(entries_.begin(), entries_.end(),
                            [](const Entry& e) { return !e.permanent; });
    }
    if (victim != entries_.end()) {
      const std::size_t idx = static_cast<std::size_t>(victim - entries_.begin());
      index_.erase(Key(victim->host, victim->port));
      *victim = entries_.back();
      index_[Key(victim->host, victim->port)] = idx;
      entries_.pop_back();
    } else {
      // All entries are permanent; do not add more.
      return;
    }
  }
  Entry entry;
  entry.host = host;
  entry.port = port;
  entry.permanent = permanent;
  const std::size_t index = entries_.size();
  entries_.push_back(entry);
  index_[key] = index;
}

void AddrManager::MarkResult(const std::string& host, std::uint16_t port, bool success) {
  const std::string key = Key(host, port);
  const auto now = NowSeconds();
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = index_.find(key);
  if (it == index_.end()) {
    return;
  }
  Entry& entry = entries_[it->second];
  entry.last_attempt = now;
  if (success) {
    entry.last_success = now;
    entry.attempts = 0;
  } else {
    ++entry.attempts;
  }
}

std::optional<AddrManager::Entry> AddrManager::Select(
    const std::unordered_set<std::string>& exclude_hosts) const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (entries_.empty()) {
    return std::nullopt;
  }
  std::vector<std::size_t> order(entries_.size());
  for (std::size_t i = 0; i < entries_.size(); ++i) {
    order[i] = i;
  }
  std::shuffle(order.begin(), order.end(), std::mt19937{std::random_device{}()});
  const auto now = NowSeconds();
  for (std::size_t idx : order) {
    const Entry& entry = entries_[idx];
    // Skip hosts that already have an active outbound connection.
    // This prevents the same IP from consuming multiple outbound slots.
    if (!exclude_hosts.empty() && exclude_hosts.count(entry.host)) {
      continue;
    }
    if (entry.attempts > kMaxConsecutiveFailures) {
      // Demote persistently failing entries while still keeping them
      // in the table so operators can inspect them via telemetry.
      continue;
    }
    // Throttle repeated attempts against the same address.
    if (entry.last_attempt != 0 && now > entry.last_attempt &&
        now - entry.last_attempt < kMinRetryIntervalSeconds && entry.attempts > 0) {
      continue;
    }
    return entry;
  }
  return std::nullopt;
}

bool AddrManager::Save(const std::filesystem::path& path, std::string* error) const {
  nlohmann::json json = nlohmann::json::array();
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : entries_) {
      nlohmann::json obj;
      obj["host"] = entry.host;
      obj["port"] = entry.port;
      obj["last_success"] = entry.last_success;
      obj["last_attempt"] = entry.last_attempt;
      obj["attempts"] = entry.attempts;
      obj["permanent"] = entry.permanent;
      json.push_back(std::move(obj));
    }
  }
  std::error_code ec;
  const auto parent = path.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, ec);
  }
  std::ofstream out(path);
  if (!out) {
    if (error) {
      *error = "failed to open peers file for write: " + path.string();
    }
    return false;
  }
  out << json.dump(2);
  return true;
}

bool AddrManager::Load(const std::filesystem::path& path, std::string* error) {
  if (!std::filesystem::exists(path)) {
    return true;
  }
  std::ifstream in(path);
  if (!in) {
    if (error) {
      *error = "failed to open peers file for read: " + path.string();
    }
    return false;
  }
  nlohmann::json json;
  try {
    in >> json;
  } catch (const std::exception& ex) {
    if (error) {
      *error = "failed to parse peers file: " + std::string(ex.what());
    }
    return false;
  }
  if (!json.is_array()) {
    if (error) {
      *error = "peers file must contain a JSON array";
    }
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  entries_.clear();
  index_.clear();
  for (const auto& item : json) {
    if (!item.is_object()) {
      continue;
    }
    Entry entry;
    try {
      entry.host = item.at("host").get<std::string>();
      entry.port = item.at("port").get<std::uint16_t>();
      entry.last_success = item.value("last_success", 0ULL);
      entry.last_attempt = item.value("last_attempt", 0ULL);
      entry.attempts = item.value("attempts", 0U);
      entry.permanent = item.value("permanent", false);
    } catch (const std::exception&) {
      continue;
    }
    if (entry.host.empty() || entry.port == 0) {
      continue;
    }
    const std::string key = Key(entry.host, entry.port);
    if (index_.find(key) != index_.end()) {
      continue;
    }
    if (entries_.size() >= kMaxStoredAddresses) {
      break;
    }
    const std::size_t idx = entries_.size();
    entries_.push_back(entry);
    index_[key] = idx;
  }
  return true;
}

std::size_t AddrManager::EntryCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return entries_.size();
}

AddrManager::SeedStats AddrManager::GetSeedStats() const {
  std::lock_guard<std::mutex> lock(mutex_);
  SeedStats stats;
  stats.dns_lookups = dns_lookups_;
  stats.dns_addresses = dns_addresses_;
  stats.dns_failures = dns_failures_;
  stats.static_seeds = static_seeds_;
  return stats;
}

void AddrManager::RecordDnsLookup(std::size_t addresses, std::size_t failures) {
  std::lock_guard<std::mutex> lock(mutex_);
  ++dns_lookups_;
  dns_addresses_ += static_cast<std::uint64_t>(addresses);
  dns_failures_ += static_cast<std::uint64_t>(failures);
}

void AddrManager::RecordStaticSeeds(std::size_t count) {
  std::lock_guard<std::mutex> lock(mutex_);
  static_seeds_ += static_cast<std::uint64_t>(count);
}

}  // namespace qryptcoin::net
