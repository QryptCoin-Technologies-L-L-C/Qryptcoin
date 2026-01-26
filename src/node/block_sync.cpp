#include "node/block_sync.hpp"

#include <algorithm>
#include <iostream>
#include <span>

#include "consensus/block_hash.hpp"
#include "consensus/params.hpp"
#include "consensus/pow.hpp"
#include "config/network.hpp"
#include "net/channel.hpp"
#include "primitives/serialize.hpp"
#include "primitives/txid.hpp"
#include "util/hex.hpp"

namespace qryptcoin::node {

namespace {

constexpr std::uint32_t kMaxHeadersPerRequest = 2000;
constexpr std::size_t kMaxTransactionBytes = 1'000'000;
constexpr std::size_t kMaxInFlightBlocksTotal = 16;
constexpr std::size_t kMaxInFlightBlocksPerPeer = 4;
constexpr std::size_t kMaxInFlightTransactionsTotal = 16'384;
constexpr std::size_t kMaxInFlightTransactionsPerPeer = 2048;
constexpr auto kTransactionRequestTimeout = std::chrono::seconds(30);
constexpr auto kBlockRequestTimeout = std::chrono::seconds(30);
constexpr auto kPeerCooldownAfterStall = std::chrono::seconds(10);
constexpr auto kHeadersResponseTimeout = std::chrono::seconds(30);
constexpr std::size_t kMaxStoredHeadersTotal = 8192;
constexpr std::size_t kMaxStoredHeadersPerPeer = 4096;
constexpr std::size_t kMaxBlocksServedPerGetData = 16;
constexpr std::size_t kMaxTransactionsServedPerGetData = 1024;
constexpr std::size_t kMaxOrphanBlocks = 256;
constexpr std::size_t kMaxOrphanBytes = 32 * 1024 * 1024;
constexpr std::size_t kOrphanFifoCompactionThreshold = kMaxOrphanBlocks * 8;

std::string HashToHex(const primitives::Hash256& hash) {
  return util::HexEncode(std::span<const std::uint8_t>(hash.data(), hash.size()));
}

}  // namespace

BlockSyncManager::BlockSyncManager(ChainState& chain, net::PeerManager& peers)
    : chain_(chain), peers_(peers) {}

BlockSyncManager::~BlockSyncManager() { Stop(); }

void BlockSyncManager::Start() {
  if (running_.exchange(true)) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    peer_workers_.clear();
    download_queue_.clear();
    download_queue_hashes_.clear();
    inflight_blocks_.clear();
    inflight_transactions_.clear();
    orphan_blocks_.clear();
    orphans_by_parent_.clear();
    orphan_fifo_.clear();
    orphan_bytes_ = 0;
    header_index_.clear();
    headers_by_peer_.clear();
    if (const auto* tip = chain_.Tip()) {
      best_header_height_ = tip->height;
      best_header_hash_ = tip->hash;
    } else {
      best_header_height_ = 0;
      best_header_hash_.fill(0);
    }
  }
  peers_.SetPeerConnectedHandler(
      [this](const net::PeerManager::PeerInfo& info,
             const std::shared_ptr<net::PeerSession>& session) { OnPeerConnected(info, session); });
  peers_.SetPeerDisconnectedHandler(
      [this](const net::PeerManager::PeerInfo& info) { OnPeerDisconnected(info); });

  // Launch a background watcher that periodically scans for stalled
  // in-flight block requests and reassigns them to healthy peers.
  stall_thread_ = std::jthread([this](std::stop_token stop) { StallWatcher(stop); });
}

void BlockSyncManager::Stop() {
  if (!running_.exchange(false)) {
    return;
  }
  peers_.SetPeerConnectedHandler(nullptr);
  peers_.SetPeerDisconnectedHandler(nullptr);
  if (stall_thread_.joinable()) {
    stall_thread_.request_stop();
  }
  std::vector<PeerWorker> workers;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    workers.reserve(peer_workers_.size());
    for (auto& entry : peer_workers_) {
      entry.second.thread.request_stop();
      workers.push_back(std::move(entry.second));
    }
    peer_workers_.clear();
    download_queue_.clear();
    download_queue_hashes_.clear();
    inflight_blocks_.clear();
    inflight_transactions_.clear();
    orphan_blocks_.clear();
    orphans_by_parent_.clear();
    orphan_fifo_.clear();
    orphan_bytes_ = 0;
    header_index_.clear();
    headers_by_peer_.clear();
  }
  // Close sockets before joining worker threads so their blocking Receive() calls
  // unblock promptly during shutdown.
  for (auto& worker : workers) {
    if (worker.session) {
      worker.session->Close();
    }
  }
  workers.clear();
}

std::size_t BlockSyncManager::BestHeaderHeight() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return best_header_height_;
}

bool BlockSyncManager::IsSynced() const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto chain_height = chain_.Height();
  return chain_height >= best_header_height_;
}

BlockSyncManager::SyncStats BlockSyncManager::GetStats() const {
  SyncStats stats;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stats.best_header_height = best_header_height_;
    stats.pending_blocks =
        download_queue_.size() + inflight_blocks_.size() + orphan_blocks_.size();
  }
  stats.getheaders_sent = getheaders_sent_.load();
  stats.headers_received = headers_received_.load();
  stats.inventories_received = inventories_received_.load();
  stats.blocks_connected = blocks_connected_.load();
  stats.stalls_detected = stalls_detected_.load();
  const auto drops = net::FrameChannel::GetDropStats();
  stats.frame_payload_drops = drops.payload_too_large;
  return stats;
}

std::vector<BlockSyncManager::PeerSyncStats> BlockSyncManager::GetPeerSyncStats() const {
  std::vector<PeerSyncStats> out;
  std::lock_guard<std::mutex> lock(mutex_);
  out.reserve(peer_workers_.size());
  const auto now = std::chrono::steady_clock::now();
  for (const auto& kv : peer_workers_) {
    const auto& worker = kv.second;
    PeerSyncStats stats;
    stats.peer_id = worker.info.id;
    stats.inflight_blocks = worker.inflight_blocks;
    stats.stall_count = worker.stall_count;
    if (worker.last_response.time_since_epoch().count() != 0) {
      const auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(now - worker.last_response);
      stats.last_response_ms =
          static_cast<std::uint64_t>(elapsed.count());
    } else {
      stats.last_response_ms = 0;
    }
    out.push_back(stats);
  }
  return out;
}

void BlockSyncManager::SetRateLimits(std::size_t inv_per_sec,
                                     std::size_t getdata_per_sec,
                                     std::size_t headers_per_sec,
                                     std::size_t block_per_sec,
                                     std::size_t tx_per_sec) {
  inv_limit_per_sec_.store(inv_per_sec);
  getdata_limit_per_sec_.store(getdata_per_sec);
  headers_limit_per_sec_.store(headers_per_sec);
  block_limit_per_sec_.store(block_per_sec);
  tx_limit_per_sec_.store(tx_per_sec);
}

std::size_t BlockSyncManager::AnnounceTransaction(const primitives::Hash256& txid,
                                                  bool force) {
  if (!running_) {
    return 0;
  }
  net::messages::InventoryMessage inv;
  net::messages::InventoryVector vec;
  vec.type = net::messages::InventoryType::kTransaction;
  vec.identifier = ToInventoryId(txid);
  inv.entries.push_back(vec);
  const auto msg = net::messages::EncodeInventory(inv);

  std::vector<std::shared_ptr<net::PeerSession>> sessions;
  const auto now = std::chrono::steady_clock::now();
  const auto limit = inv_limit_per_sec_.load();
  {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions.reserve(peer_workers_.size());
    for (auto& kv : peer_workers_) {
      auto& worker = kv.second;
      if (!worker.session) {
        continue;
      }
      if (!force && worker.known_transactions.find(txid) != worker.known_transactions.end()) {
        continue;
      }
      if (limit > 0) {
        if (worker.tx_inv_window_start.time_since_epoch().count() == 0 ||
            now - worker.tx_inv_window_start >= std::chrono::seconds(1)) {
          worker.tx_inv_window_start = now;
          worker.tx_inv_window_count = 0;
        }
        if (worker.tx_inv_window_count >= limit) {
          continue;
        }
      }
      if (worker.known_transactions.insert(txid).second) {
        worker.known_tx_fifo.push_back(txid);
        if (worker.known_tx_fifo.size() > kKnownTransactionsPerPeer) {
          const auto evicted = worker.known_tx_fifo.front();
          worker.known_tx_fifo.pop_front();
          worker.known_transactions.erase(evicted);
        }
      }
      if (limit > 0) {
        ++worker.tx_inv_window_count;
      }
      sessions.push_back(worker.session);
    }
  }

  std::size_t sent = 0;
  for (const auto& session : sessions) {
    if (session && session->Send(msg)) {
      ++sent;
    }
  }
  return sent;
}

void BlockSyncManager::SetTransactionHandler(TransactionHandler handler) {
  std::lock_guard<std::mutex> lock(mutex_);
  on_transaction_received_ = std::move(handler);
}

void BlockSyncManager::SetTransactionInventoryPolicy(HasTransactionFn has_tx,
                                                     GetTransactionBytesFn get_tx_bytes) {
  std::lock_guard<std::mutex> lock(mutex_);
  has_transaction_ = std::move(has_tx);
  get_transaction_bytes_ = std::move(get_tx_bytes);
}

void BlockSyncManager::SetBlockConnectedHandler(BlockConnectedHandler handler) {
  std::lock_guard<std::mutex> lock(mutex_);
  on_block_connected_ = std::move(handler);
}

void BlockSyncManager::SetAddressObserver(AddressObserver observer) {
  std::lock_guard<std::mutex> lock(mutex_);
  on_address_seen_ = std::move(observer);
}

void BlockSyncManager::OnPeerConnected(const net::PeerManager::PeerInfo& info,
                                       const std::shared_ptr<net::PeerSession>& session) {
  if (!running_) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (on_address_seen_) {
      on_address_seen_(info.address);
    }
  }
  PeerWorker worker;
  worker.info = info;
  worker.session = session;
  worker.last_response = std::chrono::steady_clock::now();
  worker.thread =
      std::jthread([this, info, session](std::stop_token stop) { PeerLoop(stop, info, session); });
  {
    std::lock_guard<std::mutex> lock(mutex_);
    peer_workers_[info.id] = std::move(worker);
  }
  SendGetHeaders(info, session);
  RequestNextBlock(info, session);
}

void BlockSyncManager::OnPeerDisconnected(const net::PeerManager::PeerInfo& info) {
  std::optional<PeerWorker> removed;
  std::vector<primitives::Hash256> to_requeue;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peer_workers_.find(info.id);
    if (it != peer_workers_.end()) {
      removed.emplace(std::move(it->second));
      for (const auto& txid : removed->inflight_transactions) {
        auto it_tx = inflight_transactions_.find(txid);
        if (it_tx != inflight_transactions_.end() && it_tx->second.peer_id == info.id) {
          inflight_transactions_.erase(it_tx);
        }
      }
      peer_workers_.erase(it);
    }
    // Clean up headers contributed by this peer to free capacity for active peers.
    RemoveHeadersForPeerLocked(info.id);
    for (auto it_block = inflight_blocks_.begin(); it_block != inflight_blocks_.end();) {
      if (it_block->second.peer_id == info.id) {
        to_requeue.push_back(it_block->second.hash);
        it_block = inflight_blocks_.erase(it_block);
      } else {
        ++it_block;
      }
    }
  }
  if (removed.has_value()) {
    removed->thread.request_stop();
  }
  if (!to_requeue.empty()) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (const auto& h : to_requeue) {
        if (download_queue_hashes_.insert(h).second) {
          download_queue_.push_front(h);
        }
      }
    }
    RequestFromAnyPeer();
  }
  if (removed.has_value()) {
    removed->thread.request_stop();
    if (removed->thread.get_id() == std::this_thread::get_id()) {
      PeerWorker worker = std::move(*removed);
      removed.reset();
      std::thread([worker = std::move(worker)]() mutable {}).detach();
    }
  }
}

void BlockSyncManager::PeerLoop(std::stop_token stop, net::PeerManager::PeerInfo info,
                                std::shared_ptr<net::PeerSession> session) {
  using clock = std::chrono::steady_clock;
  auto window_start = clock::now();
  std::size_t messages_in_window = 0;
  constexpr std::size_t kMaxMessagesPerWindow = 500;
  constexpr auto kWindowDuration = std::chrono::seconds(1);
  std::size_t inv_count = 0;
  std::size_t getdata_count = 0;
  std::size_t headers_count = 0;
  std::size_t block_count = 0;
  std::size_t tx_count = 0;

  while (!stop.stop_requested()) {
    net::messages::Message message;
    if (!session->Receive(&message)) {
      break;
    }
    auto now = clock::now();
    if (now - window_start >= kWindowDuration) {
      window_start = now;
      messages_in_window = 0;
      inv_count = getdata_count = headers_count = block_count = tx_count = 0;
    }
    ++messages_in_window;
    if (messages_in_window > kMaxMessagesPerWindow) {
      std::cerr << "[sync] peer " << info.id << " exceeded message rate limit\n";
      peers_.AddBanScore(info.id, 10);
      break;
    }
    // Type-specific rate limits with soft banning on sustained excess.
    const auto inv_limit = inv_limit_per_sec_.load();
    const auto getdata_limit = getdata_limit_per_sec_.load();
    const auto headers_limit = headers_limit_per_sec_.load();
    const auto block_limit = block_limit_per_sec_.load();
    const auto tx_limit = tx_limit_per_sec_.load();
    using net::messages::Command;
    switch (message.command) {
      case Command::kInventory:
        if (inv_limit > 0 && ++inv_count > inv_limit) {
          std::cerr << "[sync] peer " << info.id << " exceeded INV rate limit\n";
          peers_.AddBanScore(info.id, 10);
          return;
        }
        break;
      case Command::kGetData:
        if (getdata_limit > 0 && ++getdata_count > getdata_limit) {
          std::cerr << "[sync] peer " << info.id << " exceeded GETDATA rate limit\n";
          peers_.AddBanScore(info.id, 10);
          return;
        }
        break;
      case Command::kHeaders:
        if (headers_limit > 0 && ++headers_count > headers_limit) {
          std::cerr << "[sync] peer " << info.id << " exceeded HEADERS rate limit\n";
          peers_.AddBanScore(info.id, 10);
          return;
        }
        break;
      case Command::kBlock:
        if (block_limit > 0 && ++block_count > block_limit) {
          std::cerr << "[sync] peer " << info.id << " exceeded BLOCK rate limit\n";
          peers_.AddBanScore(info.id, 20);
          return;
        }
        break;
      case Command::kTransaction:
        if (tx_limit > 0 && ++tx_count > tx_limit) {
          std::cerr << "[sync] peer " << info.id << " exceeded TX rate limit\n";
          peers_.AddBanScore(info.id, 10);
          return;
        }
        break;
      default:
        break;
    }
    DispatchMessage(info, session, message);
  }
  std::thread([this, id = info.id]() { peers_.DisconnectPeer(id); }).detach();
}

void BlockSyncManager::DispatchMessage(const net::PeerManager::PeerInfo& info,
                                       const std::shared_ptr<net::PeerSession>& session,
                                       const net::messages::Message& message) {
  using net::messages::Command;
  switch (message.command) {
    case Command::kHeaders: {
      net::messages::HeadersMessage headers;
      if (!net::messages::DecodeHeaders(message, &headers)) {
        std::cerr << "[sync] peer " << info.id << " sent malformed HEADERS payload\n";
        peers_.AddBanScore(info.id, 20);
        return;
      }
      HandleHeaders(info, session, headers);
      break;
    }
    case Command::kGetHeaders: {
      net::messages::GetHeadersMessage request;
      if (!net::messages::DecodeGetHeaders(message, &request)) {
        std::cerr << "[sync] peer " << info.id << " sent malformed GETHEADERS payload\n";
        peers_.AddBanScore(info.id, 10);
        return;
      }
      HandleGetHeaders(info, session, request);
      break;
    }
    case Command::kGetData: {
      net::messages::InventoryMessage inv;
      if (!net::messages::DecodeGetData(message, &inv)) {
        std::cerr << "[sync] peer " << info.id << " sent malformed GETDATA payload\n";
        peers_.AddBanScore(info.id, 10);
        return;
      }
      HandleGetData(info, session, inv);
      break;
    }
    case Command::kInventory: {
      net::messages::InventoryMessage inv;
      if (!net::messages::DecodeInventory(message, &inv)) {
        std::cerr << "[sync] peer " << info.id << " sent malformed INV payload\n";
        peers_.AddBanScore(info.id, 10);
        return;
      }
      HandleInventory(info, session, inv);
      break;
    }
    case Command::kBlock: {
      net::messages::BlockMessage block_msg{message.payload};
      HandleBlock(info, session, block_msg);
      break;
    }
    case Command::kPing: {
      net::messages::PingMessage ping{};
      if (!net::messages::DecodePing(message, &ping)) {
        std::cerr << "[sync] peer " << info.id << " sent malformed PING payload\n";
        peers_.AddBanScore(info.id, 5);
        return;
      }
      session->Send(net::messages::EncodePong(net::messages::PongMessage{ping.nonce}));
      break;
    }
    case Command::kTransaction: {
      HandleTransaction(info, message);
      break;
    }
    case Command::kPong:
    case Command::kVersion:
    case Command::kVerAck:
    case Command::kHandshakeInit:
    case Command::kHandshakeResponse:
    case Command::kEncryptedFrame:
    default:
      break;
  }
}

void BlockSyncManager::HandleHeaders(const net::PeerManager::PeerInfo& info,
                                     const std::shared_ptr<net::PeerSession>& session,
                                     const net::messages::HeadersMessage& headers) {
  headers_received_.fetch_add(headers.headers.size());
  if (headers.headers.empty()) {
    return;
  }
  if (headers.headers.size() > kMaxHeadersPerRequest) {
    std::cerr << "[sync] peer " << info.id << " sent oversized headers batch ("
              << headers.headers.size() << ")\n";
    peers_.AddBanScore(info.id, 20);
    return;
  }
  std::vector<HeaderEntry> accepted;
  accepted.reserve(headers.headers.size());
  const auto& params = consensus::Params(config::GetNetworkConfig().type);
  int ban_score = 0;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto fail = [&](int score, std::string_view msg) {
      if (!msg.empty()) {
        std::cerr << msg << "\n";
      }
      ban_score = score;
    };

    auto it_worker = peer_workers_.find(info.id);
    if (it_worker == peer_workers_.end()) {
      return;
    }

    const auto now = std::chrono::steady_clock::now();
    const bool headers_expected =
        it_worker->second.headers_expected_until.time_since_epoch().count() != 0 &&
        now <= it_worker->second.headers_expected_until;
    // Treat any HEADERS message as satisfying the outstanding getheaders
    // window, even if malformed, so the peer cannot keep flooding within
    // the timeout interval.
    it_worker->second.headers_expected_until = std::chrono::steady_clock::time_point{};

    do {
      if (!headers_expected) {
        fail(5, "[sync] peer " + std::to_string(info.id) +
                     " sent unsolicited HEADERS, ignoring");
        break;
      }

      // If our header state drifts too far (e.g. due to a previous buggy build
      // or a hostile peer before caps were introduced), reset to avoid
      // unbounded traversal and allocations.
      const auto chain_height = chain_.Height();
      if (best_header_height_ > chain_height + kMaxHeadersPerRequest ||
          header_index_.size() > kMaxStoredHeadersTotal) {
        std::cerr << "[sync] resetting header sync state (stored=" << header_index_.size()
                  << ", best=" << best_header_height_ << ", chain=" << chain_height << ")\n";
        header_index_.clear();
        headers_by_peer_.clear();
        download_queue_.clear();
        download_queue_hashes_.clear();
        if (const auto* tip = chain_.Tip()) {
          best_header_height_ = tip->height;
          best_header_hash_ = tip->hash;
        } else {
          best_header_height_ = 0;
          best_header_hash_.fill(0);
        }
      }

      // Only accept contiguous header chains. This reduces complexity and
      // prevents adversaries from smuggling unrelated branches in a single
      // message to amplify storage costs.
      const auto& first = headers.headers.front();
      const auto parent_hex = HashToHex(first.previous_block_hash);
      std::optional<std::size_t> parent_height;
      std::uint32_t parent_bits = 0;
      std::uint64_t parent_time = 0;
      if (const auto* record = chain_.GetByHash(parent_hex)) {
        parent_height = record->height;
        parent_bits = record->header.difficulty_bits;
        parent_time = record->header.timestamp;
      } else if (auto it = header_index_.find(parent_hex); it != header_index_.end()) {
        parent_height = it->second.height;
        parent_bits = it->second.difficulty_bits;
        parent_time = it->second.timestamp;
      }
      if (!parent_height.has_value()) {
        fail(5, "[sync] peer " + std::to_string(info.id) + " sent headers with unknown parent");
        break;
      }

      const auto max_allowed_height = chain_height + kMaxHeadersPerRequest;
      if (*parent_height >= max_allowed_height) {
        fail(10, "[sync] peer " + std::to_string(info.id) +
                     " attempted to extend headers beyond window");
        break;
      }

      primitives::Hash256 expected_prev = first.previous_block_hash;
      std::size_t height = *parent_height + 1;
      for (const auto& header : headers.headers) {
        if (header.previous_block_hash != expected_prev) {
          fail(20, "[sync] peer " + std::to_string(info.id) +
                       " sent non-contiguous headers sequence");
          break;
        }
        if (height > max_allowed_height) {
          fail(10, "[sync] peer " + std::to_string(info.id) + " sent headers beyond max window");
          break;
        }

        const auto hash = consensus::ComputeBlockHash(header);
        const auto target = consensus::CompactToTarget(header.difficulty_bits);
        if (!consensus::HashMeetsTarget(hash, target)) {
          fail(50, "[sync] peer " + std::to_string(info.id) + " sent invalid PoW header");
          break;
        }

        // Validate difficulty bits contextually so we don't waste memory and
        // bandwidth syncing a chain that cannot become valid under the active
        // consensus rules.
        std::uint32_t expected_bits = parent_bits;
        if (height == 0) {
          expected_bits = params.genesis_bits;
        } else if (params.difficulty_adjustment_activation_height != 0 &&
                   height < params.difficulty_adjustment_activation_height) {
          expected_bits = params.pow_limit_bits;
        } else if (params.difficulty_adjustment_interval != 0 &&
                   height % params.difficulty_adjustment_interval == 0 &&
                   height >= params.difficulty_adjustment_interval) {
          const auto first_index = height - params.difficulty_adjustment_interval;
          const auto* first_record = chain_.GetByHeight(first_index);
          if (!first_record) {
            fail(10, "[sync] missing anchor block for difficulty calculation");
            break;
          }
          const auto first_time = static_cast<std::uint32_t>(first_record->header.timestamp);
          const auto last_time = static_cast<std::uint32_t>(parent_time);
          expected_bits = consensus::CalculateNextWorkRequired(
              parent_bits, first_time, last_time, params.target_block_time_seconds,
              params.difficulty_adjustment_interval, params.pow_limit_bits);
        }
        if (header.difficulty_bits != expected_bits) {
          fail(50, "[sync] peer " + std::to_string(info.id) +
                       " sent header with unexpected difficulty bits");
          break;
        }

        HeaderEntry entry;
        entry.hash = hash;
        entry.previous = header.previous_block_hash;
        entry.height = height;
        entry.difficulty_bits = header.difficulty_bits;
        entry.timestamp = header.timestamp;
        entry.source_peer_id = info.id;
        accepted.push_back(entry);

        expected_prev = hash;
        parent_bits = header.difficulty_bits;
        parent_time = header.timestamp;
        ++height;
      }
      if (ban_score != 0) {
        break;
      }

      // Apply storage caps before inserting.
      const auto existing_for_peer =
          headers_by_peer_.count(info.id) ? headers_by_peer_[info.id] : 0;
      std::size_t new_unique = 0;
      for (const auto& entry : accepted) {
        if (header_index_.find(HashToHex(entry.hash)) == header_index_.end()) {
          ++new_unique;
        }
      }
      if (existing_for_peer + new_unique > kMaxStoredHeadersPerPeer ||
          header_index_.size() + new_unique > kMaxStoredHeadersTotal) {
        fail(20, "[sync] peer " + std::to_string(info.id) + " exceeded header storage caps");
        break;
      }

      for (const auto& entry : accepted) {
        const auto hex = HashToHex(entry.hash);
        if (header_index_.find(hex) == header_index_.end()) {
          header_index_[hex] = entry;
          headers_by_peer_[info.id] += 1;
        }
        if (entry.height > best_header_height_) {
          best_header_height_ = entry.height;
          best_header_hash_ = entry.hash;
        }
      }
      RebuildDownloadQueueLocked();
    } while (false);
  }
  if (ban_score != 0) {
    peers_.AddBanScore(info.id, ban_score);
    return;
  }
  RequestNextBlock(info, session);
  if (accepted.size() == kMaxHeadersPerRequest) {
    bool request_more = true;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      const auto chain_height = chain_.Height();
      const auto gap =
          best_header_height_ > chain_height ? (best_header_height_ - chain_height) : 0;
      // Avoid spamming getheaders when we already have a full window of headers
      // queued ahead of the active chain tip. This keeps header sync responsive
      // while letting block downloads catch up.
      request_more = gap < kMaxHeadersPerRequest;
    }
    if (request_more) {
      SendGetHeaders(info, session);
    }
  }
}

void BlockSyncManager::HandleGetHeaders(const net::PeerManager::PeerInfo& info,
                                        const std::shared_ptr<net::PeerSession>& session,
                                        const net::messages::GetHeadersMessage& request) {
  (void)info;
  std::size_t start_height = 0;
  bool found = false;
  for (const auto& hash : request.locators) {
    const auto hex = HashToHex(hash);
    if (const auto* record = chain_.GetByHash(hex)) {
      start_height = record->height + 1;
      found = true;
      break;
    }
  }
  if (!found) {
    start_height = 0;
  }
  const std::size_t limit = std::min<std::uint32_t>(request.max_headers, kMaxHeadersPerRequest);
  net::messages::HeadersMessage response;
  for (std::size_t height = start_height; height < start_height + limit; ++height) {
    const auto* record = chain_.GetByHeight(height);
    if (record == nullptr) break;
    response.headers.push_back(record->header);
  }
  if (!response.headers.empty()) {
    session->Send(net::messages::EncodeHeaders(response));
  }
}

void BlockSyncManager::HandleGetData(const net::PeerManager::PeerInfo& info,
                                     const std::shared_ptr<net::PeerSession>& session,
                                     const net::messages::InventoryMessage& request) {
  std::size_t blocks_served = 0;
  std::size_t tx_served = 0;
  for (const auto& entry : request.entries) {
    if (entry.type == net::messages::InventoryType::kBlock) {
      if (++blocks_served > kMaxBlocksServedPerGetData) {
        break;
      }
      auto hash = FromInventoryId(entry.identifier);
      auto hex = HashToHex(hash);
      const auto* record = chain_.GetByHash(hex);
      if (record == nullptr) {
        continue;
      }
      primitives::CBlock block;
      std::string read_error;
      if (!chain_.ReadBlock(*record, &block, &read_error)) {
        continue;
      }
      std::vector<std::uint8_t> buffer;
      primitives::serialize::SerializeBlock(block, &buffer);
      net::messages::BlockMessage msg;
      msg.data = std::move(buffer);
      session->Send(net::messages::EncodeBlock(msg));
    } else if (entry.type == net::messages::InventoryType::kTransaction) {
      if (++tx_served > kMaxTransactionsServedPerGetData) {
        break;
      }
      const auto txid = FromInventoryId(entry.identifier);
      std::vector<std::uint8_t> raw;
      bool have_bytes = false;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it_worker = peer_workers_.find(info.id);
        if (it_worker != peer_workers_.end()) {
          auto& worker = it_worker->second;
          if (worker.known_transactions.insert(txid).second) {
            worker.known_tx_fifo.push_back(txid);
            if (worker.known_tx_fifo.size() > kKnownTransactionsPerPeer) {
              const auto evicted = worker.known_tx_fifo.front();
              worker.known_tx_fifo.pop_front();
              worker.known_transactions.erase(evicted);
            }
          }
        }
        if (get_transaction_bytes_) {
          have_bytes = get_transaction_bytes_(txid, &raw);
        }
      }
      if (!have_bytes || raw.empty()) {
        continue;
      }
      std::cerr << "[relay] peer " << info.id << " requested tx " << HashToHex(txid) << "\n";
      net::messages::TransactionMessage tx_msg{raw};
      session->Send(net::messages::EncodeTransaction(tx_msg));
    }
  }
}

void BlockSyncManager::HandleInventory(const net::PeerManager::PeerInfo& info,
                                       const std::shared_ptr<net::PeerSession>& session,
                                       const net::messages::InventoryMessage& inventory) {
  inventories_received_.fetch_add(inventory.entries.size());
  bool needs_headers = false;
  net::messages::InventoryMessage tx_request;
  std::vector<primitives::Hash256> requested_txids;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it_worker = peer_workers_.find(info.id);
    if (it_worker == peer_workers_.end()) {
      return;
    }
    auto& worker = it_worker->second;
    const auto now = std::chrono::steady_clock::now();
    for (const auto& entry : inventory.entries) {
      if (entry.type == net::messages::InventoryType::kBlock) {
        auto hash = FromInventoryId(entry.identifier);
        auto hex = HashToHex(hash);
        if (chain_.GetByHash(hex) != nullptr) continue;
        if (header_index_.count(hex) > 0) continue;
        if (download_queue_hashes_.count(hash) > 0) continue;
        if (inflight_blocks_.find(hex) != inflight_blocks_.end()) {
          continue;
        }
        needs_headers = true;
      } else if (entry.type == net::messages::InventoryType::kTransaction && has_transaction_) {
        if (tx_request.entries.size() >= 1024) {
          if (needs_headers) {
            break;
          }
          continue;
        }
        if (inflight_transactions_.size() >= kMaxInFlightTransactionsTotal ||
            worker.inflight_transactions.size() >= kMaxInFlightTransactionsPerPeer) {
          break;
        }
        auto txid = FromInventoryId(entry.identifier);
        if (worker.known_transactions.insert(txid).second) {
          worker.known_tx_fifo.push_back(txid);
          if (worker.known_tx_fifo.size() > kKnownTransactionsPerPeer) {
            const auto evicted = worker.known_tx_fifo.front();
            worker.known_tx_fifo.pop_front();
            worker.known_transactions.erase(evicted);
          }
        }
        auto it_reject = recent_rejects_.find(txid);
        if (it_reject != recent_rejects_.end()) {
          if (now < it_reject->second.until) {
            continue;
          }
          recent_rejects_.erase(it_reject);
        }
        if (has_transaction_(txid)) {
          continue;
        }
        if (inflight_transactions_.find(txid) != inflight_transactions_.end()) {
          continue;
        }
        if (!worker.inflight_transactions.insert(txid).second) {
          continue;
        }
        inflight_transactions_.emplace(txid, InFlightTransaction{info.id, now});
        tx_request.entries.push_back(entry);
        requested_txids.push_back(txid);
      }
      if (needs_headers && tx_request.entries.size() >= 1024) {
        break;
      }
    }
  }
  if (needs_headers) {
    SendGetHeaders(info, session);
  }
  if (!tx_request.entries.empty()) {
    if (!session->Send(net::messages::EncodeGetData(tx_request))) {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it_worker = peer_workers_.find(info.id);
      if (it_worker != peer_workers_.end()) {
        for (const auto& txid : requested_txids) {
          it_worker->second.inflight_transactions.erase(txid);
        }
      }
      for (const auto& txid : requested_txids) {
        auto it_tx = inflight_transactions_.find(txid);
        if (it_tx != inflight_transactions_.end() && it_tx->second.peer_id == info.id) {
          inflight_transactions_.erase(it_tx);
        }
      }
    }
  }
}

void BlockSyncManager::HandleBlock(const net::PeerManager::PeerInfo& info,
                                   const std::shared_ptr<net::PeerSession>& session,
                                   const net::messages::BlockMessage& block_msg) {
  primitives::CBlock block;
  std::size_t offset = 0;
  if (!primitives::serialize::DeserializeBlock(block_msg.data, &offset, &block) ||
      offset != block_msg.data.size()) {
    std::cerr << "[sync] failed to parse block payload from peer " << info.id << "\n";
    return;
  }
  auto hash = consensus::ComputeBlockHash(block.header);
  const auto hex = HashToHex(hash);
  bool expected = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = inflight_blocks_.find(hex);
    if (it != inflight_blocks_.end()) {
      const auto assigned_peer = it->second.peer_id;
      if (assigned_peer != info.id) {
        // This can happen when a block request is reassigned after a timeout,
        // and the original peer delivers it late. Treat it as a valid response
        // (we requested the block), but do not penalize the peer.
        std::cerr << "[sync] peer " << info.id
                  << " delivered block assigned to peer " << assigned_peer << "\n";
      }
      inflight_blocks_.erase(it);
      auto it_worker = peer_workers_.find(assigned_peer);
      if (it_worker != peer_workers_.end() && it_worker->second.inflight_blocks > 0) {
        --it_worker->second.inflight_blocks;
      }
      auto it_delivering = peer_workers_.find(info.id);
      if (it_delivering != peer_workers_.end()) {
        it_delivering->second.last_response = std::chrono::steady_clock::now();
      }
      // If the block was re-queued due to a timeout, remove it now that we
      // have a copy so we don't request it again.
      for (auto itq = download_queue_.begin(); itq != download_queue_.end();) {
        if (*itq == hash) {
          download_queue_hashes_.erase(*itq);
          itq = download_queue_.erase(itq);
        } else {
          ++itq;
        }
      }
      expected = true;
    }
  }
  if (!expected) {
    // Unexpected block; ignore but do not immediately ban.
    return;
  }

  BlockConnectedHandler block_handler;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    block_handler = on_block_connected_;
  }
  primitives::Hash256 tip_before{};
  if (const auto* tip = chain_.Tip()) {
    tip_before = tip->hash;
  } else {
    tip_before.fill(0);
  }
  std::string error;
  if (!chain_.ConnectBlock(block, &error)) {
    if (error == "unknown parent") {
      std::cerr << "[sync] received out-of-order block " << HashToHex(hash)
                << " (missing parent); caching as orphan\n";
      {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto parent = block.header.previous_block_hash;
        StoreOrphanBlockLocked(hash, std::move(block), block_msg.data.size());
        const auto parent_hex = HashToHex(parent);
        if (parent != primitives::Hash256{} && chain_.GetByHash(parent_hex) == nullptr &&
            header_index_.find(parent_hex) != header_index_.end() &&
            orphan_blocks_.find(parent) == orphan_blocks_.end() &&
            inflight_blocks_.find(parent_hex) == inflight_blocks_.end() &&
            download_queue_hashes_.find(parent) == download_queue_hashes_.end()) {
          download_queue_.push_front(parent);
          download_queue_hashes_.insert(parent);
        }
      }
      RequestNextBlock(info, session);
      return;
    }
    std::cerr << "[sync] failed to connect block " << HashToHex(hash) << ": " << error << "\n";
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (download_queue_hashes_.insert(hash).second) {
        download_queue_.push_front(hash);
      }
    }
    RequestFromAnyPeer();
    return;
  }
  std::vector<primitives::CBlock> ready_orphans;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    RemoveHeaderEntryLocked(hash);
    ready_orphans = PopOrphansForParentLocked(hash);
    if (const auto* tip = chain_.Tip()) {
      if (tip->height >= best_header_height_) {
        best_header_height_ = tip->height;
        best_header_hash_ = tip->hash;
      }
    }
  }
  blocks_connected_.fetch_add(1);
  if (block_handler) {
    block_handler(block, static_cast<std::uint32_t>(chain_.Height()));
  }
  if (!ready_orphans.empty()) {
    std::deque<primitives::CBlock> orphan_queue;
    for (auto& orphan : ready_orphans) {
      orphan_queue.push_back(std::move(orphan));
    }
    while (!orphan_queue.empty()) {
      primitives::CBlock orphan = std::move(orphan_queue.front());
      orphan_queue.pop_front();
      const auto orphan_hash = consensus::ComputeBlockHash(orphan.header);
      std::string orphan_error;
      if (!chain_.ConnectBlock(orphan, &orphan_error)) {
        if (orphan_error == "unknown parent") {
          std::lock_guard<std::mutex> lock(mutex_);
          StoreOrphanBlockLocked(orphan_hash, std::move(orphan), 0);
          continue;
        }
        std::cerr << "[sync] failed to connect cached orphan block "
                  << HashToHex(orphan_hash) << ": " << orphan_error << "\n";
        continue;
      }
      std::vector<primitives::CBlock> nested;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        RemoveHeaderEntryLocked(orphan_hash);
        nested = PopOrphansForParentLocked(orphan_hash);
        if (const auto* tip = chain_.Tip()) {
          if (tip->height >= best_header_height_) {
            best_header_height_ = tip->height;
            best_header_hash_ = tip->hash;
          }
        }
      }
      blocks_connected_.fetch_add(1);
      if (block_handler) {
        block_handler(orphan, static_cast<std::uint32_t>(chain_.Height()));
      }
      for (auto& child : nested) {
        orphan_queue.push_back(std::move(child));
      }
    }
  }

  primitives::Hash256 tip_after{};
  if (const auto* tip = chain_.Tip()) {
    tip_after = tip->hash;
  } else {
    tip_after.fill(0);
  }
  if (tip_after != tip_before) {
    bool should_relay = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      const auto chain_height = chain_.Height();
      const auto gap =
          best_header_height_ > chain_height ? (best_header_height_ - chain_height) : 0;
      // Avoid spamming block announcements during deep initial sync. When we're
      // close to the best known header, relay the tip so sparse peer graphs
      // still converge quickly.
      should_relay = gap <= 2;
    }
    if (should_relay) {
      net::messages::InventoryMessage inv;
      net::messages::InventoryVector vec;
      vec.type = net::messages::InventoryType::kBlock;
      vec.identifier = ToInventoryId(tip_after);
      inv.entries.push_back(vec);
      peers_.BroadcastInventory(inv);
    }
  }

  RequestNextBlock(info, session);
}

void BlockSyncManager::HandleTransaction(const net::PeerManager::PeerInfo& info,
                                         const net::messages::Message& message) {
  TransactionHandler handler_copy;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    handler_copy = on_transaction_received_;
  }
  if (!handler_copy) {
    return;
  }
  if (message.payload.size() > kMaxTransactionBytes) {
    std::cerr << "[sync] peer " << info.id << " sent oversized transaction ("
              << message.payload.size() << " bytes)\n";
    peers_.AddBanScore(info.id, 20);
    return;
  }
  primitives::CTransaction tx;
  std::size_t offset = 0;
  if (!primitives::serialize::DeserializeTransaction(message.payload, &offset, &tx) ||
      offset != message.payload.size()) {
    std::cerr << "[sync] peer " << info.id << " sent malformed transaction payload\n";
    peers_.AddBanScore(info.id, 10);
    return;
  }
  const auto txid = primitives::ComputeTxId(tx);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = inflight_transactions_.find(txid);
    if (it != inflight_transactions_.end()) {
      const auto requested_peer = it->second.peer_id;
      inflight_transactions_.erase(it);
      auto it_worker = peer_workers_.find(requested_peer);
      if (it_worker != peer_workers_.end()) {
        it_worker->second.inflight_transactions.erase(txid);
      }
    }
    auto it_worker = peer_workers_.find(info.id);
    if (it_worker != peer_workers_.end()) {
      it_worker->second.inflight_transactions.erase(txid);
      auto& worker = it_worker->second;
      if (worker.known_transactions.insert(txid).second) {
        worker.known_tx_fifo.push_back(txid);
        if (worker.known_tx_fifo.size() > kKnownTransactionsPerPeer) {
          const auto evicted = worker.known_tx_fifo.front();
          worker.known_tx_fifo.pop_front();
          worker.known_transactions.erase(evicted);
        }
      }
    }
  }
  std::string reject_reason;
  const bool accepted = handler_copy(tx, &reject_reason);
  if (!accepted) {
    if (reject_reason.empty()) {
      reject_reason = "rejected";
    }
    std::cerr << "[relay] peer " << info.id << " tx " << HashToHex(txid)
              << " rejected: " << reject_reason << "\n";
    std::lock_guard<std::mutex> lock(mutex_);
    recent_rejects_[txid] = RecentRejectEntry{std::chrono::steady_clock::now() + kRecentRejectsTtl,
                                              reject_reason};
  }
}

void BlockSyncManager::SendGetHeaders(const net::PeerManager::PeerInfo& info,
                                      const std::shared_ptr<net::PeerSession>& session) {
  if (!running_) return;
  // Apply backpressure: don't request more headers if we already have a large
  // gap between best_header_height and the chain tip, or if the header storage
  // is getting full. This prevents "exceeded header storage caps" errors.
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto chain_height = chain_.Height();
    const auto gap =
        best_header_height_ > chain_height ? (best_header_height_ - chain_height) : 0;
    // Don't request more headers if we're already 2000+ blocks ahead
    if (gap >= kMaxHeadersPerRequest) {
      return;
    }
    // Also check if header storage is getting close to limits
    const auto peer_headers = headers_by_peer_.count(info.id) ? headers_by_peer_.at(info.id) : 0;
    if (peer_headers + kMaxHeadersPerRequest > kMaxStoredHeadersPerPeer ||
        header_index_.size() + kMaxHeadersPerRequest > kMaxStoredHeadersTotal) {
      // Storage is getting full, let block downloads catch up first
      return;
    }
  }
  getheaders_sent_.fetch_add(1);
  net::messages::GetHeadersMessage request;
  request.locators = BuildLocator();
  request.stop_hash.fill(0);
  request.max_headers = kMaxHeadersPerRequest;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peer_workers_.find(info.id);
    if (it != peer_workers_.end()) {
      it->second.headers_expected_until =
          std::chrono::steady_clock::now() + kHeadersResponseTimeout;
    }
  }
  if (!session->Send(net::messages::EncodeGetHeaders(request))) {
    std::cerr << "[sync] failed to send getheaders to peer " << info.id << "\n";
  }
}

void BlockSyncManager::RequestNextBlock(const net::PeerManager::PeerInfo& info,
                                        const std::shared_ptr<net::PeerSession>& session) {
  primitives::Hash256 next{};
  bool should_send = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_) {
      return;
    }
    if (!PrepareBlockRequestForPeerLocked(info.id, &next)) {
      return;
    }
    should_send = true;
  }
  if (!should_send) return;
  net::messages::InventoryMessage inv;
  net::messages::InventoryVector vec;
  vec.type = net::messages::InventoryType::kBlock;
  vec.identifier = ToInventoryId(next);
  inv.entries.push_back(vec);
  if (!session->Send(net::messages::EncodeGetData(inv))) {
    std::cerr << "[sync] failed to request block from peer " << info.id << "\n";
    std::lock_guard<std::mutex> lock(mutex_);
    const auto hex = HashToHex(next);
    auto it = inflight_blocks_.find(hex);
    if (it != inflight_blocks_.end()) {
      auto it_worker = peer_workers_.find(info.id);
      if (it_worker != peer_workers_.end() &&
          it_worker->second.inflight_blocks > 0) {
        --it_worker->second.inflight_blocks;
      }
      inflight_blocks_.erase(it);
    }
    if (download_queue_hashes_.insert(next).second) {
      download_queue_.push_front(next);
    }
  }
}

void BlockSyncManager::RequestFromAnyPeer() {
  if (!running_) return;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (peer_workers_.empty() || download_queue_.empty()) {
      return;
    }
  }
  // Build a scored list of outbound peers so that faster, more
  // reliable peers are preferred for new block requests.
  struct Candidate {
    net::PeerManager::PeerInfo info;
    std::shared_ptr<net::PeerSession> session;
    std::uint64_t score{0};
  };
  std::vector<net::PeerManager::PeerInfo> peers_snapshot = peers_.GetPeerInfos();
  std::vector<Candidate> candidates;
  candidates.reserve(peers_snapshot.size());
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    for (const auto& info : peers_snapshot) {
      if (info.inbound) {
        continue;
      }
      auto it = peer_workers_.find(info.id);
      if (it == peer_workers_.end()) {
        continue;
      }
      const auto& worker = it->second;
      Candidate c;
      c.info = info;
      c.session = worker.session;
      std::uint64_t latency_ms = 0;
      if (worker.last_response.time_since_epoch().count() != 0) {
        latency_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now - worker.last_response)
                .count());
      }
      const std::uint64_t stalls = static_cast<std::uint64_t>(worker.stall_count);
      const std::uint64_t inflight =
          static_cast<std::uint64_t>(worker.inflight_blocks);
      // Lower scores are better. Weight stalls and inflight more
      // heavily than latency so that persistently bad peers are
      // quickly deprioritized.
      c.score = latency_ms + stalls * 5000 + inflight * 1000;
      candidates.push_back(std::move(c));
    }
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const Candidate& a, const Candidate& b) { return a.score < b.score; });
  for (const auto& c : candidates) {
    if (!c.session) {
      continue;
    }
    RequestNextBlock(c.info, c.session);
  }
}

std::optional<std::size_t> BlockSyncManager::ParentHeightLocked(
    const primitives::Hash256& hash) const {
  const auto hex = HashToHex(hash);
  if (const auto* record = chain_.GetByHash(hex)) {
    return record->height;
  }
  auto it = header_index_.find(hex);
  if (it != header_index_.end()) {
    return it->second.height;
  }
  return std::nullopt;
}

void BlockSyncManager::RebuildDownloadQueueLocked() {
  if (best_header_height_ == 0) {
    download_queue_.clear();
    download_queue_hashes_.clear();
    return;
  }
  std::deque<primitives::Hash256> new_queue;
  std::unordered_set<std::string> visited;
  primitives::Hash256 cursor = best_header_hash_;
  std::size_t steps = 0;
  while (true) {
    if (++steps > kMaxStoredHeadersTotal) {
      break;
    }
    auto hex = HashToHex(cursor);
    if (hex.empty() || visited.count(hex)) {
      break;
    }
    visited.insert(hex);
    if (chain_.GetByHash(hex) != nullptr) {
      break;
    }
    if (orphan_blocks_.find(cursor) == orphan_blocks_.end() &&
        inflight_blocks_.find(hex) == inflight_blocks_.end()) {
      new_queue.push_front(cursor);
    }
    auto it = header_index_.find(hex);
    if (it == header_index_.end()) {
      break;
    }
    cursor = it->second.previous;
    bool all_zero = std::all_of(cursor.begin(), cursor.end(), [](std::uint8_t b) { return b == 0; });
    if (all_zero) {
      break;
    }
  }
  download_queue_ = std::move(new_queue);
  download_queue_hashes_.clear();
  for (const auto& h : download_queue_) {
    download_queue_hashes_.insert(h);
  }
}

void BlockSyncManager::RemoveHeaderEntryLocked(const primitives::Hash256& hash) {
  const auto hex = HashToHex(hash);
  auto it = header_index_.find(hex);
  if (it == header_index_.end()) {
    return;
  }
  const auto source_peer = it->second.source_peer_id;
  header_index_.erase(it);
  auto it_count = headers_by_peer_.find(source_peer);
  if (it_count != headers_by_peer_.end()) {
    if (it_count->second > 0) {
      it_count->second -= 1;
    }
    if (it_count->second == 0) {
      headers_by_peer_.erase(it_count);
    }
  }
}

void BlockSyncManager::PruneStaleHeadersLocked() {
  // Remove headers that are already in the chain (below or at the tip).
  // This prevents header accumulation when block downloads are slow.
  const auto chain_height = chain_.Height();
  std::vector<std::string> to_remove;
  to_remove.reserve(header_index_.size() / 2);

  for (const auto& kv : header_index_) {
    const auto& entry = kv.second;
    // If the header is at or below the chain tip, it's either already
    // connected or on a stale branch. Either way, we don't need it.
    if (entry.height <= chain_height) {
      to_remove.push_back(kv.first);
      continue;
    }
    // If the header's source peer is no longer connected, clean it up
    // to free capacity for active peers.
    if (peer_workers_.find(entry.source_peer_id) == peer_workers_.end()) {
      to_remove.push_back(kv.first);
      continue;
    }
  }

  for (const auto& hex : to_remove) {
    auto it = header_index_.find(hex);
    if (it == header_index_.end()) {
      continue;
    }
    const auto source_peer = it->second.source_peer_id;
    header_index_.erase(it);
    auto it_count = headers_by_peer_.find(source_peer);
    if (it_count != headers_by_peer_.end()) {
      if (it_count->second > 0) {
        it_count->second -= 1;
      }
      if (it_count->second == 0) {
        headers_by_peer_.erase(it_count);
      }
    }
  }

  if (!to_remove.empty()) {
    std::cerr << "[sync] pruned " << to_remove.size() << " stale headers (chain_height="
              << chain_height << ", remaining=" << header_index_.size() << ")\n";
  }
}

void BlockSyncManager::RemoveHeadersForPeerLocked(std::uint64_t peer_id) {
  // Remove all headers contributed by a disconnected peer.
  std::vector<std::string> to_remove;
  for (const auto& kv : header_index_) {
    if (kv.second.source_peer_id == peer_id) {
      to_remove.push_back(kv.first);
    }
  }
  for (const auto& hex : to_remove) {
    header_index_.erase(hex);
  }
  headers_by_peer_.erase(peer_id);
  if (!to_remove.empty()) {
    std::cerr << "[sync] removed " << to_remove.size() << " headers from disconnected peer "
              << peer_id << "\n";
  }
}

bool BlockSyncManager::PrepareBlockRequestForPeerLocked(std::uint64_t peer_id,
                                                        primitives::Hash256* out_hash) {
  if (!out_hash) return false;
  if (download_queue_.empty()) {
    return false;
  }
  if (inflight_blocks_.size() >= kMaxInFlightBlocksTotal) {
    return false;
  }
  auto it_worker = peer_workers_.find(peer_id);
  if (it_worker == peer_workers_.end()) {
    return false;
  }
  auto& worker = it_worker->second;
  const auto now = std::chrono::steady_clock::now();
  if (worker.next_request_allowed.time_since_epoch().count() != 0 &&
      now < worker.next_request_allowed) {
    return false;
  }
  if (worker.inflight_blocks >= kMaxInFlightBlocksPerPeer) {
    return false;
  }

  auto parent_ready = [&](const primitives::Hash256& candidate) -> bool {
    const auto candidate_hex = HashToHex(candidate);
    const auto it_header = header_index_.find(candidate_hex);
    if (it_header == header_index_.end()) {
      // If we don't know the parent, treat the candidate as not ready so we
      // don't amplify orphan rates with out-of-order requests.
      return false;
    }
    const auto parent = it_header->second.previous;
    const bool parent_all_zero =
        std::all_of(parent.begin(), parent.end(), [](std::uint8_t b) { return b == 0; });
    if (parent_all_zero) {
      return true;
    }
    const auto parent_hex = HashToHex(parent);
    if (parent_hex.empty()) {
      return false;
    }
    // If the parent is already known to the chainstate (either on the active
    // chain or on a side-chain), the candidate can be connected without
    // triggering an orphan.
    if (chain_.GetByHash(parent_hex) != nullptr) {
      return true;
    }
    // If we already have the parent cached as an orphan, wait until it becomes
    // connectable rather than requesting more descendants.
    if (orphan_blocks_.find(parent) != orphan_blocks_.end()) {
      return false;
    }
    // If the parent is still queued (but not yet requested), request it first.
    if (download_queue_hashes_.find(parent) != download_queue_hashes_.end()) {
      return false;
    }
    return false;
  };

  // Pop the next block that is not already in-flight.
  primitives::Hash256 candidate{};
  bool found = false;
  for (std::size_t i = 0; i < download_queue_.size(); ++i) {
    const auto hash = download_queue_[i];
    if (orphan_blocks_.find(hash) != orphan_blocks_.end()) {
      continue;
    }
    const auto hex = HashToHex(hash);
    if (inflight_blocks_.find(hex) != inflight_blocks_.end()) {
      continue;
    }
    if (!parent_ready(hash)) {
      continue;
    }
    candidate = hash;
    download_queue_.erase(download_queue_.begin() + static_cast<std::ptrdiff_t>(i));
    download_queue_hashes_.erase(hash);
    const auto assigned = InFlightBlock{candidate, peer_id,
                                        std::chrono::steady_clock::now()};
    inflight_blocks_.emplace(hex, assigned);
    worker.inflight_blocks += 1;
    found = true;
    break;
  }
  if (!found) {
    return false;
  }
  *out_hash = candidate;
  return true;
}

void BlockSyncManager::StallWatcher(std::stop_token stop) {
  using clock = std::chrono::steady_clock;
  while (!stop.stop_requested()) {
    std::this_thread::sleep_for(std::chrono::seconds(5));
    std::vector<std::pair<std::uint64_t, primitives::Hash256>> stalled;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      // Proactively prune headers that are no longer needed to prevent
      // "exceeded header storage caps" errors during slow block downloads.
      PruneStaleHeadersLocked();
      const auto now = clock::now();
      for (auto it = inflight_blocks_.begin(); it != inflight_blocks_.end();) {
        const auto& entry = it->second;
        if (now - entry.assigned_at > kBlockRequestTimeout) {
          stalled.emplace_back(entry.peer_id, entry.hash);
          auto it_worker = peer_workers_.find(entry.peer_id);
          if (it_worker != peer_workers_.end()) {
            auto& worker = it_worker->second;
            worker.stall_count += 1;
            if (worker.inflight_blocks > 0) {
              --worker.inflight_blocks;
            }
            worker.next_request_allowed = now + kPeerCooldownAfterStall;
          }
          it = inflight_blocks_.erase(it);
        } else {
          ++it;
        }
      }
      for (const auto& item : stalled) {
        if (download_queue_hashes_.insert(item.second).second) {
          download_queue_.push_front(item.second);
        }
      }
      for (auto it = inflight_transactions_.begin(); it != inflight_transactions_.end();) {
        if (now - it->second.requested_at <= kTransactionRequestTimeout) {
          ++it;
          continue;
        }
        const auto peer_id = it->second.peer_id;
        auto it_worker = peer_workers_.find(peer_id);
        if (it_worker != peer_workers_.end()) {
          it_worker->second.inflight_transactions.erase(it->first);
        }
        it = inflight_transactions_.erase(it);
      }
      stalls_detected_.fetch_add(stalled.size());
    }
    // Apply small ban scores and try to reassign work.
    for (const auto& item : stalled) {
      peers_.AddBanScore(item.first, 1);
    }
    if (!stalled.empty()) {
      RequestFromAnyPeer();
    }
  }
}

void BlockSyncManager::StoreOrphanBlockLocked(const primitives::Hash256& hash,
                                              primitives::CBlock block,
                                              std::size_t payload_bytes) {
  if (!running_) {
    return;
  }
  if (chain_.GetByHash(HashToHex(hash)) != nullptr) {
    return;
  }
  OrphanBlockEntry entry;
  entry.block = std::move(block);
  entry.parent = entry.block.header.previous_block_hash;
  entry.payload_bytes = payload_bytes;
  auto it = orphan_blocks_.find(hash);
  if (it != orphan_blocks_.end()) {
    const auto old_parent = it->second.parent;
    if (it->second.payload_bytes <= orphan_bytes_) {
      orphan_bytes_ -= it->second.payload_bytes;
    }
    it->second = std::move(entry);
    orphan_bytes_ += it->second.payload_bytes;
    if (old_parent != it->second.parent) {
      auto it_parent = orphans_by_parent_.find(old_parent);
      if (it_parent != orphans_by_parent_.end()) {
        it_parent->second.erase(hash);
        if (it_parent->second.empty()) {
          orphans_by_parent_.erase(it_parent);
        }
      }
    }
    orphans_by_parent_[it->second.parent].insert(hash);
    EvictOrphansIfNeededLocked();
    return;
  }
  orphan_bytes_ += entry.payload_bytes;
  auto [insert_it, inserted] = orphan_blocks_.emplace(hash, std::move(entry));
  if (inserted) {
    orphans_by_parent_[insert_it->second.parent].insert(hash);
  }
  orphan_fifo_.push_back(hash);
  MaybeCompactOrphanFifoLocked();
  EvictOrphansIfNeededLocked();
}

std::vector<primitives::CBlock> BlockSyncManager::PopOrphansForParentLocked(
    const primitives::Hash256& parent) {
  std::vector<primitives::CBlock> out;
  auto it = orphans_by_parent_.find(parent);
  if (it == orphans_by_parent_.end()) {
    return out;
  }
  std::vector<primitives::Hash256> children;
  children.reserve(it->second.size());
  for (const auto& child : it->second) {
    children.push_back(child);
  }
  orphans_by_parent_.erase(it);
  out.reserve(children.size());
  for (const auto& child : children) {
    auto it_orphan = orphan_blocks_.find(child);
    if (it_orphan == orphan_blocks_.end()) {
      continue;
    }
    if (it_orphan->second.payload_bytes <= orphan_bytes_) {
      orphan_bytes_ -= it_orphan->second.payload_bytes;
    }
    out.push_back(std::move(it_orphan->second.block));
    orphan_blocks_.erase(it_orphan);
  }
  return out;
}

void BlockSyncManager::MaybeCompactOrphanFifoLocked() {
  if (orphan_fifo_.size() <= kOrphanFifoCompactionThreshold) {
    return;
  }
  std::deque<primitives::Hash256> compacted;
  for (const auto& hash : orphan_fifo_) {
    if (orphan_blocks_.find(hash) != orphan_blocks_.end()) {
      compacted.push_back(hash);
    }
  }
  orphan_fifo_ = std::move(compacted);
}

void BlockSyncManager::EvictOrphansIfNeededLocked() {
  while (orphan_blocks_.size() > kMaxOrphanBlocks || orphan_bytes_ > kMaxOrphanBytes) {
    if (orphan_fifo_.empty()) {
      break;
    }
    const auto victim = orphan_fifo_.front();
    orphan_fifo_.pop_front();
    auto it = orphan_blocks_.find(victim);
    if (it == orphan_blocks_.end()) {
      continue;
    }
    if (it->second.payload_bytes <= orphan_bytes_) {
      orphan_bytes_ -= it->second.payload_bytes;
    } else {
      orphan_bytes_ = 0;
    }
    const auto parent = it->second.parent;
    orphan_blocks_.erase(it);
    auto it_parent = orphans_by_parent_.find(parent);
    if (it_parent != orphans_by_parent_.end()) {
      it_parent->second.erase(victim);
      if (it_parent->second.empty()) {
        orphans_by_parent_.erase(it_parent);
      }
    }
  }
}

std::vector<primitives::Hash256> BlockSyncManager::BuildLocator() const {
  std::vector<primitives::Hash256> locator;
  auto height = chain_.Height();
  std::size_t step = 1;
  while (true) {
    if (const auto* record = chain_.GetByHeight(height)) {
      locator.push_back(record->hash);
    } else {
      break;
    }
    if (locator.size() >= 32 || height == 0) {
      break;
    }
    if (locator.size() > 10) {
      step *= 2;
    }
    if (height > step) {
      height -= step;
    } else {
      height = 0;
    }
  }
  const auto* genesis = chain_.GetByHeight(0);
  if (locator.empty()) {
    if (genesis) {
      locator.push_back(genesis->hash);
    }
  } else if (genesis && locator.back() != genesis->hash) {
    locator.push_back(genesis->hash);
  }
  return locator;
}

crypto::Sha3_256Hash BlockSyncManager::ToInventoryId(const primitives::Hash256& hash) {
  crypto::Sha3_256Hash id{};
  std::copy(hash.begin(), hash.end(), id.begin());
  return id;
}

primitives::Hash256 BlockSyncManager::FromInventoryId(const crypto::Sha3_256Hash& id) {
  primitives::Hash256 hash{};
  std::copy(id.begin(), id.end(), hash.begin());
  return hash;
}

}  // namespace qryptcoin::node
