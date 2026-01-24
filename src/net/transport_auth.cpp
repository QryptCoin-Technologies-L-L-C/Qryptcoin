#include "net/transport_auth.hpp"

#include <array>
#include <algorithm>
#include <fstream>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "crypto/pq_engine.hpp"
#include "util/atomic_file.hpp"
#include "util/hex.hpp"

namespace qryptcoin::net {

namespace {

constexpr std::array<std::uint8_t, 8> kIdentityMagic{{'Q', 'R', 'Y', 'I', 'D', 'K', '0', '1'}};
constexpr std::uint32_t kIdentityFormatVersion = 1;

std::filesystem::path IdentityKeyPath(const std::filesystem::path& data_dir) {
  return data_dir / "p2p_identity.dilithium";
}

std::filesystem::path PeerPinsPath(const std::filesystem::path& data_dir) {
  return data_dir / "p2p_peer_pins.txt";
}

std::filesystem::path SeedPinsPath(const std::filesystem::path& data_dir) {
  return data_dir / "p2p_seed_pins.txt";
}

std::filesystem::path EncryptedPeersPath(const std::filesystem::path& data_dir) {
  return data_dir / "p2p_encrypted_peers.txt";
}

void SetError(std::string* out, const std::string& value) {
  if (out) {
    *out = value;
  }
}

bool ReadFileBytes(const std::filesystem::path& path, std::vector<std::uint8_t>* out,
                   std::string* error) {
  if (!out) {
    SetError(error, "invalid output buffer");
    return false;
  }
  out->clear();
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) {
    SetError(error, "failed to open file");
    return false;
  }
  in.seekg(0, std::ios::end);
  const auto size = in.tellg();
  if (size < 0) {
    SetError(error, "failed to stat file");
    return false;
  }
  if (size == 0) {
    SetError(error, "file empty");
    return false;
  }
  if (size > static_cast<std::streamoff>(8 * 1024 * 1024)) {
    SetError(error, "file too large");
    return false;
  }
  out->resize(static_cast<std::size_t>(size));
  in.seekg(0, std::ios::beg);
  if (!in.read(reinterpret_cast<char*>(out->data()), size)) {
    SetError(error, "failed to read file");
    out->clear();
    return false;
  }
  return true;
}

bool WriteU32(std::vector<std::uint8_t>* out, std::uint32_t value) {
  if (!out) return false;
  out->push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
  out->push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
  out->push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
  return true;
}

bool ReadU32(std::span<const std::uint8_t> data, std::size_t* offset, std::uint32_t* out) {
  if (!offset || !out) return false;
  if (*offset + 4 > data.size()) return false;
  const std::size_t i = *offset;
  *out = static_cast<std::uint32_t>(data[i]) |
         (static_cast<std::uint32_t>(data[i + 1]) << 8) |
         (static_cast<std::uint32_t>(data[i + 2]) << 16) |
         (static_cast<std::uint32_t>(data[i + 3]) << 24);
  *offset += 4;
  return true;
}

bool ParseIdentityFile(std::span<const std::uint8_t> bytes,
                       std::vector<std::uint8_t>* secret,
                       std::vector<std::uint8_t>* pub,
                       std::string* error) {
  if (!secret || !pub) {
    SetError(error, "invalid output buffers");
    return false;
  }
  secret->clear();
  pub->clear();
  if (bytes.size() < kIdentityMagic.size() + 4) {
    SetError(error, "identity file truncated");
    return false;
  }
  if (!std::equal(kIdentityMagic.begin(), kIdentityMagic.end(), bytes.begin())) {
    SetError(error, "identity file magic mismatch");
    return false;
  }
  std::size_t offset = kIdentityMagic.size();
  std::uint32_t version = 0;
  if (!ReadU32(bytes, &offset, &version)) {
    SetError(error, "identity file version truncated");
    return false;
  }
  if (version != kIdentityFormatVersion) {
    SetError(error, "identity file version unsupported");
    return false;
  }

  std::uint32_t secret_len = 0;
  std::uint32_t pub_len = 0;
  if (!ReadU32(bytes, &offset, &secret_len) || !ReadU32(bytes, &offset, &pub_len)) {
    SetError(error, "identity file length truncated");
    return false;
  }
  const std::size_t expected_secret = crypto::DilithiumSecretKeySize();
  const std::size_t expected_pub = crypto::DilithiumPublicKeySize();
  if (secret_len != expected_secret || pub_len != expected_pub) {
    SetError(error, "identity file key size mismatch");
    return false;
  }
  if (offset + expected_secret + expected_pub != bytes.size()) {
    SetError(error, "identity file trailing bytes");
    return false;
  }
  secret->assign(bytes.begin() + offset, bytes.begin() + offset + expected_secret);
  offset += expected_secret;
  pub->assign(bytes.begin() + offset, bytes.end());
  return true;
}

bool SerializeIdentityFile(const crypto::QPqDilithiumKey& key, std::vector<std::uint8_t>* out) {
  if (!out) return false;
  out->clear();
  out->insert(out->end(), kIdentityMagic.begin(), kIdentityMagic.end());
  WriteU32(out, kIdentityFormatVersion);
  WriteU32(out, static_cast<std::uint32_t>(key.SecretKey().size()));
  WriteU32(out, static_cast<std::uint32_t>(key.PublicKey().size()));
  out->insert(out->end(), key.SecretKey().begin(), key.SecretKey().end());
  out->insert(out->end(), key.PublicKey().begin(), key.PublicKey().end());
  return true;
}

struct CachedIdentity {
  std::shared_ptr<crypto::QPqDilithiumKey> key;
};

struct CachedPins {
  std::unordered_map<std::string, std::vector<std::uint8_t>> pins;
  bool loaded{false};
};

struct CachedEncryptedPeers {
  std::unordered_set<std::string> peers;
  bool loaded{false};
};

std::mutex g_auth_mutex;
std::unordered_map<std::string, CachedIdentity> g_identities;
std::unordered_map<std::string, CachedPins> g_pins;
std::unordered_map<std::string, CachedPins> g_seed_pins;
std::unordered_map<std::string, CachedEncryptedPeers> g_encrypted_peers;

bool LoadPinsFile(const std::filesystem::path& path,
                  std::unordered_map<std::string, std::vector<std::uint8_t>>* out,
                  std::string* error) {
  if (!out) return false;
  out->clear();
  std::ifstream in(path);
  if (!in.is_open()) {
    // Missing pins file is not an error.
    return true;
  }
  std::string line;
  std::size_t line_no = 0;
  while (std::getline(in, line)) {
    ++line_no;
    auto first = line.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) continue;
    if (line[first] == '#') continue;
    auto sep = line.find_first_of(" \t", first);
    if (sep == std::string::npos) {
      SetError(error, "pins parse error at line " + std::to_string(line_no));
      return false;
    }
    const std::string key = line.substr(first, sep - first);
    auto value_start = line.find_first_not_of(" \t", sep);
    if (value_start == std::string::npos) {
      SetError(error, "pins parse error at line " + std::to_string(line_no));
      return false;
    }
    auto value_end = line.find_last_not_of(" \t\r\n");
    const std::string hex = line.substr(value_start, value_end - value_start + 1);
    std::vector<std::uint8_t> pubkey;
    if (!util::HexDecode(hex, &pubkey) || pubkey.size() != crypto::DilithiumPublicKeySize()) {
      SetError(error, "pins invalid public key at line " + std::to_string(line_no));
      return false;
    }
    (*out)[key] = std::move(pubkey);
  }
  return true;
}

bool SavePinsFile(const std::filesystem::path& path,
                  const std::unordered_map<std::string, std::vector<std::uint8_t>>& pins,
                  std::string* error) {
  std::vector<std::pair<std::string, std::string>> rows;
  rows.reserve(pins.size());
  for (const auto& kv : pins) {
    rows.emplace_back(kv.first, util::HexEncode(kv.second));
  }
  std::sort(rows.begin(), rows.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
  return util::AtomicWriteFile(
      path,
      [&](std::ofstream& out) -> bool {
        out << "# qryptcoin p2p identity pins (TOFU)\n";
        for (const auto& row : rows) {
          out << row.first << " " << row.second << "\n";
        }
        return static_cast<bool>(out);
      },
      error);
}

bool LoadEncryptedPeersFile(const std::filesystem::path& path,
                            std::unordered_set<std::string>* out,
                            std::string* error) {
  if (!out) return false;
  out->clear();
  std::ifstream in(path);
  if (!in.is_open()) {
    return true;
  }
  std::string line;
  std::size_t line_no = 0;
  while (std::getline(in, line)) {
    ++line_no;
    auto first = line.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) continue;
    if (line[first] == '#') continue;
    auto value_end = line.find_last_not_of(" \t\r\n");
    if (value_end == std::string::npos || value_end < first) {
      continue;
    }
    const std::string peer = line.substr(first, value_end - first + 1);
    if (peer.empty() || peer.size() > 256) {
      SetError(error, "encrypted peer pin parse error at line " + std::to_string(line_no));
      return false;
    }
    out->insert(peer);
  }
  return true;
}

bool SaveEncryptedPeersFile(const std::filesystem::path& path,
                            const std::unordered_set<std::string>& peers,
                            std::string* error) {
  std::vector<std::string> rows;
  rows.reserve(peers.size());
  for (const auto& peer : peers) {
    rows.push_back(peer);
  }
  std::sort(rows.begin(), rows.end());
  return util::AtomicWriteFile(
      path,
      [&](std::ofstream& out) -> bool {
        out << "# qryptcoin peers that previously negotiated encrypted transport\n";
        for (const auto& peer : rows) {
          out << peer << "\n";
        }
        return static_cast<bool>(out);
      },
      error);
}

}  // namespace

crypto::Sha3_256Hash ComputeTransportAuthTranscriptHash(
    std::uint32_t protocol_version,
    std::uint64_t initiator_services,
    std::uint64_t responder_services,
    std::uint8_t initiator_preferred_mode,
    std::uint8_t responder_preferred_mode,
    bool initiator_requires_encryption,
    bool responder_requires_encryption,
    std::span<const std::uint8_t> initiator_identity_pubkey,
    std::span<const std::uint8_t> responder_identity_pubkey,
    std::span<const std::uint8_t> initiator_kyber_pubkey,
    std::span<const std::uint8_t> responder_kyber_ciphertext) {
  std::vector<std::uint8_t> preimage;
  preimage.reserve(128 + initiator_identity_pubkey.size() + responder_identity_pubkey.size() +
                   initiator_kyber_pubkey.size() + responder_kyber_ciphertext.size());

  constexpr std::string_view kDomain = "QRY-P2P-TRANSCRIPT-V1";
  preimage.insert(preimage.end(), kDomain.begin(), kDomain.end());

  auto append_u32 = [&](std::uint32_t value) {
    preimage.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    preimage.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    preimage.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
    preimage.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
  };
  auto append_u64 = [&](std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
      preimage.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFu));
    }
  };
  auto append_bytes = [&](std::span<const std::uint8_t> bytes) {
    append_u32(static_cast<std::uint32_t>(bytes.size()));
    preimage.insert(preimage.end(), bytes.begin(), bytes.end());
  };

  append_u32(protocol_version);
  append_u64(initiator_services);
  append_u64(responder_services);
  preimage.push_back(initiator_preferred_mode);
  preimage.push_back(responder_preferred_mode);
  preimage.push_back(static_cast<std::uint8_t>(initiator_requires_encryption ? 1 : 0));
  preimage.push_back(static_cast<std::uint8_t>(responder_requires_encryption ? 1 : 0));
  append_bytes(initiator_identity_pubkey);
  append_bytes(responder_identity_pubkey);
  append_bytes(initiator_kyber_pubkey);
  append_bytes(responder_kyber_ciphertext);
  return crypto::Sha3_256(preimage);
}

bool LoadOrCreateTransportIdentity(const std::filesystem::path& data_dir,
                                   std::shared_ptr<crypto::QPqDilithiumKey>* out,
                                   std::string* error) {
  if (!out) {
    SetError(error, "invalid output key");
    return false;
  }

  if (data_dir.empty()) {
    try {
      auto key = std::make_shared<crypto::QPqDilithiumKey>(crypto::QPqDilithiumKey::Generate());
      *out = std::move(key);
      return true;
    } catch (const std::exception& ex) {
      SetError(error, ex.what());
      return false;
    }
  }

  const std::string cache_key = data_dir.string();
  {
    std::lock_guard<std::mutex> lock(g_auth_mutex);
    auto it = g_identities.find(cache_key);
    if (it != g_identities.end() && it->second.key) {
      *out = it->second.key;
      return true;
    }
  }

  const auto path = IdentityKeyPath(data_dir);
  std::vector<std::uint8_t> file_bytes;
  std::vector<std::uint8_t> secret;
  std::vector<std::uint8_t> pub;
  std::shared_ptr<crypto::QPqDilithiumKey> key;

  if (std::ifstream(path, std::ios::binary).good()) {
    std::string read_error;
    if (!ReadFileBytes(path, &file_bytes, &read_error)) {
      SetError(error, "identity load failed: " + read_error);
      return false;
    }
    std::string parse_error;
    if (!ParseIdentityFile(file_bytes, &secret, &pub, &parse_error)) {
      SetError(error, "identity parse failed: " + parse_error);
      return false;
    }
    try {
      key = std::make_shared<crypto::QPqDilithiumKey>(crypto::QPqDilithiumKey::Import(secret, pub));
    } catch (const std::exception& ex) {
      SetError(error, "identity import failed: " + std::string(ex.what()));
      return false;
    }
  } else {
    try {
      key = std::make_shared<crypto::QPqDilithiumKey>(crypto::QPqDilithiumKey::Generate());
    } catch (const std::exception& ex) {
      SetError(error, "identity generate failed: " + std::string(ex.what()));
      return false;
    }
    std::vector<std::uint8_t> serialized;
    SerializeIdentityFile(*key, &serialized);
    std::string write_error;
    if (!util::AtomicWriteFileBytes(path, serialized, &write_error)) {
      SetError(error, "identity write failed: " + write_error);
      return false;
    }
  }

  {
    std::lock_guard<std::mutex> lock(g_auth_mutex);
    g_identities[cache_key] = CachedIdentity{key};
  }
  *out = std::move(key);
  return true;
}

bool EnforcePeerIdentityPin(const std::filesystem::path& data_dir,
                            const std::string& peer_key_id,
                            std::span<const std::uint8_t> peer_public_key,
                            bool allow_tofu,
                            bool* pinned_new,
                            std::string* error) {
  if (pinned_new) {
    *pinned_new = false;
  }
  if (peer_key_id.empty()) {
    SetError(error, "empty peer key id");
    return false;
  }
  if (peer_public_key.size() != crypto::DilithiumPublicKeySize()) {
    SetError(error, "peer public key size mismatch");
    return false;
  }
  if (data_dir.empty()) {
    // No persistence available; accept but do not pin.
    return true;
  }

  const std::string cache_key = data_dir.string();
  std::lock_guard<std::mutex> lock(g_auth_mutex);
  auto& cache = g_pins[cache_key];
  if (!cache.loaded) {
    std::string load_error;
    if (!LoadPinsFile(PeerPinsPath(data_dir), &cache.pins, &load_error)) {
      SetError(error, load_error);
      return false;
    }
    cache.loaded = true;
  }

  const auto it = cache.pins.find(peer_key_id);
  if (it == cache.pins.end()) {
    if (!allow_tofu) {
      SetError(error, "peer key not pinned");
      return false;
    }
    cache.pins[peer_key_id] = std::vector<std::uint8_t>(peer_public_key.begin(),
                                                        peer_public_key.end());
    std::string write_error;
    if (!SavePinsFile(PeerPinsPath(data_dir), cache.pins, &write_error)) {
      cache.pins.erase(peer_key_id);
      SetError(error, "pins write failed: " + write_error);
      return false;
    }
    if (pinned_new) {
      *pinned_new = true;
    }
    return true;
  }

  const auto& expected = it->second;
  if (expected.size() != peer_public_key.size() ||
      !std::equal(expected.begin(), expected.end(), peer_public_key.begin())) {
    SetError(error, "peer identity key mismatch");
    return false;
  }
  return true;
}

bool EnforceSeedIdentityPin(const std::filesystem::path& data_dir,
                            const std::string& peer_key_id,
                            const std::string& peer_host,
                            std::span<const std::uint8_t> peer_public_key,
                            bool* had_pin,
                            std::string* error) {
  if (had_pin) {
    *had_pin = false;
  }
  if (data_dir.empty()) {
    return true;
  }
  if (peer_public_key.size() != crypto::DilithiumPublicKeySize()) {
    SetError(error, "peer public key size mismatch");
    return false;
  }

  const std::string cache_key = data_dir.string();
  std::lock_guard<std::mutex> lock(g_auth_mutex);
  auto& cache = g_seed_pins[cache_key];
  if (!cache.loaded) {
    std::string load_error;
    if (!LoadPinsFile(SeedPinsPath(data_dir), &cache.pins, &load_error)) {
      SetError(error, "seed pins load failed: " + load_error);
      return false;
    }
    cache.loaded = true;
  }

  auto it = cache.pins.end();
  if (!peer_key_id.empty()) {
    it = cache.pins.find(peer_key_id);
  }
  if (it == cache.pins.end() && !peer_host.empty()) {
    it = cache.pins.find(peer_host);
  }
  if (it == cache.pins.end()) {
    return true;
  }
  if (had_pin) {
    *had_pin = true;
  }

  const auto& expected = it->second;
  if (expected.size() != peer_public_key.size() ||
      !std::equal(expected.begin(), expected.end(), peer_public_key.begin())) {
    SetError(error, "seed identity key mismatch");
    return false;
  }
  return true;
}

bool EnforcePeerEncryptionHistory(const std::filesystem::path& data_dir,
                                  const std::string& peer_key_id,
                                  bool negotiated_encryption,
                                  std::string* error) {
  if (peer_key_id.empty()) {
    SetError(error, "empty peer key id");
    return false;
  }
  if (data_dir.empty()) {
    return true;
  }

  const std::string cache_key = data_dir.string();
  std::lock_guard<std::mutex> lock(g_auth_mutex);
  auto& cache = g_encrypted_peers[cache_key];
  if (!cache.loaded) {
    std::string load_error;
    if (!LoadEncryptedPeersFile(EncryptedPeersPath(data_dir), &cache.peers, &load_error)) {
      SetError(error, load_error);
      return false;
    }
    cache.loaded = true;
  }

  if (!negotiated_encryption) {
    if (cache.peers.find(peer_key_id) != cache.peers.end()) {
      SetError(error, "peer previously negotiated encrypted transport");
      return false;
    }
    return true;
  }

  if (cache.peers.insert(peer_key_id).second) {
    std::string write_error;
    if (!SaveEncryptedPeersFile(EncryptedPeersPath(data_dir), cache.peers, &write_error)) {
      cache.peers.erase(peer_key_id);
      SetError(error, "encrypted peer pin write failed: " + write_error);
      return false;
    }
  }
  return true;
}

}  // namespace qryptcoin::net
