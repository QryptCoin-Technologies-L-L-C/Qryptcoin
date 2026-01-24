#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "config/network.hpp"
#include "consensus/params.hpp"
#include "crypto/pq_engine.hpp"
#include "net/channel.hpp"
#include "net/messages.hpp"
#include "net/peer_session.hpp"
#include "net/transport_auth.hpp"

namespace {

using namespace qryptcoin;

bool BindEphemeral(net::FrameChannel* listener, const std::string& addr, std::uint16_t* out_port) {
  if (!listener || !out_port) return false;
  std::mt19937 rng(static_cast<std::uint32_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  for (int attempt = 0; attempt < 200; ++attempt) {
    const std::uint16_t port = static_cast<std::uint16_t>(20000u + (rng() % 30000u));
    if (listener->BindAndListen(addr, port)) {
      *out_port = port;
      return true;
    }
  }
  return false;
}

std::filesystem::path MakeTempDir(const std::string& suffix) {
  std::mt19937 rng(static_cast<std::uint32_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  auto root = std::filesystem::temp_directory_path() /
              (suffix + "-" + std::to_string(rng()));
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(root);
  return root;
}

bool TestIdentityMismatchAfterTofuPin() {
  config::SelectNetwork(config::NetworkType::kRegtest);

  config::NetworkConfig base = config::GetNetworkConfig();
  base.listen_address = "127.0.0.1";
  base.encryption_mode = config::EncryptionMode::kEncrypted;
  base.encryption_required = true;
  base.authenticated_transport_required = true;
  base.authenticated_transport_tofu = true;

  const auto client_dir = MakeTempDir("qryptcoin-auth-client");
  const auto server_dir_a = MakeTempDir("qryptcoin-auth-server-a");
  const auto server_dir_b = MakeTempDir("qryptcoin-auth-server-b");

  net::FrameChannel listener;
  std::uint16_t port = 0;
  if (!BindEphemeral(&listener, base.listen_address, &port)) {
    std::cerr << "authenticated_transport_tests: failed to bind listener\n";
    return false;
  }

  std::atomic<bool> server_round1_ok{false};
  std::atomic<bool> server_round2_ok{false};
  std::thread server_thread([&] {
    for (int round = 0; round < 2; ++round) {
      net::FrameChannel inbound = listener.Accept();
      inbound.socket().SetTimeout(5000);
      net::PeerSession session(std::move(inbound), /*initiator=*/false);
      config::NetworkConfig server_cfg = base;
      server_cfg.data_dir = (round == 0 ? server_dir_a : server_dir_b).string();
      if (!session.PerformHandshake(server_cfg)) {
        session.Close();
        continue;
      }
      if (round == 0) {
        server_round1_ok.store(true);
      } else {
        server_round2_ok.store(true);
      }
      session.Close();
    }
  });

  config::NetworkConfig client_cfg = base;
  client_cfg.data_dir = client_dir.string();

  // First connection pins the identity via TOFU and should succeed.
  net::PeerSession client1;
  if (!client1.Connect(base.listen_address, port) || !client1.PerformHandshake(client_cfg)) {
    std::cerr << "authenticated_transport_tests: initial authenticated handshake failed\n";
    client1.Close();
    server_thread.join();
    return false;
  }
  client1.Close();

  // Second connection should fail because the server presents a different identity key.
  net::PeerSession client2;
  if (!client2.Connect(base.listen_address, port)) {
    std::cerr << "authenticated_transport_tests: second connect failed\n";
    server_thread.join();
    return false;
  }
  const bool ok2 = client2.PerformHandshake(client_cfg);
  const std::string err2 = client2.last_error();
  client2.Close();

  server_thread.join();
  std::filesystem::remove_all(client_dir);
  std::filesystem::remove_all(server_dir_a);
  std::filesystem::remove_all(server_dir_b);

  if (!server_round1_ok.load() || !server_round2_ok.load()) {
    std::cerr << "authenticated_transport_tests: server did not complete both handshakes\n";
    return false;
  }
  if (ok2) {
    std::cerr << "authenticated_transport_tests: expected identity mismatch to fail\n";
    return false;
  }
  if (err2 != "peer identity key mismatch") {
    std::cerr << "authenticated_transport_tests: expected deterministic mismatch error, got: "
              << err2 << "\n";
    return false;
  }
  return true;
}

bool TestIdentityMismatchAllowedWhenPinningDisabled() {
  config::SelectNetwork(config::NetworkType::kRegtest);

  config::NetworkConfig base = config::GetNetworkConfig();
  base.listen_address = "127.0.0.1";
  base.encryption_mode = config::EncryptionMode::kEncrypted;
  base.encryption_required = true;
  base.authenticated_transport_required = true;
  base.authenticated_transport_tofu = true;

  const auto client_dir = MakeTempDir("qryptcoin-auth-disable-client");
  const auto server_dir_a = MakeTempDir("qryptcoin-auth-disable-server-a");
  const auto server_dir_b = MakeTempDir("qryptcoin-auth-disable-server-b");

  net::FrameChannel listener;
  std::uint16_t port = 0;
  if (!BindEphemeral(&listener, base.listen_address, &port)) {
    std::cerr << "authenticated_transport_tests: failed to bind disable listener\n";
    return false;
  }

  std::atomic<int> server_ok{0};
  std::thread server_thread([&] {
    for (int round = 0; round < 2; ++round) {
      net::FrameChannel inbound = listener.Accept();
      inbound.socket().SetTimeout(5000);
      net::PeerSession session(std::move(inbound), /*initiator=*/false);
      config::NetworkConfig server_cfg = base;
      server_cfg.data_dir = (round == 0 ? server_dir_a : server_dir_b).string();
      if (session.PerformHandshake(server_cfg)) {
        server_ok.fetch_add(1);
      }
      session.Close();
    }
  });

  config::NetworkConfig client_cfg = base;
  client_cfg.data_dir = client_dir.string();

  net::PeerSession client1;
  if (!client1.Connect(base.listen_address, port) || !client1.PerformHandshake(client_cfg)) {
    std::cerr << "authenticated_transport_tests: initial handshake failed (disable test)\n";
    client1.Close();
    server_thread.join();
    return false;
  }
  client1.Close();

  net::PeerSession client2;
  client2.SetEnforcePeerIdentityPinning(false);
  if (!client2.Connect(base.listen_address, port) || !client2.PerformHandshake(client_cfg)) {
    std::cerr << "authenticated_transport_tests: expected pinning-disabled handshake to succeed\n";
    std::cerr << "authenticated_transport_tests: client error: " << client2.last_error() << "\n";
    client2.Close();
    server_thread.join();
    return false;
  }
  client2.Close();

  server_thread.join();
  std::filesystem::remove_all(client_dir);
  std::filesystem::remove_all(server_dir_a);
  std::filesystem::remove_all(server_dir_b);

  if (server_ok.load() != 2) {
    std::cerr << "authenticated_transport_tests: expected 2 disable handshakes, got "
              << server_ok.load() << "\n";
    return false;
  }
  return true;
}

bool TestInboundDoesNotPinBySourceAddress() {
  config::SelectNetwork(config::NetworkType::kRegtest);

  config::NetworkConfig base = config::GetNetworkConfig();
  base.listen_address = "127.0.0.1";
  base.encryption_mode = config::EncryptionMode::kEncrypted;
  base.encryption_required = true;
  base.authenticated_transport_required = true;
  base.authenticated_transport_tofu = true;

  const auto server_dir = MakeTempDir("qryptcoin-auth-inbound-server");
  const auto client_dir_a = MakeTempDir("qryptcoin-auth-inbound-client-a");
  const auto client_dir_b = MakeTempDir("qryptcoin-auth-inbound-client-b");

  net::FrameChannel listener;
  std::uint16_t port = 0;
  if (!BindEphemeral(&listener, base.listen_address, &port)) {
    std::cerr << "authenticated_transport_tests: failed to bind inbound listener\n";
    return false;
  }

  std::atomic<int> server_ok{0};
  std::thread server_thread([&] {
    for (int round = 0; round < 2; ++round) {
      net::FrameChannel inbound = listener.Accept();
      inbound.socket().SetTimeout(5000);
      net::PeerSession session(std::move(inbound), /*initiator=*/false);
      config::NetworkConfig server_cfg = base;
      server_cfg.data_dir = server_dir.string();
      if (session.PerformHandshake(server_cfg)) {
        server_ok.fetch_add(1);
      }
      session.Close();
    }
  });

  config::NetworkConfig client_cfg_a = base;
  client_cfg_a.data_dir = client_dir_a.string();
  net::PeerSession client_a;
  if (!client_a.Connect(base.listen_address, port) || !client_a.PerformHandshake(client_cfg_a)) {
    std::cerr << "authenticated_transport_tests: inbound client A handshake failed\n";
    client_a.Close();
    server_thread.join();
    return false;
  }
  client_a.Close();

  config::NetworkConfig client_cfg_b = base;
  client_cfg_b.data_dir = client_dir_b.string();
  net::PeerSession client_b;
  if (!client_b.Connect(base.listen_address, port) || !client_b.PerformHandshake(client_cfg_b)) {
    std::cerr << "authenticated_transport_tests: inbound client B handshake failed\n";
    std::cerr << "authenticated_transport_tests: client B error: " << client_b.last_error() << "\n";
    client_b.Close();
    server_thread.join();
    return false;
  }
  client_b.Close();

  server_thread.join();
  std::filesystem::remove_all(server_dir);
  std::filesystem::remove_all(client_dir_a);
  std::filesystem::remove_all(client_dir_b);

  if (server_ok.load() != 2) {
    std::cerr << "authenticated_transport_tests: expected 2 inbound handshakes, got "
              << server_ok.load() << "\n";
    return false;
  }
  return true;
}

bool TestHandshakeResponseReplayFails() {
  config::SelectNetwork(config::NetworkType::kRegtest);

  config::NetworkConfig base = config::GetNetworkConfig();
  base.listen_address = "127.0.0.1";
  base.encryption_mode = config::EncryptionMode::kEncrypted;
  base.encryption_required = true;
  base.authenticated_transport_required = false;
  base.authenticated_transport_tofu = false;

  const auto client_dir = MakeTempDir("qryptcoin-auth-replay-client");
  base.data_dir = client_dir.string();

  std::shared_ptr<crypto::QPqDilithiumKey> client_identity;
  std::string id_error;
  if (!net::LoadOrCreateTransportIdentity(client_dir, &client_identity, &id_error)) {
    std::cerr << "authenticated_transport_tests: failed to init client identity: " << id_error
              << "\n";
    return false;
  }

  // Craft a replayed responder handshake response that is valid for a different
  // initiator Kyber key. The client should reject it due to transcript mismatch.
  const auto responder_identity = crypto::QPqDilithiumKey::Generate();
  const auto kyber_old = crypto::QPqKyberKEM::Generate();
  const auto encapsulated = crypto::QPqKyberKEM::Encapsulate(kyber_old.PublicKey());

  net::messages::HandshakeResponse replay_resp;
  replay_resp.kyber_ciphertext = encapsulated.ciphertext;
  replay_resp.identity_public_key.assign(responder_identity.PublicKey().begin(),
                                         responder_identity.PublicKey().end());

  const std::uint32_t proto = net::messages::kCurrentProtocolVersion;
  const std::uint64_t initiator_services = base.service_bits;
  const std::uint64_t responder_services = base.service_bits;
  const auto transcript = net::ComputeTransportAuthTranscriptHash(
      proto,
      initiator_services,
      responder_services,
      static_cast<std::uint8_t>(base.encryption_mode),
      static_cast<std::uint8_t>(base.encryption_mode),
      /*initiator_requires_encryption=*/true,
      /*responder_requires_encryption=*/true,
      client_identity->PublicKey(),
      replay_resp.identity_public_key,
      kyber_old.PublicKey(),
      replay_resp.kyber_ciphertext);
  replay_resp.signature = responder_identity.Sign(transcript);

  net::FrameChannel listener;
  std::uint16_t port = 0;
  if (!BindEphemeral(&listener, base.listen_address, &port)) {
    std::cerr << "authenticated_transport_tests: failed to bind replay listener\n";
    return false;
  }

  std::atomic<bool> server_ready{false};
  std::thread server_thread([&] {
    net::FrameChannel inbound = listener.Accept();
    inbound.SetMessageStart(base.message_start);
    inbound.socket().SetTimeout(5000);

    // Minimal responder-side version handshake (no encryption downgrade allowed here).
    net::messages::Message msg;
    if (!inbound.Receive(&msg)) {
      return;
    }
    net::messages::VersionMessage peer_version;
    if (!net::messages::DecodeVersion(msg, &peer_version)) {
      return;
    }
    net::messages::VersionMessage local_version;
    local_version.protocol_version =
        std::min<std::uint32_t>(net::messages::kCurrentProtocolVersion, peer_version.protocol_version);
    local_version.services = responder_services;
    local_version.timestamp = peer_version.timestamp;
    local_version.preferred_mode = base.encryption_mode;
    local_version.requires_encryption =
        base.encryption_required || base.authenticated_transport_required;
    local_version.network_id = base.network_id;
    local_version.genesis_hash = consensus::Params(base.type).genesis_hash;
    if (!inbound.Send(net::messages::EncodeVersion(local_version))) {
      return;
    }
    if (!inbound.Receive(&msg) || !net::messages::IsVerAck(msg)) {
      return;
    }
    if (!inbound.Send(net::messages::EncodeVerAck())) {
      return;
    }

    // Receive the initiator handshake init then replay a mismatched response.
    if (!inbound.Receive(&msg) || msg.command != net::messages::Command::kHandshakeInit) {
      return;
    }
    server_ready.store(true);
    inbound.Send(net::messages::EncodeHandshakeResponse(replay_resp));
    inbound.socket().Close();
  });

  net::PeerSession client;
  if (!client.Connect(base.listen_address, port)) {
    std::cerr << "authenticated_transport_tests: replay client connect failed\n";
    server_thread.join();
    return false;
  }
  const bool ok = client.PerformHandshake(base);
  client.Close();
  server_thread.join();
  std::filesystem::remove_all(client_dir);

  if (!server_ready.load()) {
    std::cerr << "authenticated_transport_tests: replay server did not reach init stage\n";
    return false;
  }
  if (ok) {
    std::cerr << "authenticated_transport_tests: expected replayed handshake response to fail\n";
    return false;
  }
  return true;
}

}  // namespace

int main() {
  if (!TestIdentityMismatchAfterTofuPin()) {
    return 1;
  }
  if (!TestIdentityMismatchAllowedWhenPinningDisabled()) {
    return 1;
  }
  if (!TestInboundDoesNotPinBySourceAddress()) {
    return 1;
  }
  if (!TestHandshakeResponseReplayFails()) {
    return 1;
  }
  std::cout << "authenticated_transport_tests: OK\n";
  return 0;
}
