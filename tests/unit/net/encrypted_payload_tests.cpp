#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <random>
#include <thread>
#include <vector>

#include "config/network.hpp"
#include "consensus/params.hpp"
#include "net/channel.hpp"
#include "net/messages.hpp"
#include "net/peer_session.hpp"

namespace {

bool BindEphemeral(qryptcoin::net::FrameChannel* listener,
                   const std::string& addr,
                   std::uint16_t* out_port) {
  std::mt19937 rng(static_cast<std::uint32_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  for (int attempt = 0; attempt < 200; ++attempt) {
    const std::uint16_t port =
        static_cast<std::uint16_t>(20000u + (rng() % 30000u));
    if (listener->BindAndListen(addr, port)) {
      if (out_port) *out_port = port;
      return true;
    }
  }
  return false;
}

}  // namespace

int main() {
  using namespace qryptcoin;

  config::SelectNetwork(config::NetworkType::kRegtest);
  const auto& params = consensus::Params(config::NetworkType::kRegtest);

  config::NetworkConfig cfg = config::GetNetworkConfig();
  cfg.listen_address = "127.0.0.1";
  cfg.encryption_mode = config::EncryptionMode::kEncrypted;
  cfg.encryption_required = true;

  net::FrameChannel server_listener;
  std::uint16_t port = 0;
  if (!BindEphemeral(&server_listener, cfg.listen_address, &port)) {
    std::cerr << "Failed to bind test listener\n";
    return 1;
  }

  const std::size_t max_block_bytes = params.max_block_serialized_bytes;
  std::atomic<bool> server_ok{false};

  std::thread server_thread([&] {
    net::FrameChannel inbound = server_listener.Accept();
    inbound.socket().SetTimeout(5000);
    net::PeerSession session(std::move(inbound), /*initiator=*/false);
    if (!session.PerformHandshake(cfg)) {
      return;
    }
    net::messages::Message msg;
    if (!session.Receive(&msg)) {
      return;
    }
    if (msg.command != net::messages::Command::kBlock) {
      return;
    }
    if (msg.payload.size() != max_block_bytes) {
      std::cerr << "Server received unexpected payload size: " << msg.payload.size()
                << " bytes\n";
      return;
    }
    server_ok.store(true);
    session.Close();
  });

  net::PeerSession client;
  if (!client.Connect(cfg.listen_address, port)) {
    std::cerr << "Client connect failed\n";
    server_thread.join();
    return 1;
  }
  if (!client.PerformHandshake(cfg)) {
    std::cerr << "Client handshake failed\n";
    server_thread.join();
    return 1;
  }

  net::messages::BlockMessage block_msg;
  block_msg.data.resize(max_block_bytes);
  if (!block_msg.data.empty()) {
    block_msg.data.front() = 0xAA;
    block_msg.data.back() = 0x55;
  }
  if (!client.Send(net::messages::EncodeBlock(block_msg))) {
    std::cerr << "Client send block failed\n";
    client.Close();
    server_thread.join();
    return 1;
  }
  client.Close();
  server_thread.join();

  if (!server_ok.load()) {
    std::cerr << "Encrypted max-payload relay test failed\n";
    return 1;
  }
  return 0;
}

