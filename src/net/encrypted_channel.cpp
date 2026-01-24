#include "net/encrypted_channel.hpp"

#include <chrono>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "crypto/hash.hpp"
#include "net/messages.hpp"
#include "net/transport_auth.hpp"
#include "util/aead.hpp"

namespace qryptcoin::net {

namespace {

std::array<std::uint8_t, util::kChaCha20Poly1305NonceSize> MakeNonce(std::uint64_t counter) {
  std::array<std::uint8_t, util::kChaCha20Poly1305NonceSize> nonce{};
  for (int i = 0; i < 8; ++i) {
    nonce[i] = static_cast<std::uint8_t>((counter >> (8 * i)) & 0xFF);
  }
  return nonce;
}

crypto::Sha3_256Hash ComputeFinishedHash(std::span<const std::uint8_t> transcript_hash,
                                        std::uint8_t role) {
  constexpr std::string_view kDomain = "QRY-P2P-FINISHED-V1";
  std::vector<std::uint8_t> preimage;
  preimage.reserve(kDomain.size() + transcript_hash.size() + 1);
  preimage.insert(preimage.end(), kDomain.begin(), kDomain.end());
  preimage.insert(preimage.end(), transcript_hash.begin(), transcript_hash.end());
  preimage.push_back(role);
  return crypto::Sha3_256(preimage);
}

}  // namespace

EncryptedChannel::EncryptedChannel(FrameChannel channel) : channel_(std::move(channel)) {}

bool EncryptedChannel::PerformHandshake(bool initiator, bool enable_encryption,
                                        const TransportAuthContext* auth) {
  last_error_.clear();
  if (!enable_encryption) {
    encrypted_ = false;
    return true;
  }
  if (auth == nullptr || auth->identity_key == nullptr) {
    last_error_ = "missing transport auth context";
    return false;
  }
  if (initiator) {
    return InitiatorHandshake(*auth);
  }
  return ResponderHandshake(*auth);
}

bool EncryptedChannel::Send(const messages::Message& message) {
  last_error_.clear();
  if (!encrypted_) {
    return SendPlain(message);
  }
  return EncryptAndSend(message);
}

bool EncryptedChannel::Receive(messages::Message* message) {
  last_error_.clear();
  if (!encrypted_) {
    return ReceivePlain(message);
  }
  return ReceiveAndDecrypt(message);
}

void EncryptedChannel::Close() {
  channel_.socket().Close();
}

bool EncryptedChannel::SendPlain(const messages::Message& message) {
  if (!channel_.Send(message)) {
    last_error_ = channel_.last_error();
    return false;
  }
  return true;
}

bool EncryptedChannel::ReceivePlain(messages::Message* message) {
  if (!channel_.Receive(message)) {
    last_error_ = channel_.last_error();
    return false;
  }
  return true;
}

std::vector<std::uint8_t> EncryptedChannel::DeriveKey(std::span<const std::uint8_t> secret,
                                                      std::span<const std::uint8_t> transcript_hash,
                                                      std::string_view info) {
  std::vector<std::uint8_t> buffer(secret.begin(), secret.end());
  buffer.insert(buffer.end(), transcript_hash.begin(), transcript_hash.end());
  buffer.insert(buffer.end(), info.begin(), info.end());
  return crypto::Sha3_256Vector(buffer);
}

bool EncryptedChannel::InitiatorHandshake(const TransportAuthContext& auth) {
  try {
    auto fail = [&](std::string message) {
      last_error_ = std::move(message);
      return false;
    };

    kyber_keypair_ = crypto::QPqKyberKEM::Generate();
    messages::HandshakeInit init;
    init.kyber_public_key.assign(kyber_keypair_.PublicKey().begin(),
                                 kyber_keypair_.PublicKey().end());
    init.identity_public_key.assign(auth.identity_key->PublicKey().begin(),
                                    auth.identity_key->PublicKey().end());
    if (!channel_.Send(messages::EncodeHandshakeInit(init))) {
      return fail("handshake init send failed: " + channel_.last_error());
    }
    messages::Message response_message;
    if (!channel_.Receive(&response_message)) {
      return fail("handshake response receive failed: " + channel_.last_error());
    }
    messages::HandshakeResponse response;
    if (!messages::DecodeHandshakeResponse(response_message, &response)) {
      const std::size_t expected = crypto::KyberCiphertextSize() +
                                   crypto::DilithiumPublicKeySize() +
                                   crypto::DilithiumSignatureSize();
      return fail("handshake response decode failed (cmd=" +
                  std::to_string(static_cast<std::uint16_t>(response_message.command)) +
                  ", payload=" + std::to_string(response_message.payload.size()) +
                  ", expected=" + std::to_string(expected) + ")");
    }

    const auto transcript_hash = ComputeTransportAuthTranscriptHash(
        auth.protocol_version,
        auth.initiator_services,
        auth.responder_services,
        auth.initiator_preferred_mode,
        auth.responder_preferred_mode,
        auth.initiator_requires_encryption,
        auth.responder_requires_encryption,
        init.identity_public_key,
        response.identity_public_key,
        init.kyber_public_key,
        response.kyber_ciphertext);
    if (!crypto::VerifySignature(crypto::SignatureAlgorithm::kDilithium,
                                 transcript_hash,
                                 response.signature,
                                 response.identity_public_key)) {
      return fail("handshake response signature verify failed");
    }

    messages::HandshakeFinalize fin;
    fin.signature = auth.identity_key->Sign(transcript_hash);
    if (!channel_.Send(messages::EncodeHandshakeFinalize(fin))) {
      return fail("handshake finalize send failed: " + channel_.last_error());
    }

    auto shared = kyber_keypair_.Decapsulate(response.kyber_ciphertext);
    auto send = DeriveKey(shared, transcript_hash, "qrypt-send");
    auto recv = DeriveKey(shared, transcript_hash, "qrypt-recv");
    std::copy(send.begin(), send.end(), send_key_.begin());
    std::copy(recv.begin(), recv.end(), recv_key_.begin());
    encrypted_ = true;
    send_counter_ = 0;
    recv_counter_ = 0;
    if (auth.peer_identity_public_key) {
      *auth.peer_identity_public_key = response.identity_public_key;
    }

    messages::HandshakeFinished finished_msg;
    finished_msg.verify = ComputeFinishedHash(transcript_hash, /*role=*/0x01);
    if (!Send(messages::EncodeHandshakeFinished(finished_msg))) {
      return fail("handshake finished send failed: " + last_error_);
    }
    messages::Message peer_msg;
    if (!Receive(&peer_msg)) {
      return fail("handshake finished receive failed: " + last_error_);
    }
    messages::HandshakeFinished peer_fin;
    if (!messages::DecodeHandshakeFinished(peer_msg, &peer_fin)) {
      return fail("handshake finished decode failed");
    }
    const auto expected_peer = ComputeFinishedHash(transcript_hash, /*role=*/0x02);
    if (peer_fin.verify != expected_peer) {
      return fail("handshake finished verify mismatch");
    }
    return true;
  } catch (const std::exception& ex) {
    last_error_ = ex.what();
    return false;
  } catch (...) {
    last_error_ = "unknown error";
    return false;
  }
}

bool EncryptedChannel::ResponderHandshake(const TransportAuthContext& auth) {
  try {
    auto fail = [&](std::string message) {
      last_error_ = std::move(message);
      return false;
    };

    messages::Message init_message;
    if (!channel_.Receive(&init_message)) {
      return fail("handshake init receive failed: " + channel_.last_error());
    }
    messages::HandshakeInit init;
    if (!messages::DecodeHandshakeInit(init_message, &init)) {
      const std::size_t expected = crypto::KyberPublicKeySize() +
                                   crypto::DilithiumPublicKeySize();
      return fail("handshake init decode failed (cmd=" +
                  std::to_string(static_cast<std::uint16_t>(init_message.command)) +
                  ", payload=" + std::to_string(init_message.payload.size()) +
                  ", expected=" + std::to_string(expected) + ")");
    }
    auto encapsulated = crypto::QPqKyberKEM::Encapsulate(init.kyber_public_key);
    messages::HandshakeResponse resp;
    resp.kyber_ciphertext = encapsulated.ciphertext;
    resp.identity_public_key.assign(auth.identity_key->PublicKey().begin(),
                                    auth.identity_key->PublicKey().end());
    const auto transcript_hash = ComputeTransportAuthTranscriptHash(
        auth.protocol_version,
        auth.initiator_services,
        auth.responder_services,
        auth.initiator_preferred_mode,
        auth.responder_preferred_mode,
        auth.initiator_requires_encryption,
        auth.responder_requires_encryption,
        init.identity_public_key,
        resp.identity_public_key,
        init.kyber_public_key,
        resp.kyber_ciphertext);
    resp.signature = auth.identity_key->Sign(transcript_hash);
    if (!channel_.Send(messages::EncodeHandshakeResponse(resp))) {
      return fail("handshake response send failed: " + channel_.last_error());
    }

    messages::Message fin_message;
    if (!channel_.Receive(&fin_message)) {
      return fail("handshake finalize receive failed: " + channel_.last_error());
    }
    messages::HandshakeFinalize fin;
    if (!messages::DecodeHandshakeFinalize(fin_message, &fin)) {
      const std::size_t expected = crypto::DilithiumSignatureSize();
      return fail("handshake finalize decode failed (cmd=" +
                  std::to_string(static_cast<std::uint16_t>(fin_message.command)) +
                  ", payload=" + std::to_string(fin_message.payload.size()) +
                  ", expected=" + std::to_string(expected) + ")");
    }
    if (!crypto::VerifySignature(crypto::SignatureAlgorithm::kDilithium,
                                 transcript_hash,
                                 fin.signature,
                                 init.identity_public_key)) {
      return fail("handshake finalize signature verify failed");
    }

    auto recv = DeriveKey(encapsulated.shared_secret, transcript_hash, "qrypt-send");
    auto send = DeriveKey(encapsulated.shared_secret, transcript_hash, "qrypt-recv");
    std::copy(send.begin(), send.end(), send_key_.begin());
    std::copy(recv.begin(), recv.end(), recv_key_.begin());
    encrypted_ = true;
    send_counter_ = 0;
    recv_counter_ = 0;
    if (auth.peer_identity_public_key) {
      *auth.peer_identity_public_key = init.identity_public_key;
    }

    messages::Message peer_msg;
    if (!Receive(&peer_msg)) {
      return fail("handshake finished receive failed: " + last_error_);
    }
    messages::HandshakeFinished peer_fin;
    if (!messages::DecodeHandshakeFinished(peer_msg, &peer_fin)) {
      return fail("handshake finished decode failed");
    }
    const auto expected_peer = ComputeFinishedHash(transcript_hash, /*role=*/0x01);
    if (peer_fin.verify != expected_peer) {
      return fail("handshake finished verify mismatch");
    }

    messages::HandshakeFinished finished_msg;
    finished_msg.verify = ComputeFinishedHash(transcript_hash, /*role=*/0x02);
    if (!Send(messages::EncodeHandshakeFinished(finished_msg))) {
      return fail("handshake finished send failed: " + last_error_);
    }
    return true;
  } catch (const std::exception& ex) {
    last_error_ = ex.what();
    return false;
  } catch (...) {
    last_error_ = "unknown error";
    return false;
  }
}

bool EncryptedChannel::EncryptAndSend(const messages::Message& message) {
  std::array<std::uint8_t, util::kChaCha20Poly1305NonceSize> nonce = MakeNonce(send_counter_++);
  std::vector<std::uint8_t> inner;
  inner.reserve(sizeof(std::uint16_t) + message.payload.size());
  inner.push_back(static_cast<std::uint8_t>(static_cast<std::uint16_t>(message.command) & 0xFF));
  inner.push_back(static_cast<std::uint8_t>((static_cast<std::uint16_t>(message.command) >> 8) & 0xFF));
  inner.insert(inner.end(), message.payload.begin(), message.payload.end());
  auto ciphertext =
      util::ChaCha20Poly1305Encrypt(send_key_, nonce, {}, inner);
  std::vector<std::uint8_t> payload;
  payload.insert(payload.end(), nonce.begin(), nonce.end());
  payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());
  messages::Message envelope{messages::Command::kEncryptedFrame, payload};
  if (!channel_.Send(envelope)) {
    last_error_ = channel_.last_error();
    return false;
  }
  return true;
}

bool EncryptedChannel::ReceiveAndDecrypt(messages::Message* message) {
  messages::Message outer;
  if (!channel_.Receive(&outer)) {
    last_error_ = channel_.last_error();
    return false;
  }
  if (outer.command != messages::Command::kEncryptedFrame) {
    last_error_ = "unexpected command (expected encrypted frame)";
    return false;
  }
  if (outer.payload.size() <= util::kChaCha20Poly1305NonceSize) {
    last_error_ = "encrypted frame truncated";
    return false;
  }
  std::array<std::uint8_t, util::kChaCha20Poly1305NonceSize> nonce{};
  std::copy_n(outer.payload.begin(), nonce.size(), nonce.begin());
  const auto expected_nonce = MakeNonce(recv_counter_);
  if (nonce != expected_nonce) {
    last_error_ = "encrypted frame nonce mismatch";
    return false;
  }
  std::vector<std::uint8_t> plaintext;
  if (!util::ChaCha20Poly1305Decrypt(recv_key_, nonce, {},
                                     std::span<const std::uint8_t>(outer.payload.data() + nonce.size(),
                                                                   outer.payload.size() - nonce.size()),
                                     &plaintext)) {
    last_error_ = "encrypted frame AEAD decrypt failed";
    return false;
  }
  if (plaintext.size() < 2) {
    last_error_ = "encrypted frame inner payload truncated";
    return false;
  }
  std::uint16_t cmd = plaintext[0] | (plaintext[1] << 8);
  message->command = static_cast<messages::Command>(cmd);
  if (message->command == messages::Command::kEncryptedFrame) {
    last_error_ = "nested encrypted frame not allowed";
    return false;
  }
  message->payload.assign(plaintext.begin() + 2, plaintext.end());
  recv_counter_++;
  return true;
}

}  // namespace qryptcoin::net
