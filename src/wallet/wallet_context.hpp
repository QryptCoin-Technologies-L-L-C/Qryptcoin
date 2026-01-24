#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "crypto/hash.hpp"
#include "crypto/p2qh_address.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "crypto/pq_engine.hpp"

namespace qryptcoin::wallet {

class WalletAccount {
 public:
  WalletAccount(std::string label, crypto::QPqDilithiumKey dilithium);
  WalletAccount(WalletAccount&&) noexcept;
  WalletAccount& operator=(WalletAccount&&) noexcept;
  WalletAccount(const WalletAccount&) = delete;
  WalletAccount& operator=(const WalletAccount&) = delete;
  ~WalletAccount();

  const std::string& label() const noexcept { return label_; }
  crypto::P2QHDescriptor HybridDescriptor() const;
  std::string DescriptorHex() const;
  std::string P2QHAddress(std::string_view hrp = "qry") const;
  const std::vector<std::uint8_t>& DescriptorReveal() const noexcept { return descriptor_reveal_; }

 private:
  void BuildDescriptorInternal();

  std::string label_;
  crypto::QPqDilithiumKey dilithium_key_;
  crypto::P2QHDescriptor descriptor_;
  std::vector<std::uint8_t> descriptor_reveal_;
};

class WalletContext {
 public:
  WalletAccount& CreateHybridAccount(const std::string& label);
  std::vector<std::string> ListDescriptorHexes() const;
  std::vector<std::string> ListAddresses(std::string_view hrp = "qry") const;
  std::size_t size() const noexcept { return accounts_.size(); }

 private:
  std::vector<WalletAccount> accounts_;
};

}  // namespace qryptcoin::wallet
