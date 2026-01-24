#include "wallet/wallet_context.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <span>
#include <vector>

namespace qryptcoin::wallet {

namespace {

std::string BytesToHex(std::span<const std::uint8_t> data) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (const auto byte : data) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

}  // namespace

WalletAccount::WalletAccount(std::string label, crypto::QPqDilithiumKey dilithium)
    : label_(std::move(label)), dilithium_key_(std::move(dilithium)) {
  BuildDescriptorInternal();
}

WalletAccount::WalletAccount(WalletAccount&&) noexcept = default;

WalletAccount& WalletAccount::operator=(WalletAccount&&) noexcept = default;

WalletAccount::~WalletAccount() = default;

void WalletAccount::BuildDescriptorInternal() {
  descriptor_reveal_ = crypto::BuildP2QHReveal(dilithium_key_.PublicKey());
  descriptor_ = crypto::DescriptorFromReveal(descriptor_reveal_);
}

crypto::P2QHDescriptor WalletAccount::HybridDescriptor() const {
  return descriptor_;
}

std::string WalletAccount::DescriptorHex() const {
  const auto serialized = crypto::SerializeP2QHDescriptor(descriptor_);
  return BytesToHex(std::span<const std::uint8_t>(serialized.data(), serialized.size()));
}

std::string WalletAccount::P2QHAddress(std::string_view hrp) const {
  return crypto::EncodeP2QHAddress(descriptor_, hrp);
}

WalletAccount& WalletContext::CreateHybridAccount(const std::string& label) {
  accounts_.emplace_back(label, crypto::QPqDilithiumKey::Generate());
  return accounts_.back();
}

std::vector<std::string> WalletContext::ListDescriptorHexes() const {
  std::vector<std::string> descriptors;
  descriptors.reserve(accounts_.size());
  for (const auto& account : accounts_) {
    descriptors.push_back(account.DescriptorHex());
  }
  return descriptors;
}

std::vector<std::string> WalletContext::ListAddresses(std::string_view hrp) const {
  std::vector<std::string> addresses;
  addresses.reserve(accounts_.size());
  for (const auto& account : accounts_) {
    addresses.push_back(account.P2QHAddress(hrp));
  }
  return addresses;
}

}  // namespace qryptcoin::wallet
