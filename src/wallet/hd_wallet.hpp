#pragma once

#include <array>
#include <cstdint>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include <unordered_map>

#include "consensus/utxo.hpp"
#include "crypto/pq_engine.hpp"
#include "crypto/payment_code.hpp"
#include "crypto/p2qh_descriptor.hpp"
#include "primitives/transaction.hpp"

namespace qryptcoin::wallet {

struct WalletTransaction {
  std::string txid;
  primitives::Amount amount{0};
  bool incoming{true};
  std::string label;
  std::uint64_t timestamp{0};
  primitives::Amount fee{0};
  std::int32_t confirmations{0};
  bool coinbase{false};
};

enum class UTXOState : std::uint8_t {
  kAvailable = 0,
  kPending = 1,
  kSpent = 2,
  kOrphaned = 3,
};

struct WalletUTXO {
  primitives::COutPoint outpoint;
  primitives::CTxOut txout;
  std::uint32_t key_index{0};
  crypto::SignatureAlgorithm algorithm{crypto::SignatureAlgorithm::kDilithium};
  UTXOState state{UTXOState::kAvailable};
  primitives::Hash256 pending_txid{};
  std::uint32_t confirmed_height{0};
  bool is_change{false};
  bool coinbase{false};
  // Outputs tracked as watch-only belong to scripts that the wallet
  // can monitor but cannot spend from because it does not possess
  // the corresponding private keys.
  bool watch_only{false};
};

struct CreatedTransaction {
  primitives::CTransaction tx;
  primitives::Amount fee{0};
  primitives::Amount sent_total{0};
  std::vector<primitives::COutPoint> spent_outpoints;
  std::optional<WalletUTXO> change_utxo;
};

// Lightweight view of deterministically derived key material suitable for
// tooling and diagnostics. This struct intentionally avoids any wallet file
// metadata and focuses on the PQ primitives and descriptor wire format.
struct DerivedKeyInfo {
  std::uint32_t index{0};
  crypto::SignatureAlgorithm algorithm{crypto::SignatureAlgorithm::kDilithium};
  crypto::P2QHDescriptor descriptor;
  std::vector<std::uint8_t> reveal;
  std::vector<std::uint8_t> dilithium_public_key;
  std::vector<std::uint8_t> dilithium_secret_key;
};

enum class PaymentCodeReservationStatus : std::uint8_t {
  kReserved = 0,
  kUsed = 1,
  kExpired = 2,
};

struct PaymentCodeReservation {
  std::uint32_t key_index{0};
  std::uint64_t issued_time{0};
  std::uint32_t issued_height{0};
  std::uint32_t expiry_height{0};
  std::array<std::uint8_t, 16> challenge{};
  PaymentCodeReservationStatus status{PaymentCodeReservationStatus::kReserved};
};

class HDWallet {
 public:
  static std::unique_ptr<HDWallet> Create(const std::string& path, const std::string& password,
                                          crypto::SignatureAlgorithm default_algo);
  static std::unique_ptr<HDWallet> Load(const std::string& path, const std::string& password);
  static std::unique_ptr<HDWallet> Load(const std::string& path, const std::string& password,
                                        std::string* error);
  static std::unique_ptr<HDWallet> ImportSeedHex(const std::string& path,
                                                 const std::string& password,
                                                 const std::string& seed_hex,
                                                 crypto::SignatureAlgorithm default_algo);
  // Construct an in-memory wallet from an existing 32-byte master seed.
  // This helper does not touch the filesystem and is intended for tools
  // and tests that need deterministic derivation without persisting a
  // wallet.dat. The resulting wallet starts unlocked.
  static std::unique_ptr<HDWallet> FromSeedForTools(
      const std::array<std::uint8_t, 32>& seed,
      crypto::SignatureAlgorithm default_algo);
  // Create or reset the wallet using a 24-word mnemonic sentence. The
  // mnemonic is converted to a 64-byte mnemonic seed via PBKDF2-HMAC-SHA512,
  // which is then mapped to the 32-byte internal master seed via SHA3-256.
  // This allows recovery of wallets created from the same mnemonic.
  bool CreateFromMnemonic(const std::string& path, const std::string& password,
                          const std::string& mnemonic,
                          const std::string& mnemonic_passphrase,
                          crypto::SignatureAlgorithm default_algo);
  // Generate a fresh 24-word English mnemonic using the embedded 2048-word
  // wordlist. The mnemonic is returned as a single space-
  // separated string.
  static std::string GenerateMnemonic24();
  // Deterministically derive PQ key material for a fixed index and algorithm
  // without mutating wallet state or touching the filesystem. This is intended
  // for tooling such as converters and debuggers that need access to raw
  // pubkeys, secret keys, and descriptor reveal payloads.
  bool ExportDerivedKeyForTools(std::uint32_t index, crypto::SignatureAlgorithm algorithm,
                                DerivedKeyInfo* out) const;

  ~HDWallet();
  HDWallet(const HDWallet&) = delete;
  HDWallet& operator=(const HDWallet&) = delete;
  HDWallet(HDWallet&&) = default;
  HDWallet& operator=(HDWallet&&) = default;

  std::string NewAddress(crypto::SignatureAlgorithm policy);
  std::string NewAddress(bool hybrid_override = false);
  // Reserve and persist a fresh one-time address intended for interactive
  // Payment Code resolution. The address is never re-issued, even if it
  // expires or is never paid.
  bool ReservePaymentCodeAddress(const PaymentCodeReservation& reservation,
                                 std::string* out_address,
                                 std::string* error = nullptr);
  std::string PaymentCode() const;
  std::string PaymentCodeV2() const;
  std::string PaymentCodeV2ShortId() const;
  std::vector<std::string> ListAddresses() const;
  bool ForgetAddress(const std::string& address);
  std::vector<std::string> ListDescriptorHexes() const;
  std::optional<std::uint32_t> KeyIndexForAddress(const std::string& address) const;
  std::optional<std::vector<std::uint8_t>> ScriptForAddress(const std::string& address) const;
  std::optional<crypto::P2QHDescriptor> DescriptorForAddress(const std::string& address) const;
  std::optional<crypto::P2QHDescriptor> DescriptorForProgram(std::span<const std::uint8_t> program) const;
  primitives::Amount GetBalance() const;
  // Sum the value of all unspent watch-only UTXOs. These are outputs
  // the wallet can see and report on, but cannot spend.
  primitives::Amount GetWatchOnlyBalance() const;
  bool DefaultHybridPolicy() const noexcept {
    return false;
  }
  crypto::SignatureAlgorithm DefaultAlgorithm() const noexcept { return default_algorithm_; }
  std::vector<WalletTransaction> ListTransactions() const;
  bool AddUTXO(const WalletUTXO& utxo, bool is_coinbase = false,
               primitives::Amount tx_fee_miks = 0);
  bool MaybeTrackOutput(const primitives::Hash256& txid, std::size_t vout_index,
                        const primitives::CTxOut& txout, bool is_coinbase,
                        primitives::Amount tx_fee_miks = 0);
  bool MaybeTrackStealthTransaction(const primitives::Hash256& txid,
                                    const primitives::CTransaction& tx,
                                    bool is_coinbase,
                                    primitives::Amount tx_fee_miks = 0,
                                    std::function<bool(const primitives::COutPoint&)> is_unspent = {});
  std::optional<CreatedTransaction> CreateTransaction(
      const std::vector<std::pair<std::string, primitives::Amount>>& outputs,
      primitives::Amount fee_rate, std::string* error);
  std::optional<CreatedTransaction> CreateTransactionWithVersion(
      const std::vector<std::pair<std::string, primitives::Amount>>& outputs,
      primitives::Amount fee_rate,
      std::uint32_t tx_version,
      std::string* error);
  std::optional<CreatedTransaction> CreateTransactionWithWitnessPayload(
      const std::vector<std::pair<std::string, primitives::Amount>>& outputs,
      primitives::Amount fee_rate,
      std::span<const std::uint8_t> witness_payload,
      std::string* error);
  bool CommitTransaction(const CreatedTransaction& tx, std::string* error = nullptr);
  void ConfirmPendingTransaction(const primitives::Hash256& txid,
                                 std::uint32_t confirmed_height = 0);
  void RollbackPendingTransaction(const primitives::Hash256& txid);
  std::vector<primitives::Hash256> PendingTransactionIds() const;
  std::size_t MarkOrphanedUtxos(
      const std::function<bool(const primitives::COutPoint&)>& view_has_utxo);
  bool Save() const;
  std::string ExportSeedHex() const;
  const std::vector<WalletUTXO>& TrackedUtxos() const { return utxos_; }
  bool CreateFresh(const std::string& path, const std::string& password,
                   crypto::SignatureAlgorithm default_algo);
  bool LoadFromFile(const std::string& path, const std::string& password);
  bool BackupTo(const std::string& destination) const;
  bool ChangePassphrase(const std::string& new_passphrase);
  const std::string& wallet_path() const { return wallet_path_; }
  const std::string& CurrentPassphrase() const { return password_; }
  const std::string& last_error() const noexcept { return last_error_; }
  bool IsLocked() const noexcept { return locked_; }
  std::optional<std::uint32_t> BirthHeight() const { return birth_height_; }
  std::optional<std::uint32_t> LastScanHeight() const { return last_scan_height_; }
  void SetBirthHeight(std::uint32_t height) { birth_height_ = height; }
  void SetLastScanHeight(std::uint32_t height) { last_scan_height_ = height; }
  // Deterministically derive an address at a fixed index without mutating
  // wallet state. This is primarily intended for tooling so that command
  // line utilities can reproduce the addresses that a normal HD wallet
  // would generate at the same index.
  std::string DeriveAddressForTools(std::uint32_t index,
                                    crypto::SignatureAlgorithm algorithm);
  // Register a bech32m P2QH address as watch-only. The wallet will
  // track outputs sent to this script and include them in the
  // watch-only balance but will never attempt to spend them.
  bool AddWatchOnlyAddress(const std::string& address);
  // Remove a previously registered watch-only address. This does not
  // delete any historical transactions but stops tracking future
  // outputs to the script.
  bool RemoveWatchOnlyAddress(const std::string& address);
  // Return the set of watch-only addresses currently tracked.
  std::vector<std::string> ListWatchOnlyAddresses() const;
  // Clear all tracked UTXOs from the wallet. This is useful when the wallet
  // has stale UTXO entries that no longer exist on the blockchain (e.g., after
  // importing a wallet from a different chain). After purging, the wallet
  // should be rescanned to rebuild the UTXO set from the current chain state.
  std::size_t PurgeUtxos();
  // Ensure that the HD keychain maintains at least `gap_limit` consecutive
  // unused addresses at the tail of the derived range. This provides a
  // simple keypool-style buffer so rescans can safely discover funds sent
  // to the next few external addresses without requiring the wallet to
  // have explicitly handed them out beforehand.
  void EnsureKeypoolGap(std::uint32_t gap_limit);
  void Lock();
  bool Unlock(const std::string& passphrase);
  std::size_t PaymentCodeReservationCount() const;
  bool HasPaymentCodeReservationForKeyIndex(std::uint32_t key_index) const;

 private:
  enum class DerivationScheme : std::uint8_t {
    kSha3Ctr = 0,
    kLegacyMt19937 = 1,
  };

  HDWallet(std::string path, std::string password, std::array<std::uint8_t, 32> seed,
           crypto::SignatureAlgorithm default_algo);

  struct AddressEntry {
    std::uint32_t index{0};
    crypto::SignatureAlgorithm algorithm{crypto::SignatureAlgorithm::kDilithium};
    std::string address;
    crypto::P2QHDescriptor descriptor;
    primitives::Hash256 program{};
  };

  struct KeyMaterial {
    crypto::SignatureAlgorithm algorithm{crypto::SignatureAlgorithm::kDilithium};
    crypto::P2QHDescriptor descriptor;
    std::vector<std::uint8_t> reveal;
    std::optional<crypto::QPqDilithiumKey> dilithium;
  };

  bool IsKeyBurned(std::uint32_t key_index) const;
  void BurnKeyIndex(std::uint32_t key_index);

  std::vector<std::uint8_t> SerializeState() const;
  bool DeserializeState(const std::vector<std::uint8_t>& payload, std::uint16_t version);
  bool EncryptAndWrite(const std::vector<std::uint8_t>& payload) const;
  bool ReadAndDecrypt(std::vector<std::uint8_t>* payload, std::uint16_t* version) const;

  KeyMaterial DeriveKeyMaterial(std::uint32_t index, crypto::SignatureAlgorithm algorithm) const;
  KeyMaterial DeriveStealthKeyMaterial(const std::array<std::uint8_t, 32>& key_seed) const;
  std::optional<CreatedTransaction> CreateTransactionInternal(
      const std::vector<std::pair<std::string, primitives::Amount>>& outputs,
      primitives::Amount fee_rate,
      std::uint32_t tx_version,
      std::span<const std::uint8_t> witness_payload,
      std::string* error);
  crypto::PaymentCodeV2 BuildPaymentCodeV2() const;
  const crypto::QPqKyberKEM& PaymentCodeV2Kem() const;
  std::string DeriveAddressInternal(std::uint32_t index, crypto::SignatureAlgorithm algorithm);
  primitives::COutPoint MakeChangeOutPoint(const primitives::CTransaction& tx,
                                           std::uint32_t change_index) const;
  AddressEntry* FindAddressEntry(const std::string& address);
  const AddressEntry* FindAddressEntry(const std::string& address) const;
  void IndexAddress(std::size_t idx);
  std::optional<AddressEntry> RebuildEntry(std::uint32_t index,
                                           crypto::SignatureAlgorithm algorithm,
                                           const std::string& address);
  void RecordTransaction(const WalletTransaction& tx);
  std::uint64_t Now() const;

  std::string wallet_path_;
  std::string password_;
  std::uint16_t wallet_format_version_{0};
  DerivationScheme derivation_scheme_{DerivationScheme::kSha3Ctr};
  mutable std::string last_error_;
  std::array<std::uint8_t, 32> seed_{};
  std::uint32_t next_index_{0};
  crypto::SignatureAlgorithm default_algorithm_{crypto::SignatureAlgorithm::kDilithium};
  bool in_memory_{false};
  std::vector<AddressEntry> addresses_;
  std::vector<WalletUTXO> utxos_;
  std::vector<std::uint32_t> burned_key_indices_;
  std::unordered_map<primitives::COutPoint, std::array<std::uint8_t, 32>,
                     consensus::OutPointHasher> stealth_spend_seeds_;
  std::unordered_map<std::string, std::size_t> address_index_;
  struct ProgramHasher {
    std::size_t operator()(const primitives::Hash256& program) const noexcept {
      std::size_t result = 0;
      for (auto byte : program) {
        result = (result * 131) ^ static_cast<std::size_t>(byte);
      }
      return result;
    }
  };
  std::unordered_map<primitives::Hash256, std::size_t, ProgramHasher> program_index_;
  struct WatchOnlyEntry {
    std::string address;
    crypto::P2QHDescriptor descriptor;
    primitives::Hash256 program{};
  };
  std::vector<WatchOnlyEntry> watch_only_;
  std::unordered_map<std::string, std::size_t> watch_only_address_index_;
  std::unordered_map<primitives::Hash256, std::size_t, ProgramHasher> watch_only_program_index_;
  std::vector<WalletTransaction> transactions_;
  std::vector<PaymentCodeReservation> payment_code_reservations_;
  mutable std::optional<crypto::QPqKyberKEM> paycode_v2_kem_;
  bool locked_{false};
  std::optional<std::uint32_t> birth_height_;
  std::optional<std::uint32_t> last_scan_height_;
};

}  // namespace qryptcoin::wallet
