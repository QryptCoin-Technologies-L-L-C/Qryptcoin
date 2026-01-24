#include <array>
#include <filesystem>
#include <iostream>

#include "wallet/hd_wallet.hpp"
#include "config/network.hpp"
#include "crypto/p2qh_address.hpp"
#include "crypto/mnemonic.hpp"
#include "crypto/hash.hpp"
#include "script/p2qh.hpp"

int main() {
  try {
    using namespace qryptcoin;
    const std::string wallet_path = "test_wallet.dat";
    const std::string import_path = "import_wallet.dat";
    std::filesystem::remove(wallet_path);
    std::filesystem::remove(import_path);

    auto wallet = wallet::HDWallet::Create(wallet_path, "testpass",
                                           crypto::SignatureAlgorithm::kDilithium);
    if (!wallet) {
      std::cerr << "Failed to create wallet\n";
      return EXIT_FAILURE;
    }
    auto addr1 = wallet->NewAddress();
    auto addr2 = wallet->NewAddress();
    auto script_opt = wallet->ScriptForAddress(addr1);
    if (!script_opt) {
      std::cerr << "Failed to derive script\n";
      return EXIT_FAILURE;
    }
    primitives::COutPoint outpoint;
    outpoint.txid.fill(0x01);
    outpoint.index = 0;
    primitives::CTxOut txout;
    txout.value = 5 * primitives::kMiksPerQRY;
    txout.locking_descriptor = *script_opt;
    wallet::WalletUTXO utxo{outpoint,
                            txout,
                            wallet->KeyIndexForAddress(addr1).value(),
                            crypto::SignatureAlgorithm::kDilithium,
                            false,
                            false,
                            false,
                            false};
    wallet->AddUTXO(utxo);
    if (wallet->GetBalance() == 0) {
      std::cerr << "Balance not updated\n";
      return EXIT_FAILURE;
    }
    std::vector<std::pair<std::string, primitives::Amount>> outputs = {
        {addr2, 2 * primitives::kMiksPerQRY}};
    std::string error;

    // Reject spends that attempt to create out-of-range outputs.
    {
      std::vector<std::pair<std::string, primitives::Amount>> bad_outputs = {
          {addr2, primitives::kMaxMoney + 1}};
      std::string bad_error;
      auto bad_tx = wallet->CreateTransaction(bad_outputs, 5, &bad_error);
      if (bad_tx) {
        std::cerr << "Expected out-of-range output to be rejected\n";
        return EXIT_FAILURE;
      }
      if (bad_error.find("out of range") == std::string::npos) {
        std::cerr << "Unexpected error for out-of-range output: " << bad_error << "\n";
        return EXIT_FAILURE;
      }
    }

    // Reject fee rates that exceed the maximum money range.
    {
      std::string bad_error;
      auto bad_tx = wallet->CreateTransaction(outputs, primitives::kMaxMoney + 1, &bad_error);
      if (bad_tx) {
        std::cerr << "Expected out-of-range fee_rate to be rejected\n";
        return EXIT_FAILURE;
      }
      if (bad_error.find("fee rate out of range") == std::string::npos) {
        std::cerr << "Unexpected error for fee_rate out-of-range: " << bad_error << "\n";
        return EXIT_FAILURE;
      }
    }

    auto tx = wallet->CreateTransaction(outputs, 5, &error);
    if (!tx) {
      std::cerr << "Transaction creation failed: " << error << "\n";
      return EXIT_FAILURE;
    }
    if (!wallet->Save()) {
      std::cerr << "Save failed\n";
      return EXIT_FAILURE;
    }
    auto loaded = wallet::HDWallet::Load(wallet_path, "testpass");
    if (!loaded) {
      std::cerr << "Failed to reload wallet\n";
      return EXIT_FAILURE;
    }
    if (loaded->ListAddresses().size() < 2) {
      std::cerr << "Addresses not persisted\n";
      return EXIT_FAILURE;
    }
    auto seed_hex = wallet->ExportSeedHex();
    auto imported = wallet::HDWallet::ImportSeedHex(
        import_path, "pass2", seed_hex,
        crypto::SignatureAlgorithm::kDilithium);
    if (!imported) {
      std::cerr << "Import failed\n";
      return EXIT_FAILURE;
    }
    // Verify that seed-based deterministic derivation is stable across
    // import/export by comparing a fixed index rather than relying on
    // internal address lists or keypool layout.
    const auto algo = crypto::SignatureAlgorithm::kDilithium;
    const auto addr_original =
        wallet->DeriveAddressForTools(/*index=*/0, algo);
    const auto addr_imported =
        imported->DeriveAddressForTools(/*index=*/0, algo);
    if (addr_original != addr_imported) {
      std::cerr << "Seed import mismatch\n";
      return EXIT_FAILURE;
    }
    std::filesystem::remove(wallet_path);
    std::filesystem::remove(import_path);

    // Verify that mnemonic-based creation produces the same master seed as
    // importing the derived seed hex directly.
    const std::string mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon art";
    const std::string mnemonic_passphrase;

    const auto mnemonic_seed =
        crypto::MnemonicSeedFromSentence(mnemonic, mnemonic_passphrase);
    const auto seed32 = crypto::Sha3_256(
        std::span<const std::uint8_t>(mnemonic_seed.data(), mnemonic_seed.size()));

    auto to_hex = [](std::span<const std::uint8_t> data) {
      static constexpr char kHex[] = "0123456789abcdef";
      std::string out;
      out.reserve(data.size() * 2);
      for (auto b : data) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
      }
      return out;
    };

    const auto seed_hex_from_mnemonic = to_hex(seed32);

    const std::string mnemonic_wallet_path1 = "mnemonic_wallet1.dat";
    const std::string mnemonic_wallet_path2 = "mnemonic_wallet2.dat";
    const std::string mnemonic_wallet_path_bad = "mnemonic_wallet_bad.dat";
    std::filesystem::remove(mnemonic_wallet_path1);
    std::filesystem::remove(mnemonic_wallet_path2);
    std::filesystem::remove(mnemonic_wallet_path_bad);

    // Enforce strict 24-word mnemonics for wallet recovery/import.
    {
      auto w_bad = wallet::HDWallet::Create(
          mnemonic_wallet_path_bad, "passmn",
          crypto::SignatureAlgorithm::kDilithium);
      if (!w_bad) {
        std::cerr << "Create for mnemonic negative test wallet failed\n";
        return EXIT_FAILURE;
      }

      const std::string mnemonic_12 =
          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon about";
      if (w_bad->CreateFromMnemonic(
              mnemonic_wallet_path_bad, "passmn", mnemonic_12,
              mnemonic_passphrase,
              crypto::SignatureAlgorithm::kDilithium)) {
        std::cerr << "Expected 12-word mnemonic to be rejected\n";
        return EXIT_FAILURE;
      }
      if (w_bad->last_error().find("24") == std::string::npos) {
        std::cerr << "Unexpected error for 12-word mnemonic: " << w_bad->last_error() << "\n";
        return EXIT_FAILURE;
      }

      const std::string mnemonic_bad_checksum =
          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon abandon";
      if (w_bad->CreateFromMnemonic(
              mnemonic_wallet_path_bad, "passmn", mnemonic_bad_checksum,
              mnemonic_passphrase,
              crypto::SignatureAlgorithm::kDilithium)) {
        std::cerr << "Expected checksum-invalid mnemonic to be rejected\n";
        return EXIT_FAILURE;
      }
      if (w_bad->last_error().find("checksum") == std::string::npos) {
        std::cerr << "Unexpected error for checksum-invalid mnemonic: " << w_bad->last_error()
                  << "\n";
        return EXIT_FAILURE;
      }

      std::filesystem::remove(mnemonic_wallet_path_bad);
    }

    // Coin selection and change behavior: prefer change UTXOs and avoid
    // creating uneconomical dust change.
    {
      std::array<std::uint8_t, 32> seed{};
      seed.fill(7);
      auto send_wallet = wallet::HDWallet::FromSeedForTools(
          seed, crypto::SignatureAlgorithm::kDilithium);
      if (!send_wallet) {
        std::cerr << "Failed to create in-memory send wallet\n";
        return EXIT_FAILURE;
      }

      const auto addr_change = send_wallet->NewAddress();
      const auto addr_external = send_wallet->NewAddress();

      auto script_change = send_wallet->ScriptForAddress(addr_change);
      auto script_external = send_wallet->ScriptForAddress(addr_external);
      if (!script_change || !script_external) {
        std::cerr << "Failed to derive scripts for send wallet\n";
        return EXIT_FAILURE;
      }

      // UTXO A: external funds on addr_external (2 QRY).
      primitives::COutPoint out_ext;
      out_ext.txid.fill(0xA1);
      out_ext.index = 0;
      primitives::CTxOut txout_ext;
      txout_ext.value = 2 * primitives::kMiksPerQRY;
      txout_ext.locking_descriptor = *script_external;
      wallet::WalletUTXO utxo_ext{
          out_ext,
          txout_ext,
          send_wallet->KeyIndexForAddress(addr_external).value(),
          crypto::SignatureAlgorithm::kDilithium,
          false,
          false,
          false,
          false};
      send_wallet->AddUTXO(utxo_ext);

      // UTXO B: tagged as wallet-internal change on addr_change (0.5 QRY).
      primitives::COutPoint out_chg;
      out_chg.txid.fill(0xB2);
      out_chg.index = 0;
      primitives::CTxOut txout_chg;
      txout_chg.value = primitives::kMiksPerQRY / 2;  // 0.5 QRY
      txout_chg.locking_descriptor = *script_change;
      wallet::WalletUTXO utxo_chg{
          out_chg,
          txout_chg,
          send_wallet->KeyIndexForAddress(addr_change).value(),
          crypto::SignatureAlgorithm::kDilithium,
          false,
          true,   // is_change
          false,  // coinbase
          false}; // watch_only
      send_wallet->AddUTXO(utxo_chg);

      // Spend 0.4 QRY; the wallet should preferentially consume the
      // change UTXO so the resulting transaction uses utxo_chg as its
      // only input when fees are small.
      const primitives::Amount spend_value =
          4 * primitives::kMiksPerQRY / 10;  // 0.4 QRY
      std::vector<std::pair<std::string, primitives::Amount>> send_outputs = {
          {addr_external, spend_value}};
      std::string send_error;
      auto spend_tx =
          send_wallet->CreateTransaction(send_outputs, /*fee_rate=*/1, &send_error);
      if (!spend_tx) {
        std::cerr << "Send wallet CreateTransaction failed: " << send_error << "\n";
        return EXIT_FAILURE;
      }
      if (spend_tx->tx.vin.size() != 1) {
        std::cerr << "Expected single-input spend from change UTXO\n";
        return EXIT_FAILURE;
      }
      if (spend_tx->tx.vin[0].prevout.txid != out_chg.txid ||
          spend_tx->tx.vin[0].prevout.index != out_chg.index) {
        std::cerr << "Coin selection did not prefer change UTXO first\n";
        return EXIT_FAILURE;
      }
    }

    // Dust change suppression: when the natural change is below the wallet's
    // dust threshold, it should be folded into the fee and no change output
    // should be created.
    {
      std::array<std::uint8_t, 32> seed{};
      seed.fill(9);
      auto w = wallet::HDWallet::FromSeedForTools(
          seed, crypto::SignatureAlgorithm::kDilithium);
      if (!w) {
        std::cerr << "Failed to create in-memory wallet for dust test\n";
        return EXIT_FAILURE;
      }
      const auto addr = w->NewAddress();
      auto script = w->ScriptForAddress(addr);
      if (!script) {
        std::cerr << "Failed to derive script for dust test\n";
        return EXIT_FAILURE;
      }

      const primitives::Amount dust =
          primitives::kMiksPerQRY / 10'000ULL;  // must match wallet dust heuristic
      const primitives::Amount utxo_value = 10 * dust;
      const primitives::Amount send_value = utxo_value - (dust / 2);

      primitives::COutPoint out;
      out.txid.fill(0xC3);
      out.index = 0;
      primitives::CTxOut txout;
      txout.value = utxo_value;
      txout.locking_descriptor = *script;
      wallet::WalletUTXO utxo{
          out,
          txout,
          w->KeyIndexForAddress(addr).value(),
          crypto::SignatureAlgorithm::kDilithium,
          false,
          false,
          false,
          false};
      w->AddUTXO(utxo);

      std::vector<std::pair<std::string, primitives::Amount>> send_outputs = {
          {addr, send_value}};
      std::string err;
      auto tx = w->CreateTransaction(send_outputs, /*fee_rate=*/0, &err);
      if (!tx) {
        std::cerr << "Dust test CreateTransaction failed: " << err << "\n";
        return EXIT_FAILURE;
      }
      if (tx->tx.vout.size() != 1) {
        std::cerr << "Dust change should have been absorbed into the fee\n";
        return EXIT_FAILURE;
      }
      if (tx->tx.vout[0].value != send_value) {
        std::cerr << "Unexpected output value in dust test\n";
        return EXIT_FAILURE;
      }
    }

    // Insufficient funds sanity: a wallet with no UTXOs must not produce
    // a transaction and should surface a clear error string.
    {
      std::array<std::uint8_t, 32> seed{};
      seed.fill(11);
      auto w = wallet::HDWallet::FromSeedForTools(
          seed, crypto::SignatureAlgorithm::kDilithium);
      if (!w) {
        std::cerr << "Failed to create in-memory wallet for insufficient-funds test\n";
        return EXIT_FAILURE;
      }
      const auto addr = w->NewAddress();
      std::vector<std::pair<std::string, primitives::Amount>> send_outputs = {
          {addr, 1}};
      std::string err;
      auto tx = w->CreateTransaction(send_outputs, /*fee_rate=*/1, &err);
      if (tx) {
        std::cerr << "Unexpectedly created transaction with no funds\n";
        return EXIT_FAILURE;
      }
      if (err != "insufficient funds") {
        std::cerr << "Unexpected error for insufficient funds: " << err << "\n";
        return EXIT_FAILURE;
      }
    }

    // Watch-only tracking: imported addresses should be monitored as
    // non-spendable balance and excluded from coin selection.
    {
      // Owner wallet that controls a P2QH address.
      std::array<std::uint8_t, 32> seed_owner{};
      seed_owner.fill(13);
      auto owner = wallet::HDWallet::FromSeedForTools(
          seed_owner, crypto::SignatureAlgorithm::kDilithium);
      if (!owner) {
        std::cerr << "Failed to create owner wallet for watch-only test\n";
        return EXIT_FAILURE;
      }
      const auto owner_addr = owner->NewAddress();

      // Separate watching wallet with no corresponding private keys.
      std::array<std::uint8_t, 32> seed_watch{};
      seed_watch.fill(14);
      auto watcher = wallet::HDWallet::FromSeedForTools(
          seed_watch, crypto::SignatureAlgorithm::kDilithium);
      if (!watcher) {
        std::cerr << "Failed to create watch-only wallet\n";
        return EXIT_FAILURE;
      }

      if (!watcher->AddWatchOnlyAddress(owner_addr)) {
        std::cerr << "AddWatchOnlyAddress failed\n";
        return EXIT_FAILURE;
      }

      // Simulate a transaction paying 1 QRY to the owner address and
      // ensure the watching wallet tracks it as watch-only.
      crypto::P2QHDescriptor desc{};
      if (!crypto::DecodeP2QHAddress(
              owner_addr, config::GetNetworkConfig().bech32_hrp, &desc)) {
        std::cerr << "Failed to decode owner address for watch-only test\n";
        return EXIT_FAILURE;
      }
      const primitives::Amount value = primitives::kMiksPerQRY;
      primitives::CTxOut txout;
      txout.value = value;
      txout.locking_descriptor = script::CreateP2QHScript(desc).data;
      primitives::Hash256 txid{};
      txid.fill(0x42);

      if (!watcher->MaybeTrackOutput(txid, /*vout_index=*/0, txout,
                                     /*is_coinbase=*/false)) {
        std::cerr << "Watch-only wallet did not track matching output\n";
        return EXIT_FAILURE;
      }

      if (watcher->GetWatchOnlyBalance() != value) {
        std::cerr << "Unexpected watch-only balance\n";
        return EXIT_FAILURE;
      }
      if (watcher->GetBalance() != 0) {
        std::cerr << "Watch-only funds must not be counted as spendable\n";
        return EXIT_FAILURE;
      }

      const auto& tracked = watcher->TrackedUtxos();
      if (tracked.empty() || !tracked.back().watch_only) {
        std::cerr << "Tracked UTXO is not marked watch-only\n";
        return EXIT_FAILURE;
      }

      // Attempting to create a spend with only watch-only funds must
      // fail with an insufficient-funds error.
      const auto dest_addr = watcher->NewAddress();
      std::vector<std::pair<std::string, primitives::Amount>> send_outputs = {
          {dest_addr, value / 2}};
      std::string err;
      auto spend = watcher->CreateTransaction(send_outputs, /*fee_rate=*/1, &err);
      if (spend) {
        std::cerr << "Unexpectedly created transaction from watch-only funds\n";
        return EXIT_FAILURE;
      }
      if (err != "insufficient funds") {
        std::cerr << "Unexpected error for watch-only spend attempt: " << err
                  << "\n";
        return EXIT_FAILURE;
      }

      // Removing the watch-only address should prevent future outputs
      // to that script from being tracked.
      if (!watcher->RemoveWatchOnlyAddress(owner_addr)) {
        std::cerr << "RemoveWatchOnlyAddress failed\n";
        return EXIT_FAILURE;
      }
      primitives::Hash256 txid2{};
      txid2.fill(0x43);
      if (watcher->MaybeTrackOutput(txid2, 0, txout, /*is_coinbase=*/false)) {
        std::cerr << "Output still tracked after removing watch-only address\n";
        return EXIT_FAILURE;
      }
    }

    auto w_import = wallet::HDWallet::ImportSeedHex(
        mnemonic_wallet_path1, "passmn",
        seed_hex_from_mnemonic,
        crypto::SignatureAlgorithm::kDilithium);
    if (!w_import) {
      std::cerr << "ImportSeedHex from mnemonic-derived seed failed\n";
      return EXIT_FAILURE;
    }

    auto w_mnemonic = wallet::HDWallet::Create(
        mnemonic_wallet_path2, "passmn",
        crypto::SignatureAlgorithm::kDilithium);
    if (!w_mnemonic) {
      std::cerr << "Create for mnemonic wallet failed\n";
      return EXIT_FAILURE;
    }
    if (!w_mnemonic->CreateFromMnemonic(
            mnemonic_wallet_path2, "passmn", mnemonic,
            mnemonic_passphrase,
            crypto::SignatureAlgorithm::kDilithium)) {
      std::cerr << "CreateFromMnemonic failed\n";
      return EXIT_FAILURE;
    }

    if (w_import->ExportSeedHex() != w_mnemonic->ExportSeedHex()) {
      std::cerr << "Mnemonic-based wallet seed mismatch\n";
      return EXIT_FAILURE;
    }

    std::filesystem::remove(mnemonic_wallet_path1);
    std::filesystem::remove(mnemonic_wallet_path2);
  } catch (const std::exception& ex) {
    std::cerr << "wallet_hd_tests exception: " << ex.what() << "\n";
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << "wallet_hd_tests unknown exception\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
