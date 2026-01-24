#include "util/atomic_file.hpp"

#include <atomic>
#include <chrono>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#endif

namespace qryptcoin::util {

namespace {

std::atomic<std::uint64_t> g_temp_counter{0};

std::filesystem::path MakeTempPath(const std::filesystem::path& target) {
  const auto nonce = g_temp_counter.fetch_add(1, std::memory_order_relaxed);
  const auto now =
      std::chrono::steady_clock::now().time_since_epoch().count();
  std::string tmp_name =
      target.filename().string() + ".tmp." + std::to_string(now) + "." + std::to_string(nonce);
  return target.parent_path() / tmp_name;
}

bool ReplaceFile(const std::filesystem::path& from, const std::filesystem::path& to,
                 std::string* error) {
#ifdef _WIN32
  const std::wstring from_w = from.wstring();
  const std::wstring to_w = to.wstring();
  if (!MoveFileExW(from_w.c_str(), to_w.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    if (error) {
      *error = "MoveFileExW failed";
    }
    return false;
  }
  return true;
#else
  std::error_code ec;
  std::filesystem::rename(from, to, ec);
  if (!ec) {
    return true;
  }
  // Some standard library implementations may refuse to replace an
  // existing destination; fall back to an explicit remove+rename.
  std::filesystem::remove(to, ec);
  ec.clear();
  std::filesystem::rename(from, to, ec);
  if (ec) {
    if (error) {
      *error = "rename failed: " + ec.message();
    }
    return false;
  }
  return true;
#endif
}

}  // namespace

bool AtomicWriteFile(const std::filesystem::path& path,
                     const std::function<bool(std::ofstream&)>& writer,
                     std::string* error) {
  const auto parent = path.parent_path();
  if (!parent.empty()) {
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    if (ec) {
      if (error) {
        *error = "create_directories failed: " + ec.message();
      }
      return false;
    }
  }

  const auto tmp_path = MakeTempPath(path);
  {
    std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
      if (error) {
        *error = "failed to open temp file for write";
      }
      return false;
    }
    if (!writer(out)) {
      out.close();
      std::error_code ec;
      std::filesystem::remove(tmp_path, ec);
      if (error && error->empty()) {
        *error = "writer failed";
      }
      return false;
    }
    out.flush();
    if (!out.good()) {
      out.close();
      std::error_code ec;
      std::filesystem::remove(tmp_path, ec);
      if (error) {
        *error = "flush failed";
      }
      return false;
    }
  }

  if (!ReplaceFile(tmp_path, path, error)) {
    std::error_code ec;
    std::filesystem::remove(tmp_path, ec);
    return false;
  }
  return true;
}

bool AtomicWriteFileBytes(const std::filesystem::path& path,
                          std::span<const std::uint8_t> data,
                          std::string* error) {
  return AtomicWriteFile(
      path,
      [&](std::ofstream& out) -> bool {
        if (!data.empty()) {
          out.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size()));
        }
        return out.good();
      },
      error);
}

}  // namespace qryptcoin::util

