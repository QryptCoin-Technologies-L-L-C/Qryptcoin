#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <span>
#include <string>

namespace qryptcoin::util {

// Atomically replace `path` by writing to a temp file in the same directory and
// renaming it into place. The writer must write the full contents to the stream
// and return true on success.
bool AtomicWriteFile(const std::filesystem::path& path,
                     const std::function<bool(std::ofstream&)>& writer,
                     std::string* error = nullptr);

// Convenience wrapper for writing a byte span atomically.
bool AtomicWriteFileBytes(const std::filesystem::path& path,
                          std::span<const std::uint8_t> data,
                          std::string* error = nullptr);

}  // namespace qryptcoin::util

