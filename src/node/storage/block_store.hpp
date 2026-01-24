#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "primitives/block.hpp"

namespace qryptcoin::storage {

class BlockStore {
 public:
  explicit BlockStore(std::string path);

  bool Append(const primitives::CBlock& block);
  bool Append(const primitives::CBlock& block, std::uint64_t* out_offset);
  bool ReadAt(std::uint64_t offset, primitives::CBlock* block) const;
  bool ForEach(const std::function<bool(const primitives::CBlock&, std::size_t height,
                                        std::uint64_t offset)>& visitor) const;
  bool Exists() const;

 private:
  std::string path_;
};

}  // namespace qryptcoin::storage
