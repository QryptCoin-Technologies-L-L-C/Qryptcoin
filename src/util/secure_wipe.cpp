#include "util/secure_wipe.hpp"

#include <cstring>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace qryptcoin::util {

void SecureWipe(void* data, std::size_t size) noexcept {
  if (data == nullptr || size == 0) {
    return;
  }
#ifdef _WIN32
  SecureZeroMemory(data, size);
#elif defined(__STDC_LIB_EXT1__)
  (void)memset_s(data, size, 0, size);
#else
  volatile std::uint8_t* ptr = reinterpret_cast<volatile std::uint8_t*>(data);
  while (size--) {
    *ptr++ = 0;
  }
#endif
}

}  // namespace qryptcoin::util

