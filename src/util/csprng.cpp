#include "util/csprng.hpp"

#include <cstdlib>
#include <cstring>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

namespace qryptcoin::util {

bool FillSecureRandomBytes(std::span<std::uint8_t> out, std::string* error) {
  if (out.empty()) {
    return true;
  }

#ifdef _WIN32
  const NTSTATUS status =
      BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status != 0) {
    if (error) {
      *error = "BCryptGenRandom failed";
    }
    return false;
  }
  return true;
#else
  std::size_t filled = 0;
#if defined(__linux__)
  while (filled < out.size()) {
    const ssize_t n = getrandom(out.data() + filled, out.size() - filled, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    filled += static_cast<std::size_t>(n);
  }
  if (filled == out.size()) {
    return true;
  }
#endif

  const int fd = ::open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    if (error) {
      *error = std::string("open(/dev/urandom) failed: ") + std::strerror(errno);
    }
    return false;
  }
  while (filled < out.size()) {
    const ssize_t n = ::read(fd, out.data() + filled, out.size() - filled);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      ::close(fd);
      if (error) {
        *error = std::string("read(/dev/urandom) failed: ") + std::strerror(errno);
      }
      return false;
    }
    if (n == 0) {
      ::close(fd);
      if (error) {
        *error = "read(/dev/urandom) returned EOF";
      }
      return false;
    }
    filled += static_cast<std::size_t>(n);
  }
  ::close(fd);
  return true;
#endif
}

void FillSecureRandomBytesOrAbort(std::span<std::uint8_t> out) {
  std::string err;
  if (!FillSecureRandomBytes(out, &err)) {
    // Secure randomness is a hard requirement for keys, nonces, and wallet
    // material. Failing closed avoids accidentally creating deterministic keys.
    std::abort();
  }
}

std::vector<std::uint8_t> SecureRandomBytes(std::size_t size) {
  std::vector<std::uint8_t> out(size);
  FillSecureRandomBytesOrAbort(out);
  return out;
}

}  // namespace qryptcoin::util
