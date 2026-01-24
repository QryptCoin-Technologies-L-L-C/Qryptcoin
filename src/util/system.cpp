#include "util/system.hpp"

#include <sstream>

namespace qryptcoin::util {

namespace {
constexpr const char* DetectPlatform() {
#if defined(_WIN32)
  return "Windows";
#elif defined(__APPLE__)
  return "macOS";
#elif defined(__linux__)
  return "Linux";
#else
  return "Unknown";
#endif
}
}  // namespace

std::string PlatformSummary() {
  std::ostringstream ss;
  ss << DetectPlatform() << " | C++" << __cplusplus;
#ifdef NDEBUG
  ss << " | Release";
#else
  ss << " | Debug";
#endif
  return ss.str();
}

}  // namespace qryptcoin::util

