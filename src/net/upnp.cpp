#include "net/upnp.hpp"

namespace qryptcoin::net {

bool TryMapPort(std::uint16_t, std::string* external_address) {
  if (external_address) {
    external_address->clear();
  }
  // Stub implementation: real UPnP support can be wired in later.
  return false;
}

}  // namespace qryptcoin::net

