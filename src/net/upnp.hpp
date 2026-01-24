#pragma once

#include <cstdint>
#include <string>

namespace qryptcoin::net {

// Placeholder UPnP integration hook. In the current tree this simply
// returns false so that inbound connectivity gracefully falls back to
// outbound-only mode. When linked against a UPnP client library such
// as miniupnpc, this function can be extended to attempt an actual
// port mapping and report the discovered external address.
bool TryMapPort(std::uint16_t port, std::string* external_address);

}  // namespace qryptcoin::net

