#ifndef ADA_SERIALIZERS_H
#define ADA_SERIALIZERS_H

#include "ada/common_defs.h"

#include <array>
#include <optional>
#include <string>

namespace ada::serializers {

  size_t find_longest_sequence_of_ipv6_pieces(const std::array<uint16_t, 8>& address) noexcept;

  // An IPv6 address is a 128-bit unsigned integer that identifies a network address.
  std::string ipv6(const std::array<uint16_t, 8>& address) noexcept;

  // An IPv4 address is a 32-bit unsigned integer that identifies a network address.
  std::string ipv4(const uint64_t address) noexcept;

} // namespace ada::serializers

#endif // ADA_SERIALIZERS_H
