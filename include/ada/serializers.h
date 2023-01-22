/**
 * @file serializers.h
 * @brief Definitions for the URL serializers.
 */
#ifndef ADA_SERIALIZERS_H
#define ADA_SERIALIZERS_H

#include "ada/common_defs.h"

#include <array>
#include <optional>
#include <string>

namespace ada::serializers {

  /**
   * Finds and returns the longest sequence of 0 values in a ipv6 input.
   *
   * @returns -1 if not found.
   */
  size_t find_longest_sequence_of_ipv6_pieces(const std::array<uint16_t, 8>& address) noexcept;

  /**
   * Serializes an ipv6 address.
   * @details An IPv6 address is a 128-bit unsigned integer that identifies a network address.
   * @see https://url.spec.whatwg.org/#concept-ipv6-serializer
   */
  std::string ipv6(const std::array<uint16_t, 8>& address) noexcept;

  /**
   * Serializes an ipv4 address.
   * @details An IPv4 address is a 32-bit unsigned integer that identifies a network address.
   * @see https://url.spec.whatwg.org/#concept-ipv4-serializer
   */
  std::string ipv4(const uint64_t address) noexcept;

} // namespace ada::serializers

#endif // ADA_SERIALIZERS_H
