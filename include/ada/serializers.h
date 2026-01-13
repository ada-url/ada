/**
 * @file serializers.h
 * @brief IP address serialization utilities.
 *
 * This header provides functions for converting IP addresses to their
 * string representations according to the WHATWG URL Standard.
 */
#ifndef ADA_SERIALIZERS_H
#define ADA_SERIALIZERS_H

#include "ada/common_defs.h"

#include <array>
#include <string>

/**
 * @namespace ada::serializers
 * @brief IP address serialization functions.
 *
 * Contains utilities for serializing IPv4 and IPv6 addresses to strings.
 */
namespace ada::serializers {

/**
 * Finds the longest consecutive sequence of zero pieces in an IPv6 address.
 * Used for :: compression in IPv6 serialization.
 *
 * @param address The 8 16-bit pieces of the IPv6 address.
 * @param[out] compress Index of the start of the longest zero sequence.
 * @param[out] compress_length Length of the longest zero sequence.
 */
void find_longest_sequence_of_ipv6_pieces(
    const std::array<uint16_t, 8>& address, size_t& compress,
    size_t& compress_length) noexcept;

/**
 * Serializes an IPv6 address to its string representation.
 *
 * @param address The 8 16-bit pieces of the IPv6 address.
 * @return The serialized IPv6 string (e.g., "2001:db8::1").
 * @see https://url.spec.whatwg.org/#concept-ipv6-serializer
 */
std::string ipv6(const std::array<uint16_t, 8>& address);

/**
 * Serializes an IPv4 address to its dotted-decimal string representation.
 *
 * @param address The 32-bit IPv4 address as an integer.
 * @return The serialized IPv4 string (e.g., "192.168.1.1").
 * @see https://url.spec.whatwg.org/#concept-ipv4-serializer
 */
std::string ipv4(uint64_t address);

}  // namespace ada::serializers

#endif  // ADA_SERIALIZERS_H
