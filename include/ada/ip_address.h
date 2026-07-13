/**
 * @file ip_address.h
 * @brief Shared IPv4/IPv6 parsing and serialization helpers (internal).
 *
 * These functions are not part of the public API and may change at any time.
 */
#ifndef ADA_IP_ADDRESS_H
#define ADA_IP_ADDRESS_H

#include "ada/common_defs.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace ada::ip_address {

/**
 * Parse a WHATWG IPv4 host string into a 32-bit address.
 * On success returns true and writes the packed address to @p address.
 * @p pure_decimal_count is set to the number of pure-decimal segments
 * (used by callers to avoid re-serialization when the input is already
 * canonical dotted-decimal).
 * @p had_trailing_dot is set when the input ended with '.'.
 */
[[nodiscard]] bool parse_ipv4(std::string_view input, uint32_t& address,
                              int& pure_decimal_count,
                              bool& had_trailing_dot) noexcept;

/**
 * Parse a WHATWG IPv6 host string (without surrounding brackets) into
 * eight 16-bit pieces. Returns true on success.
 */
[[nodiscard]] bool parse_ipv6(std::string_view input,
                              std::array<uint16_t, 8>& address) noexcept;

/**
 * Write dotted-decimal IPv4 into @p out. Requires at least 15 bytes.
 * Returns the number of bytes written (no null terminator).
 */
[[nodiscard]] size_t serialize_ipv4_to(uint32_t address, char* out) noexcept;

/**
 * Write compressed lowercase IPv6 (without brackets) into @p out.
 * Requires at least 39 bytes. Returns the number of bytes written.
 */
[[nodiscard]] size_t serialize_ipv6_to(const std::array<uint16_t, 8>& address,
                                       char* out) noexcept;

/**
 * Convenience wrappers that allocate a std::string (for callers that need it).
 */
[[nodiscard]] std::string serialize_ipv4(uint32_t address);
[[nodiscard]] std::string serialize_ipv6(
    const std::array<uint16_t, 8>& address);

/**
 * Returns true when @p serialized matches the canonical serialization of
 * @p address (used for in-place host buffer optimization).
 */
[[nodiscard]] bool ipv4_is_canonical(std::string_view serialized,
                                     uint32_t address) noexcept;
[[nodiscard]] bool ipv6_is_canonical(
    std::string_view serialized,
    const std::array<uint16_t, 8>& address) noexcept;

}  // namespace ada::ip_address

#endif  // ADA_IP_ADDRESS_H
