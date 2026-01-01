/**
 * @file checkers.h
 * @brief Declarations for URL specific checkers used within Ada.
 */
#ifndef ADA_CHECKERS_H
#define ADA_CHECKERS_H

#include "ada/common_defs.h"

#include <cstring>
#include <string_view>

/**
 * These functions are not part of our public API and may
 * change at any time.
 * @private
 * @namespace ada::checkers
 * @brief Includes the definitions for validation functions
 */
namespace ada::checkers {

/**
 * @private
 * Assuming that x is an ASCII letter, this function returns the lower case
 * equivalent.
 * @details More likely to be inlined by the compiler and constexpr.
 */
constexpr char to_lower(char x) noexcept;

/**
 * @private
 * Returns true if the character is an ASCII letter. Equivalent to std::isalpha
 * but more likely to be inlined by the compiler.
 *
 * @attention std::isalpha is not constexpr generally.
 */
constexpr bool is_alpha(char x) noexcept;

/**
 * @private
 * Check whether a string starts with 0x or 0X. The function is only
 * safe if input.size() >=2.
 *
 * @see has_hex_prefix
 */
constexpr bool has_hex_prefix_unsafe(std::string_view input);
/**
 * @private
 * Check whether a string starts with 0x or 0X.
 */
constexpr bool has_hex_prefix(std::string_view input);

/**
 * @private
 * Check whether x is an ASCII digit. More likely to be inlined than
 * std::isdigit.
 */
constexpr bool is_digit(char x) noexcept;

/**
 * @private
 * @details A string starts with a Windows drive letter if all of the following
 * are true:
 *
 *   - its length is greater than or equal to 2
 *   - its first two code points are a Windows drive letter
 *   - its length is 2 or its third code point is U+002F (/), U+005C (\), U+003F
 * (?), or U+0023 (#).
 *
 * https://url.spec.whatwg.org/#start-with-a-windows-drive-letter
 */
inline constexpr bool is_windows_drive_letter(std::string_view input) noexcept;

/**
 * @private
 * @details A normalized Windows drive letter is a Windows drive letter of which
 * the second code point is U+003A (:).
 */
inline constexpr bool is_normalized_windows_drive_letter(
    std::string_view input) noexcept;

/**
 * @private
 * Returns true if an input is an ipv4 address. It is assumed that the string
 * does not contain uppercase ASCII characters (the input should have been
 * lowered cased before calling this function) and is not empty.
 */
ada_really_inline constexpr bool is_ipv4(std::string_view view) noexcept;

/**
 * @private
 * Returns a bitset. If the first bit is set, then at least one character needs
 * percent encoding. If the second bit is set, a \\ is found. If the third bit
 * is set then we have a dot. If the fourth bit is set, then we have a percent
 * character.
 */
ada_really_inline constexpr uint8_t path_signature(
    std::string_view input) noexcept;

/**
 * @private
 * Returns true if the length of the domain name and its labels are according to
 * the specifications. The length of the domain must be 255 octets (253
 * characters not including the last 2 which are the empty label reserved at the
 * end). When the empty label is included (a dot at the end), the domain name
 * can have 254 characters. The length of a label must be at least 1 and at most
 * 63 characters.
 * @see section 3.1. of https://www.rfc-editor.org/rfc/rfc1034
 * @see https://www.unicode.org/reports/tr46/#ToASCII
 */
ada_really_inline constexpr bool verify_dns_length(
    std::string_view input) noexcept;

/**
 * @private
 * Fast-path parser for pure decimal IPv4 addresses (e.g., "192.168.1.1").
 * Returns the packed 32-bit IPv4 address on success, or a value > 0xFFFFFFFF
 * to indicate failure (caller should fall back to general parser).
 * This is optimized for the common case where the input is a well-formed
 * decimal IPv4 address with exactly 4 octets.
 */
ada_really_inline constexpr uint64_t try_parse_ipv4_fast(
    std::string_view input) noexcept;

/**
 * Sentinel value indicating try_parse_ipv4_fast() did not succeed.
 * Any value > 0xFFFFFFFF indicates the fast path should not be used.
 */
constexpr uint64_t ipv4_fast_fail = uint64_t(1) << 32;

}  // namespace ada::checkers

#endif  // ADA_CHECKERS_H
