/**
 * @file checkers.h
 * @brief Declarations for URL specific checkers used within Ada.
 */
#ifndef ADA_CHECKERS_H
#define ADA_CHECKERS_H

#include "ada/common_defs.h"

#include <string_view>
#include <cstring>

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
inline bool has_hex_prefix_unsafe(std::string_view input);
/**
 * @private
 * Check whether a string starts with 0x or 0X.
 */
inline bool has_hex_prefix(std::string_view input);

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
 * @warning Will be removed when Ada requires C++20.
 */
ada_really_inline bool begins_with(std::string_view view,
                                   std::string_view prefix);

/**
 * @private
 * Returns true if an input is an ipv4 address. It is assumed that the string
 * does not contain uppercase ASCII characters (the input should have been
 * lowered cased before calling this function) and is not empty.
 */
ada_really_inline ada_constexpr bool is_ipv4(std::string_view view) noexcept;

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

}  // namespace ada::checkers

#endif  // ADA_CHECKERS_H
