/**
 * @file unicode.h
 * @brief Definitions for all unicode specific functions.
 */
#ifndef ADA_UNICODE_H
#define ADA_UNICODE_H

#include "ada/common_defs.h"
#include "ada/ada_idna.h"

#include <string>
#include <optional>

/**
 * Unicode operations. These functions are not part of our public API and may
 * change at any time.
 *
 * @private
 * @namespace ada::unicode
 * @brief Includes the definitions for unicode operations
 */
namespace ada::unicode {

/**
 * @private
 * We receive a UTF-8 string representing a domain name.
 * If the string is percent encoded, we apply percent decoding.
 *
 * Given a domain, we need to identify its labels.
 * They are separated by label-separators:
 *
 * U+002E (.) FULL STOP
 * U+FF0E FULLWIDTH FULL STOP
 * U+3002 IDEOGRAPHIC FULL STOP
 * U+FF61 HALFWIDTH IDEOGRAPHIC FULL STOP
 *
 * They are all mapped to U+002E.
 *
 * We process each label into a string that should not exceed 63 octets.
 * If the string is already punycode (starts with "xn--"), then we must
 * scan it to look for unallowed code points.
 * Otherwise, if the string is not pure ASCII, we need to transcode it
 * to punycode by following RFC 3454 which requires us to
 * - Map characters  (see section 3),
 * - Normalize (see section 4),
 * - Reject forbidden characters,
 * - Check for right-to-left characters and if so, check all requirements (see
 * section 6),
 * - Optionally reject based on unassigned code points (section 7).
 *
 * The Unicode standard provides a table of code points with a mapping, a list
 * of forbidden code points and so forth. This table is subject to change and
 * will vary based on the implementation. For Unicode 15, the table is at
 * https://www.unicode.org/Public/idna/15.0.0/IdnaMappingTable.txt
 * If you use ICU, they parse this table and map it to code using a Python
 * script.
 *
 * The resulting strings should not exceed 255 octets according to RFC 1035
 * section 2.3.4. ICU checks for label size and domain size, but these errors
 * are ignored.
 *
 * @see https://url.spec.whatwg.org/#concept-domain-to-ascii
 *
 */
bool to_ascii(std::optional<std::string>& out, std::string_view plain,
              size_t first_percent);

/**
 * @private
 * Checks if the input has tab or newline characters.
 *
 * @attention The has_tabs_or_newline function is a bottleneck and it is simple
 * enough that compilers like GCC can 'autovectorize it'.
 */
ada_really_inline bool has_tabs_or_newline(
    std::string_view user_input) noexcept;

/**
 * @private
 * Checks if the input is a forbidden host code point.
 * @see https://url.spec.whatwg.org/#forbidden-host-code-point
 */
ada_really_inline constexpr bool is_forbidden_host_code_point(char c) noexcept;

/**
 * @private
 * Checks if the input contains a forbidden domain code point.
 * @see https://url.spec.whatwg.org/#forbidden-domain-code-point
 */
ada_really_inline constexpr bool contains_forbidden_domain_code_point(
    const char* input, size_t length) noexcept;

/**
 * @private
 * Checks if the input contains a forbidden domain code point in which case
 * the first bit is set to 1. If the input contains an upper case ASCII letter,
 * then the second bit is set to 1.
 * @see https://url.spec.whatwg.org/#forbidden-domain-code-point
 */
ada_really_inline constexpr uint8_t
contains_forbidden_domain_code_point_or_upper(const char* input,
                                              size_t length) noexcept;

/**
 * @private
 * Checks if the input is a forbidden domain code point.
 * @see https://url.spec.whatwg.org/#forbidden-domain-code-point
 */
ada_really_inline constexpr bool is_forbidden_domain_code_point(
    char c) noexcept;

/**
 * @private
 * Checks if the input is alphanumeric, '+', '-' or '.'
 */
ada_really_inline constexpr bool is_alnum_plus(char c) noexcept;

/**
 * @private
 * @details An ASCII hex digit is an ASCII upper hex digit or ASCII lower hex
 * digit. An ASCII upper hex digit is an ASCII digit or a code point in the
 * range U+0041 (A) to U+0046 (F), inclusive. An ASCII lower hex digit is an
 * ASCII digit or a code point in the range U+0061 (a) to U+0066 (f), inclusive.
 */
ada_really_inline constexpr bool is_ascii_hex_digit(char c) noexcept;

/**
 * @private
 * Checks if the input is a C0 control or space character.
 *
 * @details A C0 control or space is a C0 control or U+0020 SPACE.
 * A C0 control is a code point in the range U+0000 NULL to U+001F INFORMATION
 * SEPARATOR ONE, inclusive.
 */
ada_really_inline constexpr bool is_c0_control_or_space(char c) noexcept;

/**
 * @private
 * Checks if the input is a ASCII tab or newline character.
 *
 * @details An ASCII tab or newline is U+0009 TAB, U+000A LF, or U+000D CR.
 */
ada_really_inline constexpr bool is_ascii_tab_or_newline(char c) noexcept;

/**
 * @private
 * @details A double-dot path segment must be ".." or an ASCII case-insensitive
 * match for ".%2e", "%2e.", or "%2e%2e".
 */
ada_really_inline ada_constexpr bool is_double_dot_path_segment(
    std::string_view input) noexcept;

/**
 * @private
 * @details A single-dot path segment must be "." or an ASCII case-insensitive
 * match for "%2e".
 */
ada_really_inline constexpr bool is_single_dot_path_segment(
    std::string_view input) noexcept;

/**
 * @private
 * @details ipv4 character might contain 0-9 or a-f character ranges.
 */
ada_really_inline constexpr bool is_lowercase_hex(char c) noexcept;

/**
 * @private
 * @details Convert hex to binary. Caller is responsible to ensure that
 * the parameter is an hexadecimal digit (0-9, A-F, a-f).
 */
ada_really_inline unsigned constexpr convert_hex_to_binary(char c) noexcept;

/**
 * @private
 * first_percent should be  = input.find('%')
 *
 * @todo It would be faster as noexcept maybe, but it could be unsafe since.
 * @author Node.js
 * @see https://github.com/nodejs/node/blob/main/src/node_url.cc#L245
 * @see https://encoding.spec.whatwg.org/#utf-8-decode-without-bom
 */
std::string percent_decode(std::string_view input, size_t first_percent);

/**
 * @private
 * Returns a percent-encoding string whether percent encoding was needed or not.
 * @see https://github.com/nodejs/node/blob/main/src/node_url.cc#L226
 */
std::string percent_encode(std::string_view input,
                           const uint8_t character_set[]);
/**
 * @private
 * Returns a percent-encoded string version of input, while starting the percent
 * encoding at the provided index.
 * @see https://github.com/nodejs/node/blob/main/src/node_url.cc#L226
 */
std::string percent_encode(std::string_view input,
                           const uint8_t character_set[], size_t index);
/**
 * @private
 * Returns true if percent encoding was needed, in which case, we store
 * the percent-encoded content in 'out'. If the boolean 'append' is set to
 * true, the content is appended to 'out'.
 * If percent encoding is not needed, out is left unchanged.
 * @see https://github.com/nodejs/node/blob/main/src/node_url.cc#L226
 */
template <bool append>
bool percent_encode(std::string_view input, const uint8_t character_set[],
                    std::string& out);
/**
 * @private
 * Returns the index at which percent encoding should start, or (equivalently),
 * the length of the prefix that does not require percent encoding.
 */
ada_really_inline size_t percent_encode_index(std::string_view input,
                                              const uint8_t character_set[]);
/**
 * @private
 * Lowers the string in-place, assuming that the content is ASCII.
 * Return true if the content was ASCII.
 */
constexpr bool to_lower_ascii(char* input, size_t length) noexcept;
}  // namespace ada::unicode

#endif  // ADA_UNICODE_H
