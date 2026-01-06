/**
 * @file implementation.h
 * @brief User-facing functions for URL parsing and manipulation.
 *
 * This header provides the primary public API for parsing URLs in Ada.
 * It includes the main `ada::parse()` function which is the recommended
 * entry point for most users.
 *
 * @see https://url.spec.whatwg.org/#api
 */
#ifndef ADA_IMPLEMENTATION_H
#define ADA_IMPLEMENTATION_H

#include <string>
#include <string_view>
#include <optional>

#include "ada/url.h"
#include "ada/common_defs.h"
#include "ada/errors.h"
#include "ada/url_pattern_init.h"

namespace ada {

/**
 * Result type for URL parsing operations.
 *
 * Uses `tl::expected` to represent either a successfully parsed URL or an
 * error. This allows for exception-free error handling.
 *
 * @tparam result_type The URL type to return (default: `ada::url_aggregator`)
 *
 * @example
 * ```cpp
 * ada::result<ada::url_aggregator> result = ada::parse("https://example.com");
 * if (result) {
 *     // Success: use result.value() or *result
 * } else {
 *     // Error: handle result.error()
 * }
 * ```
 */
template <class result_type = ada::url_aggregator>
using result = tl::expected<result_type, ada::errors>;

/**
 * Parses a URL string according to the WHATWG URL Standard.
 *
 * This is the main entry point for URL parsing in Ada. The function takes
 * a string input and optionally a base URL for resolving relative URLs.
 *
 * @tparam result_type The URL type to return. Can be either `ada::url` or
 *         `ada::url_aggregator` (default). The `url_aggregator` type is more
 *         memory-efficient as it stores components as offsets into a single
 *         buffer.
 *
 * @param input The URL string to parse. Must be valid ASCII or UTF-8 encoded.
 *        Leading and trailing whitespace is automatically trimmed.
 * @param base_url Optional pointer to a base URL for resolving relative URLs.
 *        If nullptr (default), only absolute URLs can be parsed successfully.
 *
 * @return A `result<result_type>` containing either the parsed URL on success,
 *         or an error code on failure. Use the boolean conversion or
 *         `has_value()` to check for success.
 *
 * @note The parser is fully compliant with the WHATWG URL Standard.
 *
 * @example
 * ```cpp
 * // Parse an absolute URL
 * auto url = ada::parse("https://user:pass@example.com:8080/path?query#hash");
 * if (url) {
 *     std::cout << url->get_hostname(); // "example.com"
 *     std::cout << url->get_pathname(); // "/path"
 * }
 *
 * // Parse a relative URL with a base
 * auto base = ada::parse("https://example.com/dir/");
 * if (base) {
 *     auto relative = ada::parse("../other/page", &*base);
 *     if (relative) {
 *         std::cout << relative->get_href(); //
 * "https://example.com/other/page"
 *     }
 * }
 * ```
 *
 * @see https://url.spec.whatwg.org/#url-parsing
 */
template <class result_type = ada::url_aggregator>
ada_warn_unused ada::result<result_type> parse(
    std::string_view input, const result_type* base_url = nullptr);

extern template ada::result<url> parse<url>(std::string_view input,
                                            const url* base_url);
extern template ada::result<url_aggregator> parse<url_aggregator>(
    std::string_view input, const url_aggregator* base_url);

/**
 * Checks whether a URL string can be successfully parsed.
 *
 * This is a fast validation function that checks if a URL string is valid
 * according to the WHATWG URL Standard without fully constructing a URL
 * object. Use this when you only need to validate URLs without needing
 * their parsed components.
 *
 * @param input The URL string to validate. Must be valid ASCII or UTF-8.
 * @param base_input Optional pointer to a base URL string for resolving
 *        relative URLs. If nullptr (default), the input is validated as
 *        an absolute URL.
 *
 * @return `true` if the URL can be parsed successfully, `false` otherwise.
 *
 * @example
 * ```cpp
 * // Check absolute URL
 * bool valid = ada::can_parse("https://example.com"); // true
 * bool invalid = ada::can_parse("not a url");         // false
 *
 * // Check relative URL with base
 * std::string_view base = "https://example.com/";
 * bool relative_valid = ada::can_parse("../path", &base); // true
 * ```
 *
 * @see https://url.spec.whatwg.org/#dom-url-canparse
 */
bool can_parse(std::string_view input,
               const std::string_view* base_input = nullptr);

#if ADA_INCLUDE_URL_PATTERN
/**
 * Parses a URL pattern according to the URLPattern specification.
 *
 * URL patterns provide a syntax for matching URLs against patterns, similar
 * to how regular expressions match strings. This is useful for routing and
 * URL-based dispatching.
 *
 * @tparam regex_provider The regex implementation to use for pattern matching.
 *
 * @param input Either a URL pattern string (valid UTF-8) or a URLPatternInit
 *        struct specifying individual component patterns.
 * @param base_url Optional pointer to a base URL string (valid UTF-8) for
 *        resolving relative patterns.
 * @param options Optional pointer to configuration options (e.g., ignore_case).
 *
 * @return A `tl::expected` containing either the parsed url_pattern on success,
 *         or an error code on failure.
 *
 * @see https://urlpattern.spec.whatwg.org
 */
template <url_pattern_regex::regex_concept regex_provider>
ada_warn_unused tl::expected<url_pattern<regex_provider>, errors>
parse_url_pattern(std::variant<std::string_view, url_pattern_init>&& input,
                  const std::string_view* base_url = nullptr,
                  const url_pattern_options* options = nullptr);
#endif  // ADA_INCLUDE_URL_PATTERN

/**
 * Converts a file system path to a file:// URL.
 *
 * Creates a properly formatted file URL from a local file system path.
 * Handles platform-specific path separators and percent-encoding.
 *
 * @param path The file system path to convert. Must be valid ASCII or UTF-8.
 *
 * @return A file:// URL string representing the given path.
 */
std::string href_from_file(std::string_view path);
}  // namespace ada

#endif  // ADA_IMPLEMENTATION_H
