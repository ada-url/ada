/**
 * @file parser.h
 * @brief Low-level URL parsing functions.
 *
 * This header provides the internal URL parsing implementation. Most users
 * should use `ada::parse()` from implementation.h instead of these functions
 * directly.
 *
 * @see implementation.h for the recommended public API
 */
#ifndef ADA_PARSER_H
#define ADA_PARSER_H

#include <string_view>
#include <variant>

#include "ada/expected.h"
#include "ada/scheme.h"
#include "ada/url_base.h"

#include "ada/url_pattern_regex.h"
#include "ada/url_pattern_init.h"

/** @private Forward declarations */
namespace ada {
struct url_aggregator;
struct url;
#if ADA_INCLUDE_URL_PATTERN
template <url_pattern_regex::regex_concept regex_provider>
class url_pattern;
struct url_pattern_options;
#endif  // ADA_INCLUDE_URL_PATTERN
enum class errors : uint8_t;
}  // namespace ada

/**
 * @namespace ada::parser
 * @brief Internal URL parsing implementation.
 *
 * Contains the core URL parsing algorithm as specified by the WHATWG URL
 * Standard. These functions are used internally by `ada::parse()`.
 */
namespace ada::parser {
/**
 * Parses a URL string into a URL object.
 *
 * @tparam result_type The type of URL object to create (url or url_aggregator).
 *
 * @param user_input The URL string to parse (must be valid UTF-8).
 * @param base_url Optional base URL for resolving relative URLs.
 *
 * @return The parsed URL object. Check `is_valid` to determine if parsing
 *         succeeded.
 *
 * @see https://url.spec.whatwg.org/#concept-basic-url-parser
 */
template <typename result_type = url_aggregator>
result_type parse_url(std::string_view user_input,
                      const result_type* base_url = nullptr);

extern template url_aggregator parse_url<url_aggregator>(
    std::string_view user_input, const url_aggregator* base_url);
extern template url parse_url<url>(std::string_view user_input,
                                   const url* base_url);

template <typename result_type = url_aggregator, bool store_values = true>
result_type parse_url_impl(std::string_view user_input,
                           const result_type* base_url = nullptr);

extern template url_aggregator parse_url_impl<url_aggregator, true>(
    std::string_view user_input, const url_aggregator* base_url);
extern template url_aggregator parse_url_impl<url_aggregator, false>(
    std::string_view user_input, const url_aggregator* base_url);
extern template url parse_url_impl<url, true>(std::string_view user_input,
                                              const url* base_url);

/** @private Fill `url` in place. `try_fast_path` is false when parse()
 *  already ran try_parse_simple_absolute. */
template <typename result_type, bool store_values = true>
result_type& parse_url_impl_into(result_type& url, std::string_view user_input,
                                 const result_type* base_url,
                                 bool try_fast_path);

extern template url_aggregator& parse_url_impl_into<url_aggregator, true>(
    url_aggregator& out, std::string_view user_input,
    const url_aggregator* base_url, bool try_fast_path);
extern template url_aggregator& parse_url_impl_into<url_aggregator, false>(
    url_aggregator& out, std::string_view user_input,
    const url_aggregator* base_url, bool try_fast_path);
extern template url& parse_url_impl_into<url, true>(url& out,
                                                    std::string_view user_input,
                                                    const url* base_url,
                                                    bool try_fast_path);

/** @private */
template <class result_type>
bool try_parse_simple_absolute(std::string_view input, result_type& out);

/** @private */
template <class result_type>
bool finish_simple_absolute_with_port(std::string_view input, result_type& out,
                                      ada::scheme::type scheme_type,
                                      uint32_t protocol_end, size_t host_start,
                                      size_t host_end, size_t host_len,
                                      bool has_upper);

/** @private Write a host that is not a slice of `input` (canonical IPv4/IPv6).
 */
template <class result_type>
bool finish_simple_absolute_literal_host(
    std::string_view input, result_type& out, ada::scheme::type scheme_type,
    uint32_t protocol_end, size_t host_start, size_t host_end,
    std::string_view host, url_host_type parsed_host_type);

/** @private Cold already-canonical userinfo finish (`user[:pass]@host`). */
template <class result_type>
bool try_finish_simple_userinfo(std::string_view input, result_type& out,
                                ada::scheme::type scheme_type,
                                uint32_t protocol_end, size_t auth_start);

/** @private Cold bracket-IPv6 finish after the host scanner misses on '['. */
template <class result_type>
bool try_finish_simple_ipv6(std::string_view input, result_type& out,
                            ada::scheme::type scheme_type,
                            uint32_t protocol_end, size_t host_start);

/** @private Cold rest_simple=false tail; kept out of the hot I-cache. */
template <class result_type>
void finish_simple_absolute_handoff(std::string_view input, result_type& out,
                                    size_t host_start, size_t host_end,
                                    size_t host_len, uint32_t protocol_end,
                                    bool has_upper, bool has_path,
                                    size_t path_start, size_t path_end,
                                    size_t query_start, size_t hash_start);

/** @private */
template <class result_type>
bool try_parse_simple_relative(std::string_view input, const result_type& base,
                               result_type& out);

#if ADA_INCLUDE_URL_PATTERN
template <url_pattern_regex::regex_concept regex_provider>
tl::expected<url_pattern<regex_provider>, errors> parse_url_pattern_impl(
    std::variant<std::string_view, url_pattern_init>&& input,
    const std::string_view* base_url, const url_pattern_options* options);
#endif  // ADA_INCLUDE_URL_PATTERN

}  // namespace ada::parser

#endif  // ADA_PARSER_H
