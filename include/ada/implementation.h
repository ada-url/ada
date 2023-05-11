/**
 * @file implementation.h
 * @brief Definitions for user facing functions for parsing URL and it's
 * components.
 */
#ifndef ADA_IMPLEMENTATION_H
#define ADA_IMPLEMENTATION_H

#include <string>
#include <optional>

#include "ada/parser.h"
#include "ada/common_defs.h"
#include "ada/encoding_type.h"
#include "ada/url.h"
#include "ada/state.h"
#include "ada/url_aggregator.h"

namespace ada {
enum class errors { generic_error };

template <class result_type = ada::url_aggregator>
using result = tl::expected<result_type, ada::errors>;

/**
 * The URL parser takes a scalar value string input, with an optional null or
 * base URL base (default null). The parser assumes the input is a valid ASCII
 * or UTF-8 string.
 *
 * @param input the string input to analyze (must be valid ASCII or UTF-8)
 * @param base_url the optional URL input to use as a base url.
 * @return a parsed URL.
 */
template <class result_type = ada::url_aggregator>
ada_warn_unused ada::result<result_type> parse(
    std::string_view input, const result_type* base_url = nullptr);

extern template ada::result<url> parse<url>(std::string_view input,
                                            const url* base_url);
extern template ada::result<url_aggregator> parse<url_aggregator>(
    std::string_view input, const url_aggregator* base_url);

/**
 * Verifies whether the URL strings can be parsed. The function assumes
 * that the inputs are valid ASCII or UTF-8 strings.
 * @see https://url.spec.whatwg.org/#dom-url-canparse
 * @return If URL can be parsed or not.
 */
bool can_parse(std::string_view input,
               const std::string_view* base_input = nullptr);

/**
 * Computes a href string from a file path. The function assumes
 * that the input is a valid ASCII or UTF-8 string.
 * @return a href string (starts with file:://)
 */
std::string href_from_file(std::string_view path);
}  // namespace ada

#endif  // ADA_IMPLEMENTATION_H
