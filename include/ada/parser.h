/**
 * @file parser.h
 * @brief Definitions for the parser.
 */
#ifndef ADA_PARSER_H
#define ADA_PARSER_H

#include <string_view>
#include <variant>

#include "ada/expected.h"
#include "ada/url_pattern_regex.h"

/**
 * @private
 */
namespace ada {
struct url_aggregator;
struct url;
template <url_pattern_regex::regex_concept regex_provider>
class url_pattern;
struct url_pattern_options;
struct url_pattern_init;
enum class errors : uint8_t;
}  // namespace ada

/**
 * @namespace ada::parser
 * @brief Includes the definitions for supported parsers
 */
namespace ada::parser {
/**
 * Parses a url. The parameter user_input is the input to be parsed:
 * it should be a valid UTF-8 string. The parameter base_url is an optional
 * parameter that can be used to resolve relative URLs. If the base_url is
 * provided, the user_input is resolved against the base_url.
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

extern template url_aggregator parse_url_impl<url_aggregator>(
    std::string_view user_input, const url_aggregator* base_url);
extern template url parse_url_impl<url>(std::string_view user_input,
                                        const url* base_url);

template <url_pattern_regex::regex_concept regex_provider>
tl::expected<url_pattern<regex_provider>, errors> parse_url_pattern_impl(
    std::variant<std::string_view, url_pattern_init> input,
    const std::string_view* base_url, const url_pattern_options* options,
    regex_provider&& provider);

}  // namespace ada::parser

#endif  // ADA_PARSER_H
