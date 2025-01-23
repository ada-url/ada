/**
 * @file implementation-inl.h
 */
#ifndef ADA_IMPLEMENTATION_INL_H
#define ADA_IMPLEMENTATION_INL_H

#include "ada/url_pattern_regex.h"
#include "ada/expected.h"
#include "ada/implementation.h"

#include <variant>
#include <string_view>

namespace ada {

template <url_pattern_regex::regex_concept regex_provider>
ada_warn_unused tl::expected<url_pattern<regex_provider>, errors>
parse_url_pattern(std::variant<std::string_view, url_pattern_init> input,
                  const std::string_view* base_url,
                  const url_pattern_options* options) {
  return parser::parse_url_pattern_impl<regex_provider>(std::move(input),
                                                        base_url, options);
}

}  // namespace ada

#endif  // ADA_IMPLEMENTATION_INL_H
