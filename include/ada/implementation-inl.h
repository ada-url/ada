/**
 * @file implementation-inl.h
 */
#ifndef ADA_IMPLEMENTATION_INL_H
#define ADA_IMPLEMENTATION_INL_H

#include "ada/url_pattern_regex.h"

#include "ada/expected.h"
#include "ada/implementation.h"
#include "ada/url_pattern_list.h"

#include <variant>
#include <string_view>

namespace ada {

#if ADA_INCLUDE_URL_PATTERN
template <url_pattern_regex::regex_concept regex_provider>
ada_warn_unused tl::expected<url_pattern<regex_provider>, errors>
parse_url_pattern(std::variant<std::string_view, url_pattern_init>&& input,
                  const std::string_view* base_url,
                  const url_pattern_options* options) {
  return parser::parse_url_pattern_impl<regex_provider>(std::move(input),
                                                        base_url, options);
}

template <url_pattern_regex::regex_concept regex_provider>
ada_warn_unused tl::expected<url_pattern_list<regex_provider>, errors>
parse_url_pattern_list(std::span<const std::string_view> pathname_patterns,
                       const std::string_view* base_url,
                       const url_pattern_options* options) {
  std::vector<std::string> processed;
  processed.reserve(pathname_patterns.size());
  for (const std::string_view pattern : pathname_patterns) {
    if (base_url == nullptr) {
      processed.emplace_back(pattern);
      continue;
    }
    // With a base URL, each pattern is processed exactly as the pathname of
    // a URLPatternInit would be: a relative pattern is resolved against the
    // base URL's path (and an unparsable base URL is a type error).
    url_pattern_init init{};
    init.pathname = std::string(pattern);
    init.base_url = std::string(*base_url);
    auto result = url_pattern_init::process(
        init, url_pattern_init::process_type::pattern);
    if (!result) {
      return tl::unexpected(result.error());
    }
    processed.push_back(std::move(result->pathname).value_or(std::string{}));
  }
  const bool ignore_case = options != nullptr && options->ignore_case;
  auto list = url_pattern_list<regex_provider>::create(std::move(processed),
                                                       ignore_case);
  if (!list) {
    return list;
  }
  // Routes outside the static/":param"/"*" subset are compiled as a
  // URLPattern pathname component through the provider, with the same
  // options parse_url_pattern would use (ignore_case included).
  auto compile_options = url_pattern_compile_component_options::PATHNAME;
  compile_options.ignore_case = ignore_case;
  const url_pattern_list_detail::route_record* routes =
      list->compiled_.template section<url_pattern_list_detail::route_record>(
          list->compiled_.routes_offset);
  for (size_t i = 0; i < list->patterns_.size(); i++) {
    if (routes[i].regexp_component < 0) {
      continue;
    }
    auto component = url_pattern_component<regex_provider>::compile(
        list->patterns_[i], url_pattern_helpers::canonicalize_pathname,
        compile_options);
    if (!component) {
      return tl::unexpected(component.error());
    }
    list->compiled_.group_names[i] = component->group_name_list;
    list->regexp_components_.push_back(std::move(*component));
  }
  return list;
}

template <url_pattern_regex::regex_concept regex_provider>
ada_warn_unused tl::expected<url_pattern_list<regex_provider>, errors>
parse_url_pattern_list(std::span<const url_pattern<regex_provider>> patterns) {
  std::vector<std::string> texts;
  texts.reserve(patterns.size());
  const bool ignore_case = !patterns.empty() && patterns[0].ignore_case();
  for (const url_pattern<regex_provider>& pattern : patterns) {
    if (pattern.ignore_case() != ignore_case) {
      return tl::unexpected(errors::type_error);  // one flag per list
    }
    texts.emplace_back(pattern.get_pathname());
  }
  auto list =
      url_pattern_list<regex_provider>::create(std::move(texts), ignore_case);
  if (!list) {
    return list;
  }
  // Routes outside the subset reuse the pattern's already compiled pathname
  // component: no second create_instance through the provider.
  const url_pattern_list_detail::route_record* routes =
      list->compiled_.template section<url_pattern_list_detail::route_record>(
          list->compiled_.routes_offset);
  for (size_t i = 0; i < patterns.size(); i++) {
    if (routes[i].regexp_component < 0) {
      continue;
    }
    list->compiled_.group_names[i] =
        patterns[i].pathname_component.group_name_list;
    list->regexp_components_.push_back(patterns[i].pathname_component);
  }
  return list;
}
#endif  // ADA_INCLUDE_URL_PATTERN

}  // namespace ada

#endif  // ADA_IMPLEMENTATION_INL_H
