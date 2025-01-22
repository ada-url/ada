/**
 * @file url_pattern-inl.h
 * @brief Declaration for the URLPattern inline functions.
 */
#ifndef ADA_URL_PATTERN_INL_H
#define ADA_URL_PATTERN_INL_H

#include "ada/common_defs.h"
#include "ada/url_pattern.h"

#include <string_view>

namespace ada {

inline bool url_pattern_init::operator==(const url_pattern_init& other) const {
  return protocol == other.protocol && username == other.username &&
         password == other.password && hostname == other.hostname &&
         port == other.port && search == other.search && hash == other.hash &&
         pathname == other.pathname;
}

inline bool url_pattern_component_result::operator==(
    const url_pattern_component_result& other) const {
  return input == other.input && groups == other.groups;
}

template <url_pattern_regex::regex_concept regex_provider>
std::string url_pattern_component<regex_provider>::to_string() const {
#ifdef ADA_HAS_FORMAT
  return std::format(R"({{"pattern": "{}", "has_regexp_groups": {}}})", pattern,
                     has_regexp_groups ? "true" : "false"  //,
  );
#else
  return "";
#endif
}

template <url_pattern_regex::regex_concept regex_provider>
url_pattern_component_result
url_pattern_component<regex_provider>::create_component_match_result(
    std::string_view input, std::vector<std::string>&& exec_result) {
  // Let result be a new URLPatternComponentResult.
  // Set result["input"] to input.
  // Let groups be a record<USVString, (USVString or undefined)>.
  auto result =
      url_pattern_component_result{.input = std::string(input), .groups = {}};

  // If input is empty, then groups will always be empty.
  if (input.empty() || exec_result.empty()) {
    return result;
  }

  // Optimization: Let's reserve the size.
  result.groups.reserve(exec_result.size() - 1);

  // We explicitly start iterating from 0 even though the spec
  // says we should start from 1. This case is handled by the
  // std_regex_provider.
  for (size_t index = 0; index < exec_result.size(); index++) {
    result.groups.insert({
        group_name_list[index],
        std::move(exec_result[index]),
    });
  }
  return result;
}

template <url_pattern_regex::regex_concept regex_provider>
std::string url_pattern<regex_provider>::to_string() const {
#ifdef ADA_HAS_FORMAT
  return std::format(
      R"({{"protocol_component": "{}", "username_component": {}, "password_component": {}, "hostname_component": {}, "port_component": {}, "pathname_component": {}, "search_component": {}, "hash_component": {}, "ignore_case": {}}})",
      protocol_component.to_string(), username_component.to_string(),
      password_component.to_string(), hostname_component.to_string(),
      port_component.to_string(), pathname_component.to_string(),
      search_component.to_string(), hash_component.to_string(),
      ignore_case_ ? "true" : "false");
#else
  return "";
#endif
}

template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_protocol() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's protocol component's pattern string.
  return protocol_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_username() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's username component's pattern string.
  return username_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_password() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's password component's pattern string.
  return password_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_hostname() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's hostname component's pattern string.
  return hostname_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_port() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's port component's pattern string.
  return port_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_pathname() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's pathname component's pattern string.
  return pathname_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_search() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's search component's pattern string.
  return search_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
std::string_view url_pattern<regex_provider>::get_hash() const
    ada_lifetime_bound {
  // Return this's associated URL pattern's hash component's pattern string.
  return hash_component.pattern;
}
template <url_pattern_regex::regex_concept regex_provider>
bool url_pattern<regex_provider>::ignore_case() const {
  return ignore_case_;
}
template <url_pattern_regex::regex_concept regex_provider>
bool url_pattern<regex_provider>::has_regexp_groups() const {
  // If this's associated URL pattern's has regexp groups, then return true.
  return protocol_component.has_regexp_groups ||
         username_component.has_regexp_groups ||
         password_component.has_regexp_groups ||
         hostname_component.has_regexp_groups ||
         port_component.has_regexp_groups ||
         pathname_component.has_regexp_groups ||
         search_component.has_regexp_groups || hash_component.has_regexp_groups;
}

inline bool url_pattern_part::is_regexp() const noexcept {
  return type == url_pattern_part_type::REGEXP;
}

inline std::string_view url_pattern_compile_component_options::get_delimiter()
    const {
  if (delimiter) {
    return {&delimiter.value(), 1};
  }
  return {};
}

inline std::string_view url_pattern_compile_component_options::get_prefix()
    const {
  if (prefix) {
    return {&prefix.value(), 1};
  }
  return {};
}
}  // namespace ada

#endif
