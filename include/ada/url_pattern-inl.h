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

inline std::string url_pattern_component::to_string() const {
#ifdef ADA_HAS_FORMAT
  return std::format(R"({{"pattern": "{}", "has_regexp_groups": {}}})", pattern,
                     has_regexp_groups ? "true" : "false"  //,
  );
#else
  return "";
#endif
}

inline url_pattern_component_result
url_pattern_component::create_component_match_result(
    std::string_view input, const std::smatch& exec_result) {
  // Let result be a new URLPatternComponentResult.
  // Set result["input"] to input.
  // Let groups be a record<USVString, (USVString or undefined)>.
  auto result =
      url_pattern_component_result{.input = std::string(input), .groups = {}};

  // If input is empty, then groups will always be empty.
  if (input.empty()) {
    return result;
  }

  // Optimization: Let's reserve the size.
  result.groups.reserve(exec_result.size() - 1);

  size_t group_index = 0;
  // Let index be 1.
  // While index is less than Get(execResult, "length"):
  for (size_t index = 1; index < exec_result.size(); index++) {
    // Let name be component’s group name list[index - 1].
    // Let value be Get(execResult, ToString(index)).
    // Set groups[name] to value.
    auto exec = exec_result[index];
    if (!exec.matched) continue;
    result.groups.insert({
        group_name_list[group_index],
        exec.str(),
    });

    group_index++;
  }
  return result;
}

inline std::string url_pattern::to_string() const {
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

inline std::string_view url_pattern::get_protocol() const ada_lifetime_bound {
  // Return this's associated URL pattern's protocol component's pattern string.
  return protocol_component.pattern;
}
inline std::string_view url_pattern::get_username() const ada_lifetime_bound {
  // Return this's associated URL pattern's username component's pattern string.
  return username_component.pattern;
}
inline std::string_view url_pattern::get_password() const ada_lifetime_bound {
  // Return this's associated URL pattern's password component's pattern string.
  return password_component.pattern;
}
inline std::string_view url_pattern::get_hostname() const ada_lifetime_bound {
  // Return this's associated URL pattern's hostname component's pattern string.
  return hostname_component.pattern;
}
inline std::string_view url_pattern::get_port() const ada_lifetime_bound {
  // Return this's associated URL pattern's port component's pattern string.
  return port_component.pattern;
}
inline std::string_view url_pattern::get_pathname() const ada_lifetime_bound {
  // Return this's associated URL pattern's pathname component's pattern string.
  return pathname_component.pattern;
}
inline std::string_view url_pattern::get_search() const ada_lifetime_bound {
  // Return this's associated URL pattern's search component's pattern string.
  return search_component.pattern;
}
inline std::string_view url_pattern::get_hash() const ada_lifetime_bound {
  // Return this's associated URL pattern's hash component's pattern string.
  return hash_component.pattern;
}

inline bool url_pattern::ignore_case() const { return ignore_case_; }

inline bool url_pattern::has_regexp_groups() const {
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
