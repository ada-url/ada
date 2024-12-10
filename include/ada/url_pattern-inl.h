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

inline std::string_view url_pattern_component::get_pattern() const noexcept
    ada_lifetime_bound {
  return pattern;
}

inline std::string_view url_pattern_component::get_regexp() const noexcept
    ada_lifetime_bound {
  return regexp;
}

inline const std::vector<std::string>&
url_pattern_component::get_group_name_list() const noexcept ada_lifetime_bound {
  return group_name_list;
}

inline std::string_view url_pattern::get_protocol() const ada_lifetime_bound {
  // Return this's associated URL pattern's protocol component's pattern string.
  return protocol_component.get_pattern();
}
inline std::string_view url_pattern::get_username() const ada_lifetime_bound {
  // Return this's associated URL pattern's username component's pattern string.
  return username_component.get_pattern();
}
inline std::string_view url_pattern::get_password() const ada_lifetime_bound {
  // Return this's associated URL pattern's password component's pattern string.
  return password_component.get_pattern();
}
inline std::string_view url_pattern::get_hostname() const ada_lifetime_bound {
  // Return this's associated URL pattern's hostname component's pattern string.
  return hostname_component.get_pattern();
}
inline std::string_view url_pattern::get_port() const ada_lifetime_bound {
  // Return this's associated URL pattern's port component's pattern string.
  return port_component.get_pattern();
}
inline std::string_view url_pattern::get_pathname() const ada_lifetime_bound {
  // Return this's associated URL pattern's pathname component's pattern string.
  return pathname_component.get_pattern();
}
inline std::string_view url_pattern::get_search() const ada_lifetime_bound {
  // Return this's associated URL pattern's search component's pattern string.
  return search_component.get_pattern();
}
inline std::string_view url_pattern::get_hash() const ada_lifetime_bound {
  // Return this's associated URL pattern's hash component's pattern string.
  return hash_component.get_pattern();
}

inline bool url_pattern::ignore_case() const ada_lifetime_bound {
  return ignore_case_;
}

inline bool url_pattern::has_regexp_groups() const ada_lifetime_bound {
  // If this's associated URL pattern's has regexp groups, then return true.
  return protocol_component.has_regexp_groups() ||
         username_component.has_regexp_groups() ||
         password_component.has_regexp_groups() ||
         hostname_component.has_regexp_groups() ||
         port_component.has_regexp_groups() ||
         pathname_component.has_regexp_groups() ||
         search_component.has_regexp_groups() ||
         hash_component.has_regexp_groups();
}

inline bool url_pattern_part::is_regexp() const noexcept {
  return type == url_pattern_part_type::REGEXP;
}

}  // namespace ada

#endif
