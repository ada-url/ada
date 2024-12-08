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

inline std::string_view URLPattern::get_protocol() const ada_lifetime_bound {
  // Return this's associated URL pattern's protocol component's pattern string.
  return protocol.get_pattern();
}
inline std::string_view URLPattern::get_username() const ada_lifetime_bound {
  // Return this's associated URL pattern's username component's pattern string.
  return username.get_pattern();
}
inline std::string_view URLPattern::get_password() const ada_lifetime_bound {
  // Return this's associated URL pattern's password component's pattern string.
  return password.get_pattern();
}
inline std::string_view URLPattern::get_hostname() const ada_lifetime_bound {
  // Return this's associated URL pattern's hostname component's pattern string.
  return hostname.get_pattern();
}
inline std::string_view URLPattern::get_port() const ada_lifetime_bound {
  // Return this's associated URL pattern's port component's pattern string.
  return port.get_pattern();
}
inline std::string_view URLPattern::get_pathname() const ada_lifetime_bound {
  // Return this's associated URL pattern's pathname component's pattern string.
  return pathname.get_pattern();
}
inline std::string_view URLPattern::get_search() const ada_lifetime_bound {
  // Return this's associated URL pattern's search component's pattern string.
  return search.get_pattern();
}
inline std::string_view URLPattern::get_hash() const ada_lifetime_bound {
  // Return this's associated URL pattern's hash component's pattern string.
  return hash.get_pattern();
}

inline bool URLPattern::ignore_case() const ada_lifetime_bound {
  return ignore_case_;
}

inline bool URLPattern::has_regexp_groups() const ada_lifetime_bound {
  // If this's associated URL pattern's has regexp groups, then return true.
  return protocol.has_regexp_groups() || username.has_regexp_groups() ||
         password.has_regexp_groups() || hostname.has_regexp_groups() ||
         port.has_regexp_groups() || pathname.has_regexp_groups() ||
         search.has_regexp_groups() || hash.has_regexp_groups();
}

inline bool url_pattern_part::is_regexp() const noexcept {
  return type == "regexp";
}

}  // namespace ada

#endif
