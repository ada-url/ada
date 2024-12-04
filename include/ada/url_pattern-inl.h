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
inline std::string_view URLPattern::Component::get_pattern() const noexcept
    ada_lifetime_bound {
  return pattern;
}

inline std::string_view URLPattern::Component::get_regex() const noexcept
    ada_lifetime_bound {
  return regex;
}

inline const std::vector<std::string>& URLPattern::Component::get_names()
    const noexcept ada_lifetime_bound {
  return names;
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

inline bool URLPattern::case_ignored() const ada_lifetime_bound {
  return ignore_case;
}

}  // namespace ada

#endif
