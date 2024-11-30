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

inline const URLPattern::Component& URLPattern::get_protocol() const
    ada_lifetime_bound {
  return protocol;
}
inline const URLPattern::Component& URLPattern::get_username() const
    ada_lifetime_bound {
  return username;
}
inline const URLPattern::Component& URLPattern::get_password() const
    ada_lifetime_bound {
  return password;
}
inline const URLPattern::Component& URLPattern::get_port() const
    ada_lifetime_bound {
  return port;
}
inline const URLPattern::Component& URLPattern::get_pathname() const
    ada_lifetime_bound {
  return pathname;
}
inline const URLPattern::Component& URLPattern::get_search() const
    ada_lifetime_bound {
  return search;
}
inline const URLPattern::Component& URLPattern::get_hash() const
    ada_lifetime_bound {
  return hash;
}

inline bool URLPattern::case_ignored() const ada_lifetime_bound {
  return ignore_case;
}

}  // namespace ada

#endif