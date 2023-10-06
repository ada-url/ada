/**
 * @file scheme-inl.h
 * @brief Definitions for the URL scheme.
 */
#ifndef ADA_SCHEME_INL_H
#define ADA_SCHEME_INL_H

#include "ada/scheme.h"

namespace ada::scheme {

/**
 * @namespace ada::scheme::details
 * @brief Includes the definitions for scheme specific entities
 */
namespace details {
// for use with is_special and get_special_port
// Spaces, if present, are removed from URL.
constexpr std::string_view is_special_list[] = {"http", " ",   "https", "ws",
                                                "ftp",  "wss", "file",  " "};
// for use with get_special_port
constexpr uint16_t special_ports[] = {80, 0, 443, 80, 21, 443, 0, 0};
}  // namespace details

ada_really_inline constexpr bool is_special(std::string_view scheme) {
  if (scheme.empty()) {
    return false;
  }
  int hash_value = (2 * scheme.size() + (unsigned)(scheme[0])) & 7;
  const std::string_view target = details::is_special_list[hash_value];
  return (target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1));
}
constexpr uint16_t get_special_port(std::string_view scheme) noexcept {
  if (scheme.empty()) {
    return 0;
  }
  int hash_value = (2 * scheme.size() + (unsigned)(scheme[0])) & 7;
  const std::string_view target = details::is_special_list[hash_value];
  if ((target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1))) {
    return details::special_ports[hash_value];
  } else {
    return 0;
  }
}
constexpr uint16_t get_special_port(ada::scheme::type type) noexcept {
  return details::special_ports[int(type)];
}
constexpr ada::scheme::type get_scheme_type(std::string_view scheme) noexcept {
  if (scheme.empty()) {
    return ada::scheme::NOT_SPECIAL;
  }
  int hash_value = (2 * scheme.size() + (unsigned)(scheme[0])) & 7;
  const std::string_view target = details::is_special_list[hash_value];
  if ((target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1))) {
    return ada::scheme::type(hash_value);
  } else {
    return ada::scheme::NOT_SPECIAL;
  }
}

}  // namespace ada::scheme

#endif  // ADA_SCHEME_INL_H
