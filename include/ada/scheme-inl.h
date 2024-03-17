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
static constexpr std::string_view is_special_list[] = {
    "http", " ", "https", "ws", "ftp", "wss", "file", " "};

// for use with get_special_port
static constexpr uint16_t special_ports[] = {80, 0, 443, 80, 21, 443, 0, 0};
}  // namespace details

ada_really_inline constexpr bool is_special(std::string_view scheme) {
  if (scheme.empty()) {
    return false;
  }
  auto const hash_value = static_cast<int>(
      (2 * static_cast<int>(scheme.size()) + static_cast<unsigned>(scheme[0])) &
      7U);
  const std::string_view target = details::is_special_list[hash_value];
  return (target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1));
}
constexpr uint16_t get_special_port(std::string_view scheme) noexcept {
  if (scheme.empty()) {
    return 0;
  }
  auto const hash_value = static_cast<int>(
      (2 * scheme.size() + static_cast<unsigned>(scheme[0])) & 7U);
  std::string_view const target = details::is_special_list[hash_value];
  if ((target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1))) {
    return details::special_ports[hash_value];
  }
  return 0;
}
constexpr uint16_t get_special_port(ada::scheme::type const type) noexcept {
  return details::special_ports[static_cast<int>(type)];
}
constexpr ada::scheme::type get_scheme_type(
    std::string_view const scheme) noexcept {
  if (scheme.empty()) {
    return ada::scheme::NOT_SPECIAL;
  }
  auto const hash_value = static_cast<int>(
      (2 * scheme.size() + static_cast<unsigned>(scheme[0])) & 7U);
  const std::string_view target = details::is_special_list[hash_value];
  if ((target[0] == scheme[0]) && (target.substr(1) == scheme.substr(1))) {
    return static_cast<ada::scheme::type>(hash_value);
  }
  return ada::scheme::NOT_SPECIAL;
}

}  // namespace ada::scheme

#endif  // ADA_SCHEME_INL_H
