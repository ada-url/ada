/**
 * @file url_base-inl.h
 * @brief Inline functions for url base
 */
#ifndef ADA_URL_BASE_INL_H
#define ADA_URL_BASE_INL_H

#include "ada/url_aggregator.h"
#include "ada/url_components.h"
#include "ada/scheme.h"
#include "ada/scheme-inl.h"

namespace ada {

[[nodiscard]] ada_really_inline bool url_base::is_special() const noexcept {
  return type != ada::scheme::NOT_SPECIAL;
}

[[nodiscard]] inline uint16_t url_base::get_special_port() const {
  return ada::scheme::get_special_port(type);
}

[[nodiscard]] ada_really_inline uint16_t url_base::scheme_default_port() const noexcept {
  return scheme::get_special_port(type);
}

inline void url_base::copy_scheme(ada::url_base&& u) noexcept {
  non_special_scheme = u.non_special_scheme;
  type = u.type;
}
inline void url_base::copy_scheme(const ada::url_base& u) {
  non_special_scheme = u.non_special_scheme;
  type = u.type;
}

[[nodiscard]] inline std::string_view url_base::get_scheme() const noexcept {
  if(is_special()) { return ada::scheme::details::is_special_list[type]; }
  // We only move the 'scheme' if it is non-special.
  return non_special_scheme;
}
inline void url_base::set_scheme(std::string&& new_scheme) noexcept {
  type = ada::scheme::get_scheme_type(new_scheme);
  // We only move the 'scheme' if it is non-special.
  if(!is_special()) {
    non_special_scheme = new_scheme;
  }
}

} // namespace ada

#endif // ADA_URL_BASE_INL_H
