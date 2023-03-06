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

} // namespace ada

#endif // ADA_URL_BASE_INL_H
