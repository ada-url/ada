/**
 * @file url_base-inl.h
 * @brief Inline functions for url base
 */
#ifndef ADA_URL_BASE_INL_H
#define ADA_URL_BASE_INL_H

#include <optional>
#include <string>

#include "checkers.h"
#include "log.h"
#include "scheme-inl.h"
#include "scheme.h"
#include "url.h"
#include "url_aggregator.h"
#include "url_components.h"
#if ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
#endif  // ADA_REGULAR_VISUAL_STUDIO

namespace ada {

[[nodiscard]] ada_really_inline constexpr bool url_base::is_special()
    const noexcept {
  return type != ada::scheme::NOT_SPECIAL;
}

[[nodiscard]] inline uint16_t url_base::get_special_port() const noexcept {
  return ada::scheme::get_special_port(type);
}

[[nodiscard]] ada_really_inline uint16_t
url_base::scheme_default_port() const noexcept {
  return scheme::get_special_port(type);
}

}  // namespace ada

#endif  // ADA_URL_BASE_INL_H
