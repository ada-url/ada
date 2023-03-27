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
#include "ada/log.h"
#include "ada/checkers.h"
#include "ada/url.h"

#include <optional>
#include <string>
#if ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
#endif  // ADA_REGULAR_VISUAL_STUDIO

namespace ada {

[[nodiscard]] ada_really_inline bool url_base::is_special() const noexcept {
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
