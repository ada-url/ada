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
#endif // ADA_REGULAR_VISUAL_STUDIO

namespace ada {

[[nodiscard]] ada_really_inline ada::scheme::type url_base::get_scheme_type() const noexcept {
  return type;
}

[[nodiscard]] ada_really_inline bool url_base::is_special() const noexcept {
  return type != ada::scheme::NOT_SPECIAL;
}

[[nodiscard]] inline uint16_t url_base::get_special_port() const {
  return ada::scheme::get_special_port(type);
}

[[nodiscard]] ada_really_inline uint16_t url_base::scheme_default_port() const noexcept {
  return scheme::get_special_port(type);
}

ada_really_inline size_t url_base::parse_port(std::string_view view, bool check_trailing_content) noexcept {
  ada_log("parse_port('", view, "') ", view.size());
  uint16_t parsed_port{};
  auto r = std::from_chars(view.data(), view.data() + view.size(), parsed_port);
  if(r.ec == std::errc::result_out_of_range) {
    ada_log("parse_port: std::errc::result_out_of_range");
    is_valid = false;
    return 0;
  }
  ada_log("parse_port: ", parsed_port);
  const size_t consumed = size_t(r.ptr - view.data());
  ada_log("parse_port: consumed ", consumed);
  if(check_trailing_content) {
    is_valid &= (consumed == view.size() || view[consumed] == '/' || view[consumed] == '?' || (is_special() && view[consumed] == '\\'));
  }
  ada_log("parse_port: is_valid = ", is_valid);
  if(is_valid) {
    update_base_port((r.ec == std::errc() && scheme_default_port() != parsed_port) ?
        std::optional<uint16_t>(parsed_port) : std::nullopt);
  }
  return consumed;
}

} // namespace ada

#endif // ADA_URL_BASE_INL_H
