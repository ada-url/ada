/**
 * @file url-inl.h
 * @brief Definitions for the URL
 */
#ifndef ADA_URL_INL_H
#define ADA_URL_INL_H

#include "ada/checkers.h"
#include "ada/url.h"
#include "ada/url_components.h"
#include <optional>
#include <string>
#if ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
#endif // ADA_REGULAR_VISUAL_STUDIO

namespace ada {
  [[nodiscard]] ada_really_inline bool url::includes_credentials() const noexcept {
    return !username.empty() || !password.empty();
  }
  [[nodiscard]] ada_really_inline bool url::is_special() const noexcept {
    return type != ada::scheme::NOT_SPECIAL;
  }
  [[nodiscard]] inline uint16_t url::get_special_port() const {
    return ada::scheme::get_special_port(type);
  }
  [[nodiscard]] ada_really_inline ada::scheme::type url::get_scheme_type() const noexcept {
    return type;
  }
  [[nodiscard]] ada_really_inline uint16_t url::scheme_default_port() const noexcept {
    return scheme::get_special_port(type);
  }
  [[nodiscard]] inline bool url::cannot_have_credentials_or_port() const {
    return !host.has_value() || host.value().empty() || type == ada::scheme::type::FILE;
  }
  ada_really_inline size_t url::parse_port(std::string_view view, bool check_trailing_content) noexcept {
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
      port = (r.ec == std::errc() && scheme_default_port() != parsed_port) ?
        std::optional<uint16_t>(parsed_port) : std::nullopt;
    }
    return consumed;
  }
  [[nodiscard]] inline std::string_view url::get_scheme() const noexcept {
    if(is_special()) { return ada::scheme::details::is_special_list[type]; }
    // We only move the 'scheme' if it is non-special.
    return non_special_scheme;
  }
  inline void url::set_scheme(std::string&& new_scheme) noexcept {
    type = ada::scheme::get_scheme_type(new_scheme);
    // We only move the 'scheme' if it is non-special.
    if(!is_special()) {
      non_special_scheme = new_scheme;
    }
  }
  inline void url::copy_scheme(ada::url&& u) noexcept {
    non_special_scheme = u.non_special_scheme;
    type = u.type;
  }
  inline void url::copy_scheme(const ada::url& u) {
    non_special_scheme = u.non_special_scheme;
    type = u.type;
  }

  inline std::ostream& operator<<(std::ostream& out, const ada::url& u) {
    return out << u.to_string();
  }

  // number of 'leading zeroes'.
  inline int leading_zeroes(uint32_t input_num) {
#if ADA_REGULAR_VISUAL_STUDIO
    unsigned long leading_zero(0);
    unsigned long in(input_num);
    return _BitScanReverse(&leading_zero, in) ? int(31 - leading_zero) : 32;
#else
    return __builtin_clz(input_num);
#endif// ADA_REGULAR_VISUAL_STUDIO
  }

  // integer logarithm of x (ceil(log2(x)))
  inline int int_log2(uint32_t x) {
    return 31 - leading_zeroes(x | 1);
  }

  // faster than std::to_string(x).size().
  inline int fast_digit_count(uint32_t x) {
    // Compiles to very few instructions. Note that the
    // table is static and thus effectively a constant.
    // We leave it inside the function because it is meaningless
    // outside of it (this comes at no performance cost).
    const static uint64_t table[] = {
      4294967296,  8589934582,  8589934582,  8589934582,  12884901788,
      12884901788, 12884901788, 17179868184, 17179868184, 17179868184,
      21474826480, 21474826480, 21474826480, 21474826480, 25769703776,
      25769703776, 25769703776, 30063771072, 30063771072, 30063771072,
      34349738368, 34349738368, 34349738368, 34349738368, 38554705664,
      38554705664, 38554705664, 41949672960, 41949672960, 41949672960,
      42949672960, 42949672960};
    return int((x + table[int_log2(x)]) >> 32);
  }

  [[nodiscard]] ada_really_inline ada::url_components url::get_components() noexcept {
    url_components out{};

    // protocol ends with ':'. for example: "https:"
    out.protocol_end = uint32_t(get_scheme().size());

    if (host.has_value()) {

      out.host_start = out.protocol_end + 2;

      if (includes_credentials()) {
        out.username_end = uint32_t(out.protocol_end + 2 + username.size());

        out.host_start += uint32_t(username.size()) + 1;

        if (!password.empty()) {
          out.host_start += uint32_t(password.size()) + 1;
        }
      }

      out.host_end = uint32_t(out.host_start + host.value().size() - 1);
    }

    out.pathname_start = out.host_end;

    if (port.has_value()) {
      out.port = out.host_end;
      out.pathname_start += fast_digit_count(port.value());
    }

    if (query.has_value()) {
      out.search_start = uint32_t(out.pathname_start + get_pathname().size());
    }

    if (fragment.has_value()) {
      if (out.search_start != ada::url_components::omitted) {
        out.hash_start = uint32_t(out.search_start + get_search().size());
      } else {
        out.hash_start = uint32_t(out.pathname_start + get_pathname().size());
      }
    }

    return out;
  }

} // namespace ada

#endif // ADA_URL_H
