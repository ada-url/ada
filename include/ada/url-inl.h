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
  [[nodiscard]] inline bool url::cannot_have_credentials_or_port() const {
    return !host.has_value() || host.value().empty() || type == ada::scheme::type::FILE;
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

    // Trailing index is always the next character of the current one.
    size_t running_index = out.protocol_end + 1;

    if (host.has_value()) {
      // 2 characters for "//" and 1 character for starting index
      out.host_start = out.protocol_end + 3;

      if (includes_credentials()) {
        out.username_end = uint32_t(out.host_start + username.size() - 1);

        out.host_start += uint32_t(username.size() + 1);

        if (!password.empty()) {
          out.host_start += uint32_t(password.size() + 1);
        }
      } else {
        out.username_end = out.host_start;
      }

      out.host_end = uint32_t(out.host_start + host.value().size()) - 1;
      running_index = out.host_end + 1;
    } else {
      // Update host start and end date to the same index, since it does not exist.
      out.host_start = out.protocol_end + 1;
      out.host_end = out.protocol_end + 1;

      if (!has_opaque_path && checkers::begins_with(path, "//")) {
        // If url’s host is null, url does not have an opaque path, url’s path’s size is greater than 1,
        // and url’s path[0] is the empty string, then append U+002F (/) followed by U+002E (.) to output.
        running_index = out.protocol_end + 3;
      } else {
        running_index = out.protocol_end + 1;
      }
    }

    if (port.has_value()) {
      out.port = *port;
      running_index += fast_digit_count(*port) + 1; // Port omits ':'
    }

    out.pathname_start = uint32_t(running_index);

    if (!path.empty()) {
      running_index += path.size();
    }

    if (query.has_value()) {
      out.search_start = uint32_t(running_index);
      running_index += get_search().size();
      if (get_search().size() == 0) { running_index++; }
    }

    if (fragment.has_value()) {
      out.hash_start = uint32_t(running_index);
    }

    return out;
  }

  inline void url::update_base_hash(std::string_view input) {
    fragment = input;
  }

  inline void url::update_base_search(std::optional<std::string> input) {
    query = input;
  }

  inline void url::update_base_pathname(const std::string_view input) {
    path = input;
  }

  inline void url::update_base_username(const std::string_view input) {
    username = input;
  }

  inline void url::update_base_password(const std::string_view input) {
    password = input;
  }

  inline void url::update_base_port(std::optional<uint16_t> input) {
    port = input;
  }

  inline std::optional<uint16_t> url::retrieve_base_port() {
    return port;
  }

  inline std::string url::retrieve_base_pathname() {
    return path;
  }

  inline void url::clear_base_hash() {
    fragment = std::nullopt;
  }

  inline bool url::base_fragment_has_value() const {
    return fragment.has_value();
  }

  inline bool url::base_search_has_value() const {
    return query.has_value();
  }

  inline bool url::base_port_has_value() const {
    return port.has_value();
  }

  inline bool url::base_hostname_has_value() const {
    return host.has_value();
  }

} // namespace ada

#endif // ADA_URL_H
