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

inline std::ostream &operator<<(std::ostream &out, const ada::url &u) {
  return out << u.to_string();
}

[[nodiscard]] ada_really_inline ada::url_components
url::get_components() const noexcept {
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
      // TODO: why is this not just...?
      // out.username_end = url_components::omitted;
    }

    out.host_end = uint32_t(out.host_start + host.value().size()) - 1;
    running_index = out.host_end + 1;
  } else {
    // Update host start and end date to the same index, since it does not
    // exist.
    out.host_start = out.protocol_end + 1;
    out.host_end = out.protocol_end + 1;

    if (!has_opaque_path && checkers::begins_with(path, "//")) {
      // If url’s host is null, url does not have an opaque path, url’s path’s
      // size is greater than 1, and url’s path[0] is the empty string, then
      // append U+002F (/) followed by U+002E (.) to output.
      running_index = out.protocol_end + 3;
    } else {
      running_index = out.protocol_end + 1;
    }
  }

  if (port.has_value()) {
    out.port = *port;
    running_index += helpers::fast_digit_count(*port) + 1; // Port omits ':'
  }

  out.pathname_start = uint32_t(running_index);

  if (!path.empty()) {
    running_index += path.size();
  }

  if (query.has_value()) {
    out.search_start = uint32_t(running_index);
    running_index += get_search().size();
    if (get_search().size() == 0) {
      running_index++;
    }
  }

  if (fragment.has_value()) {
    out.hash_start = uint32_t(running_index);
  }

  return out;
}

inline void url::update_base_hostname(std::string_view input) {
  host = input;
}

inline void url::update_unencoded_base_hash(std::string_view input) {
  // We do the percent encoding
  fragment = unicode::percent_encode(input, ada::character_sets::FRAGMENT_PERCENT_ENCODE);
}

inline void url::update_base_search(std::string_view input, const uint8_t query_percent_encode_set[]) {
  query = ada::unicode::percent_encode(input, query_percent_encode_set);
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

inline std::optional<uint16_t> url::retrieve_base_port() const { return port; }

inline std::string_view url::retrieve_base_pathname() const { return path; }

inline void url::clear_base_hostname() { host = std::nullopt; }

inline void url::clear_base_pathname() { path = ""; }

inline void url::clear_base_search() { query = std::nullopt; }

inline bool url::base_fragment_has_value() const {
  return fragment.has_value();
}

inline bool url::base_search_has_value() const { return query.has_value(); }

inline void url::set_scheme(std::string &&new_scheme) noexcept {
  type = ada::scheme::get_scheme_type(new_scheme);
  // We only move the 'scheme' if it is non-special.
  if (!is_special()) {
    non_special_scheme = new_scheme;
  }
}

inline void url::copy_scheme(ada::url &&u) noexcept {
  non_special_scheme = u.non_special_scheme;
  type = u.type;
}

inline void url::copy_scheme(const ada::url &u) {
  non_special_scheme = u.non_special_scheme;
  type = u.type;
}

[[nodiscard]] inline std::string_view url::get_scheme() const noexcept {
  if (is_special()) {
    return ada::scheme::details::is_special_list[type];
  }
  // We only move the 'scheme' if it is non-special.
  return non_special_scheme;
}

} // namespace ada

#endif // ADA_URL_H
