/**
 * @file url-inl.h
 * @brief Definitions for the URL
 */
#ifndef ADA_URL_INL_H
#define ADA_URL_INL_H

#include "ada/url.h"
#include "ada/url_components.h"
#include "ada/scheme-inl.h"

#include <charconv>
#include <cstring>
#include <optional>
#include <string>
#if ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
#endif  // ADA_REGULAR_VISUAL_STUDIO

namespace ada {
[[nodiscard]] ada_really_inline bool url::has_credentials() const noexcept {
  return !username.empty() || !password.empty();
}
[[nodiscard]] ada_really_inline bool url::has_port() const noexcept {
  return port.has_value();
}
[[nodiscard]] inline bool url::cannot_have_credentials_or_port() const {
  return !host.has_value() || host->empty() || type == ada::scheme::type::FILE;
}
[[nodiscard]] inline bool url::has_empty_hostname() const noexcept {
  if (!host.has_value()) {
    return false;
  }
  return host->empty();
}
[[nodiscard]] inline bool url::has_hostname() const noexcept {
  return host.has_value();
}
inline std::ostream& operator<<(std::ostream& out, const ada::url& u) {
  return out << u.to_string();
}

[[nodiscard]] size_t url::get_pathname_length() const noexcept {
  return path.size();
}

[[nodiscard]] constexpr std::string_view url::get_pathname() const noexcept {
  return path;
}

[[nodiscard]] ada_really_inline ada::url_components url::get_components()
    const {
  url_components out{};

  // protocol ends with ':'. for example: "https:"
  out.protocol_end = uint32_t(get_protocol().size());

  // Trailing index is always the next character of the current one.
  // NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)
  size_t running_index = out.protocol_end;

  if (host.has_value()) {
    // 2 characters for "//" and 1 character for starting index
    out.host_start = out.protocol_end + 2;

    if (has_credentials()) {
      out.username_end = uint32_t(out.host_start + username.size());

      out.host_start += uint32_t(username.size());

      if (!password.empty()) {
        out.host_start += uint32_t(password.size() + 1);
      }

      out.host_end = uint32_t(out.host_start + host->size());
    } else {
      out.username_end = out.host_start;

      // Host does not start with "@" if it does not include credentials.
      out.host_end = uint32_t(out.host_start + host->size()) - 1;
    }

    running_index = out.host_end + 1;
  } else {
    // Update host start and end date to the same index, since it does not
    // exist.
    out.host_start = out.protocol_end;
    out.host_end = out.host_start;

    if (!has_opaque_path && path.starts_with("//")) {
      // If url's host is null, url does not have an opaque path, url's path's
      // size is greater than 1, and url's path[0] is the empty string, then
      // append U+002F (/) followed by U+002E (.) to output.
      running_index = out.protocol_end + 2;
    } else {
      running_index = out.protocol_end;
    }
  }

  if (port.has_value()) {
    out.port = *port;
    running_index += helpers::fast_digit_count(*port) + 1;  // Port omits ':'
  }

  out.pathname_start = uint32_t(running_index);

  running_index += path.size();

  if (query.has_value()) {
    out.search_start = uint32_t(running_index);
    running_index += get_search().size();
    if (get_search().empty()) {
      running_index++;
    }
  }

  if (hash.has_value()) {
    out.hash_start = uint32_t(running_index);
  }

  return out;
}

inline void url::update_base_hostname(std::string_view input) { host = input; }

inline void url::update_unencoded_base_hash(std::string_view input) {
  // We do the percent encoding
  hash = unicode::percent_encode(input,
                                 ada::character_sets::FRAGMENT_PERCENT_ENCODE);
}

inline void url::update_base_search(std::string_view input,
                                    const uint8_t query_percent_encode_set[]) {
  query = ada::unicode::percent_encode(input, query_percent_encode_set);
}

inline void url::update_base_search(std::optional<std::string>&& input) {
  query = std::move(input);
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

constexpr void url::clear_pathname() { path.clear(); }

constexpr void url::clear_search() { query = std::nullopt; }

[[nodiscard]] constexpr bool url::has_hash() const noexcept {
  return hash.has_value();
}

[[nodiscard]] constexpr bool url::has_search() const noexcept {
  return query.has_value();
}

constexpr void url::set_protocol_as_file() { type = ada::scheme::type::FILE; }

inline void url::set_scheme(std::string&& new_scheme) noexcept {
  type = ada::scheme::get_scheme_type(new_scheme);
  // We only move the 'scheme' if it is non-special.
  if (!is_special()) {
    non_special_scheme = std::move(new_scheme);
  }
}

constexpr void url::copy_scheme(ada::url&& u) {
  non_special_scheme = u.non_special_scheme;
  type = u.type;
}

constexpr void url::copy_scheme(const ada::url& u) {
  non_special_scheme = u.non_special_scheme;
  type = u.type;
}

[[nodiscard]] ada_really_inline std::string url::get_href() const {
  if (is_special() && host.has_value() && username.empty() && password.empty())
      [[likely]] {
    const std::string_view prefix =
        ada::scheme::details::special_href_prefix[type];
    const size_t host_size = host->size();
    const size_t path_size = path.size();
    const bool has_q = query.has_value();
    const bool has_h = hash.has_value();
    const bool has_p = port.has_value();
    auto finish = [](size_t total, auto&& write) -> std::string {
#if defined(__cpp_lib_string_resize_and_overwrite)
      std::string output;
      output.resize_and_overwrite(total, [&](char* p, size_t) {
        write(p);
        return total;
      });
      return output;
#else
      // Avoid string(total, '\0') zero-fill on typical hrefs (dataset p90~155).
      if (total <= 256) {
        char buf[256];
        write(buf);
        return std::string(buf, total);
      }
      std::string output(total, '\0');
      write(output.data());
      return output;
#endif
    };
    if (!has_q && !has_h && !has_p) [[likely]] {
      const size_t total = prefix.size() + host_size + path_size;
      return finish(total, [&](char* p) {
        std::memcpy(p, prefix.data(), prefix.size());
        p += prefix.size();
        // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
        std::memcpy(p, host->data(), host_size);
        p += host_size;
        std::memcpy(p, path.data(), path_size);
      });
    }
    const size_t query_size = has_q ? query->size() : 0;
    const size_t hash_size = has_h ? hash->size() : 0;
    uint16_t port_val = 0;
    int port_digits = 0;
    if (has_p) {
      port_val = *port;
      port_digits = helpers::fast_digit_count(port_val);
    }
    const size_t total =
        prefix.size() + host_size + (has_p ? size_t(1 + port_digits) : 0) +
        path_size + (has_q ? query_size + 1 : 0) + (has_h ? hash_size + 1 : 0);
    return finish(total, [&](char* p) {
      std::memcpy(p, prefix.data(), prefix.size());
      p += prefix.size();
      // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
      std::memcpy(p, host->data(), host_size);
      p += host_size;
      if (has_p) {
        *p++ = ':';
        auto [ptr, ec] = std::to_chars(p, p + 5, port_val);
        (void)ec;
        p = ptr;
      }
      std::memcpy(p, path.data(), path_size);
      p += path_size;
      if (has_q) {
        *p++ = '?';
        // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
        std::memcpy(p, query->data(), query_size);
        p += query_size;
      }
      if (has_h) {
        *p++ = '#';
        // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
        std::memcpy(p, hash->data(), hash_size);
      }
    });
  }

  std::string output;
  output.reserve(get_href_size());

  if (is_special()) {
    output.append(ada::scheme::details::is_special_list[type]);
    output += ':';
  } else {
    output.append(non_special_scheme);
    output += ':';
  }

  if (host.has_value()) {
    output += '/';
    output += '/';
    if (has_credentials()) {
      output.append(username);
      if (!password.empty()) {
        output += ':';
        output.append(password);
      }
      output += '@';
    }
    output.append(*host);
    if (port.has_value()) {
      output += ':';
      char port_buf[5];
      auto [ptr, ec] = std::to_chars(port_buf, port_buf + 5, *port);
      (void)ec;
      output.append(port_buf, static_cast<size_t>(ptr - port_buf));
    }
  } else if (!has_opaque_path && path.starts_with("//")) {
    // If url's host is null, url does not have an opaque path, url's path's
    // size is greater than 1, and url's path[0] is the empty string, then
    // append U+002F (/) followed by U+002E (.) to output.
    output += '/';
    output += '.';
  }
  output.append(path);
  if (query.has_value()) {
    output += '?';
    output.append(*query);
  }
  if (hash.has_value()) {
    output += '#';
    output.append(*hash);
  }
  return output;
}

[[nodiscard]] inline size_t url::get_href_size() const noexcept {
  size_t size = 0;
  if (is_special()) {
    size += ada::scheme::details::is_special_list[type].size() + 1;
  } else {
    size += non_special_scheme.size() + 1;
  }
  if (host.has_value()) {
    size += host->size();
    size += 2;
    if (has_credentials()) {
      size += username.size();
      if (!password.empty()) {
        size += 1 + password.size();
      }
      size += 1;
    }
    if (port.has_value()) {
      size += 1;
      uint16_t p = *port;
      size += (p >= 10000)  ? 5
              : (p >= 1000) ? 4
              : (p >= 100)  ? 3
              : (p >= 10)   ? 2
                            : 1;
    }
  } else if (!has_opaque_path && path.starts_with("//")) {
    size += 2;
  }
  size += path.size();
  if (query.has_value()) {
    size += 1 + query->size();
  }
  if (hash.has_value()) {
    size += 1 + hash->size();
  }
  return size;
}

ada_really_inline size_t url::parse_port(std::string_view view,
                                         bool check_trailing_content) noexcept {
  ada_log("parse_port('", view, "') ", view.size());
  if (!view.empty() && view[0] == '-') {
    ada_log("parse_port: view[0] == '0' && view.size() > 1");
    is_valid = false;
    return 0;
  }
  uint16_t parsed_port{};
  auto r = std::from_chars(view.data(), view.data() + view.size(), parsed_port);
  if (r.ec == std::errc::result_out_of_range) {
    ada_log("parse_port: r.ec == std::errc::result_out_of_range");
    is_valid = false;
    return 0;
  }
  ada_log("parse_port: ", parsed_port);
  const auto consumed = size_t(r.ptr - view.data());
  ada_log("parse_port: consumed ", consumed);
  if (check_trailing_content) {
    is_valid &=
        (consumed == view.size() || view[consumed] == '/' ||
         view[consumed] == '?' || (is_special() && view[consumed] == '\\'));
  }
  ada_log("parse_port: is_valid = ", is_valid);
  if (is_valid) {
    // scheme_default_port can return 0, and we should allow 0 as a base port.
    auto default_port = scheme_default_port();
    bool is_port_valid = (default_port == 0 && parsed_port == 0) ||
                         (default_port != parsed_port);
    port = (r.ec == std::errc() && is_port_valid) ? std::optional(parsed_port)
                                                  : std::nullopt;
  }
  return consumed;
}

}  // namespace ada

#endif  // ADA_URL_H
