/**
 * @file url-inl.h
 * @brief Definitions for the URL
 */
#ifndef ADA_URL_INL_H
#define ADA_URL_INL_H

#include "ada/url.h"
#include "ada/url_components.h"
#include "ada/helpers.h"
#include "ada/string_pool.h"

#include <charconv>
#include <cstring>
#include <optional>
#include <string>
#if ADA_REGULAR_VISUAL_STUDIO
#include <intrin.h>
#endif  // ADA_REGULAR_VISUAL_STUDIO

namespace ada {

// Inline destructor: recycles freelist capacity without an out-of-line public
// symbol flip (Agents.md ABI: no non-inline↔inline public method changes).
inline url::~url() {
  // Host/query/hash are typically SSO-sized; path and the simple-absolute
  // href cache (non_special_scheme) may hold heap capacity.
  string_pool::recycle(path);
  string_pool::recycle(non_special_scheme);
}

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

// True when non_special_scheme holds a simple-absolute href cache for a
// special scheme (the field is otherwise empty for special URLs).
[[nodiscard]] inline bool url::has_simple_href_cache() const noexcept {
  return !non_special_scheme.empty() &&
         type != ada::scheme::type::NOT_SPECIAL;
}

inline void url::clear_simple_href_cache() noexcept {
  if (type != ada::scheme::type::NOT_SPECIAL) {
    non_special_scheme.clear();
  }
}

// Materialize path/query/hash from the href cache, then drop the cache.
// Called by setters before mutating so components stay consistent.
inline void url::materialize_from_simple_href_cache() {
  if (!has_simple_href_cache()) {
    return;
  }
  const std::string& href = non_special_scheme;
  const size_t auth = (type == ada::scheme::type::HTTPS) ? 8 : 7;
  const size_t host_len = host.has_value() ? host->size() : 0;
  const size_t path_begin = auth + host_len;
  size_t path_end = href.size();
  size_t q_pos = std::string::npos;
  size_t h_pos = std::string::npos;
  if (path_begin < href.size()) {
    q_pos = href.find('?', path_begin);
    h_pos = href.find('#', path_begin);
    path_end = href.size();
    if (q_pos != std::string::npos) {
      path_end = q_pos;
    }
    if (h_pos != std::string::npos && h_pos < path_end) {
      path_end = h_pos;
    }
    path.assign(href.data() + path_begin, path_end - path_begin);
  } else {
    path = "/";
  }
  if (q_pos != std::string::npos) {
    const size_t q_end =
        (h_pos != std::string::npos && h_pos > q_pos) ? h_pos : href.size();
    query.emplace(href.data() + q_pos + 1, q_end - q_pos - 1);
  }
  if (h_pos != std::string::npos) {
    hash.emplace(href.data() + h_pos + 1, href.size() - h_pos - 1);
  }
  non_special_scheme.clear();
}

[[nodiscard]] inline std::string_view url::simple_href_path() const noexcept {
  const size_t auth = (type == ada::scheme::type::HTTPS) ? 8 : 7;
  const size_t host_len = host.has_value() ? host->size() : 0;
  const size_t path_begin = auth + host_len;
  if (path_begin >= non_special_scheme.size()) {
    return "/";
  }
  const size_t path_end =
      non_special_scheme.find_first_of("?#", path_begin);
  if (path_end == std::string::npos) {
    return std::string_view(non_special_scheme).substr(path_begin);
  }
  return std::string_view(non_special_scheme)
      .substr(path_begin, path_end - path_begin);
}

[[nodiscard]] size_t url::get_pathname_length() const noexcept {
  if (has_simple_href_cache() && path.empty()) {
    return simple_href_path().size();
  }
  return path.size();
}

[[nodiscard]] inline std::string_view url::get_pathname() const noexcept {
  if (has_simple_href_cache() && path.empty()) {
    return simple_href_path();
  }
  return path;
}

[[nodiscard]] ada_really_inline ada::url_components url::get_components()
    const {
  // Simple-absolute href cache: offsets match the prebuilt href layout.
  if (has_simple_href_cache()) {
    url_components out{};
    const uint32_t protocol_end =
        (type == ada::scheme::type::HTTPS) ? 6u : 5u;
    out.protocol_end = protocol_end;
    out.username_end = protocol_end + 2;
    out.host_start = protocol_end + 2;
    const uint32_t host_len =
        host.has_value() ? uint32_t(host->size()) : 0u;
    // Match the non-credentials branch below: host_end is last host index.
    out.host_end = out.host_start + host_len - (host_len > 0 ? 1u : 0u);
    out.port = url_components::omitted;
    const size_t path_begin = size_t(protocol_end) + 2 + host_len;
    out.pathname_start = uint32_t(path_begin);
    const size_t q = non_special_scheme.find('?', path_begin);
    const size_t h = non_special_scheme.find('#', path_begin);
    if (q != std::string::npos && (h == std::string::npos || q < h)) {
      out.search_start = uint32_t(q);
    }
    if (h != std::string::npos) {
      out.hash_start = uint32_t(h);
    }
    return out;
  }

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

[[nodiscard]] inline bool url::has_hash() const noexcept {
  if (hash.has_value()) {
    return true;
  }
  if (has_simple_href_cache()) {
    return non_special_scheme.find('#') != std::string::npos;
  }
  return false;
}

[[nodiscard]] inline bool url::has_search() const noexcept {
  if (query.has_value()) {
    return true;
  }
  if (has_simple_href_cache()) {
    return non_special_scheme.find('?') != std::string::npos;
  }
  return false;
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
  type = u.type;
  // non_special_scheme holds the scheme name only for non-special URLs. For
  // special URLs it may hold a simple-absolute href cache — never copy that.
  if (u.type == ada::scheme::type::NOT_SPECIAL) {
    non_special_scheme = std::move(u.non_special_scheme);
  } else {
    non_special_scheme.clear();
  }
}

constexpr void url::copy_scheme(const ada::url& u) {
  type = u.type;
  if (u.type == ada::scheme::type::NOT_SPECIAL) {
    non_special_scheme = u.non_special_scheme;
  } else {
    non_special_scheme.clear();
  }
}

namespace detail {
// Grow string to n bytes without requiring value-init of new chars when the
// platform provides that API. Not noexcept: allocation may throw bad_alloc.
ada_really_inline void string_resize_uninitialized(std::string& s, size_t n) {
#if defined(__cpp_lib_string_resize_and_overwrite)
  s.resize_and_overwrite(
      n, [](char*, std::size_t count) noexcept { return count; });
#elif defined(_LIBCPP_VERSION) && defined(__APPLE__)
  // Apple libc++ public extension; not available on all libc++ / libstdc++.
  s.__resize_default_init(n);
#else
  s.resize(n);
#endif
}
}  // namespace detail

[[nodiscard]] ada_really_inline std::string url::get_href() const {
  // Simple-absolute cache: return a copy of the prebuilt href. (Stealing would
  // break a second get_href / getters that slice the cache.)
  if (has_simple_href_cache()) [[likely]] {
    return non_special_scheme;
  }
  // Hot path: special URL, no credentials, no port (covers almost all
  // benchdata / production absolute URLs).
  if (host.has_value() && username.empty() && password.empty() &&
      !port.has_value() && type != ada::scheme::type::NOT_SPECIAL) [[likely]] {
    // Hardcode common schemes to avoid table load + size branch.
    const char* scheme_ptr;
    size_t scheme_len;
    if (type == ada::scheme::type::HTTPS) [[likely]] {
      scheme_ptr = "https";
      scheme_len = 5;
    } else if (type == ada::scheme::type::HTTP) {
      scheme_ptr = "http";
      scheme_len = 4;
    } else {
      const std::string_view scheme =
          ada::scheme::details::is_special_list[type];
      scheme_ptr = scheme.data();
      scheme_len = scheme.size();
    }
    const size_t host_size = host->size();
    const size_t path_size = path.size();
    const bool has_q = query.has_value();
    const bool has_h = hash.has_value();
    const size_t query_size = has_q ? query->size() : 0;
    const size_t hash_size = has_h ? hash->size() : 0;
    const size_t total = scheme_len + 3 + host_size + path_size +
                         (has_q ? query_size + 1 : 0) +
                         (has_h ? hash_size + 1 : 0);
    std::string output;
    detail::string_resize_uninitialized(output, total);
    char* d = output.data();
    std::memcpy(d, scheme_ptr, scheme_len);
    d += scheme_len;
    d[0] = ':';
    d[1] = '/';
    d[2] = '/';
    d += 3;
    // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
    std::memcpy(d, host->data(), host_size);
    d += host_size;
    std::memcpy(d, path.data(), path_size);
    d += path_size;
    if (has_q) {
      *d++ = '?';
      // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
      std::memcpy(d, query->data(), query_size);
      d += query_size;
    }
    if (has_h) {
      *d++ = '#';
      // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
      std::memcpy(d, hash->data(), hash_size);
    }
    return output;
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
  if (has_simple_href_cache()) {
    return non_special_scheme.size();
  }
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
