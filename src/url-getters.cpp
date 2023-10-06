/**
 * @file url-getters.cpp
 * Includes all the getters of `ada::url`
 */
#include "ada.h"
#include "ada/implementation.h"
#include "ada/helpers.h"
#include "ada/scheme.h"

#include <algorithm>
#include <string>

namespace ada {
[[nodiscard]] std::string url::get_origin() const noexcept {
  if (is_special()) {
    // Return a new opaque origin.
    if (type == scheme::FILE) {
      return "null";
    }
    return ada::helpers::concat(get_protocol(), "//", get_host());
  }

  if (non_special_scheme == "blob") {
    if (!path.empty()) {
      auto result = ada::parse<ada::url>(path);
      if (result &&
          (result->type == scheme::HTTP || result->type == scheme::HTTPS)) {
        // If pathURL's scheme is not "http" and not "https", then return a
        // new opaque origin.
        return ada::helpers::concat(result->get_protocol(), "//",
                                    result->get_host());
      }
    }
  }

  // Return a new opaque origin.
  return "null";
}

[[nodiscard]] std::string url::get_protocol() const noexcept {
  if (is_special()) {
    return helpers::concat(ada::scheme::details::is_special_list[type], ":");
  }
  // We only move the 'scheme' if it is non-special.
  return helpers::concat(non_special_scheme, ":");
}

[[nodiscard]] std::string url::get_host() const noexcept {
  // If url's host is null, then return the empty string.
  // If url's port is null, return url's host, serialized.
  // Return url's host, serialized, followed by U+003A (:) and url's port,
  // serialized.
  if (!host.has_value()) {
    return "";
  }
  if (port.has_value()) {
    return host.value() + ":" + get_port();
  }
  return host.value();
}

[[nodiscard]] std::string url::get_hostname() const noexcept {
  return host.value_or("");
}

[[nodiscard]] std::string_view url::get_pathname() const noexcept {
  return path;
}

[[nodiscard]] std::string url::get_search() const noexcept {
  // If this's URL's query is either null or the empty string, then return the
  // empty string. Return U+003F (?), followed by this's URL's query.
  return (!query.has_value() || (query.value().empty())) ? ""
                                                         : "?" + query.value();
}

[[nodiscard]] const std::string& url::get_username() const noexcept {
  return username;
}

[[nodiscard]] const std::string& url::get_password() const noexcept {
  return password;
}

[[nodiscard]] std::string url::get_port() const noexcept {
  return port.has_value() ? std::to_string(port.value()) : "";
}

[[nodiscard]] std::string url::get_hash() const noexcept {
  // If this's URL's fragment is either null or the empty string, then return
  // the empty string. Return U+0023 (#), followed by this's URL's fragment.
  return (!hash.has_value() || (hash.value().empty())) ? ""
                                                       : "#" + hash.value();
}

}  // namespace ada
