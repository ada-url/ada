/**
 * @file url-getters.cpp
 * Includes all the getters of `ada::url`
 */
#include "ada.h"

#include <algorithm>
#include <string>

namespace ada {

  [[nodiscard]] std::string url::get_href() const noexcept {
    std::string output = get_protocol();
    size_t url_delimiter_count = std::count(path.begin(), path.end(), '/');

    if (host.has_value()) {
      output += "//";
      if (includes_credentials()) {
        output += get_username();
        if (!get_password().empty()) {
          output += ":" + get_password();
        }
        output += "@";
      }

      output += get_host();
    } else if (!has_opaque_path && url_delimiter_count > 1 && path.length() >= 2 && path[0] == '/' && path[1] == '/') {
      // If url’s host is null, url does not have an opaque path, url’s path’s size is greater than 1,
      // and url’s path[0] is the empty string, then append U+002F (/) followed by U+002E (.) to output.
      output += "/.";
    }

    output += get_pathname() 
           // If query is non-null, then set this’s query object’s list to the result of parsing query.
           + (query.has_value() ? "?" + query.value() : "")
           // If  url’s fragment is non-null, then append U+0023 (#), followed by url’s fragment, to output.
           + (fragment.has_value() ? "#" + fragment.value() : "");
    return output;
  }

  [[nodiscard]] std::string url::get_origin() const noexcept {
    if (is_special()) {
      return get_protocol() + "//" + get_host();
    }

    if (get_scheme() == "blob") {
      if (path.length() > 0) {
        url result = ada::parser::parse_url(get_pathname());
        if (result.is_valid) {
          if (result.is_special()) {
            return result.get_protocol() + "//" + result.get_host();
          }
        }
      }
    }

    // Return a new opaque origin.
    return "null";
  }

  [[nodiscard]] std::string url::get_protocol() const noexcept {
    return std::string(get_scheme()) + ":";
  }

  [[nodiscard]] std::string url::get_host() const noexcept {
    // If url’s host is null, then return the empty string.
    // If url’s port is null, return url’s host, serialized.
    // Return url’s host, serialized, followed by U+003A (:) and url’s port, serialized.
    if (!host.has_value()) { return ""; }
    return host.value() + (port.has_value() ? ":" + get_port() : "");
  }

  [[nodiscard]] std::string url::get_hostname() const noexcept {
    return host.value_or("");
  }

  [[nodiscard]] std::string url::get_pathname() const noexcept {
    return path;
  }

  [[nodiscard]] std::string url::get_search() const noexcept {
    // If this’s URL’s query is either null or the empty string, then return the empty string.
    // Return U+003F (?), followed by this’s URL’s query.
    return (!query.has_value() || (query.value().empty())) ? "" : "?" + query.value();
  }

  [[nodiscard]] std::string url::get_username() const noexcept {
    return username;
  }

  [[nodiscard]] std::string url::get_password() const noexcept {
    return password;
  }

  [[nodiscard]] std::string url::get_port() const noexcept {
    return port.has_value() ? std::to_string(port.value()) : "";
  }

  [[nodiscard]] std::string url::get_hash() const noexcept {
    // If this’s URL’s fragment is either null or the empty string, then return the empty string.
    // Return U+0023 (#), followed by this’s URL’s fragment.
    return (!fragment.has_value() || (fragment.value().empty())) ? "" : "#" + fragment.value();
  }

} // namespace ada
