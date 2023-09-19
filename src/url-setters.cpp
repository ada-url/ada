/**
 * @file url-setters.cpp
 * Includes all the setters of `ada::url`
 */
#include "ada.h"
#include "ada/helpers.h"

#include <optional>
#include <string>

namespace ada {

template <bool override_hostname>
bool url::set_host_or_hostname(const std::string_view input) {
  if (has_opaque_path) {
    return false;
  }

  std::optional<std::string> previous_host = host;
  std::optional<uint16_t> previous_port = port;

  size_t host_end_pos = input.find('#');
  std::string _host(input.data(), host_end_pos != std::string_view::npos
                                      ? host_end_pos
                                      : input.size());
  helpers::remove_ascii_tab_or_newline(_host);
  std::string_view new_host(_host);

  // If url's scheme is "file", then set state to file host state, instead of
  // host state.
  if (type != ada::scheme::type::FILE) {
    std::string_view host_view(_host.data(), _host.length());
    auto [location, found_colon] =
        helpers::get_host_delimiter_location(is_special(), host_view);

    // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
    // Note: the 'found_colon' value is true if and only if a colon was
    // encountered while not inside brackets.
    if (found_colon) {
      if (override_hostname) {
        return false;
      }
      std::string_view buffer = new_host.substr(location + 1);
      if (!buffer.empty()) {
        set_port(buffer);
      }
    }
    // If url is special and host_view is the empty string, validation error,
    // return failure. Otherwise, if state override is given, host_view is the
    // empty string, and either url includes credentials or url's port is
    // non-null, return.
    else if (host_view.empty() &&
             (is_special() || has_credentials() || port.has_value())) {
      return false;
    }

    // Let host be the result of host parsing host_view with url is not special.
    if (host_view.empty() && !is_special()) {
      host = "";
      return true;
    }

    bool succeeded = parse_host(host_view);
    if (!succeeded) {
      host = previous_host;
      update_base_port(previous_port);
    }
    return succeeded;
  }

  size_t location = new_host.find_first_of("/\\?");
  if (location != std::string_view::npos) {
    new_host.remove_suffix(new_host.length() - location);
  }

  if (new_host.empty()) {
    // Set url's host to the empty string.
    host = "";
  } else {
    // Let host be the result of host parsing buffer with url is not special.
    if (!parse_host(new_host)) {
      host = previous_host;
      update_base_port(previous_port);
      return false;
    }

    // If host is "localhost", then set host to the empty string.
    if (host.has_value() && host.value() == "localhost") {
      host = "";
    }
  }
  return true;
}

bool url::set_host(const std::string_view input) {
  return set_host_or_hostname<false>(input);
}

bool url::set_hostname(const std::string_view input) {
  return set_host_or_hostname<true>(input);
}

bool url::set_username(const std::string_view input) {
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  username = ada::unicode::percent_encode(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  return true;
}

bool url::set_password(const std::string_view input) {
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  password = ada::unicode::percent_encode(
      input, character_sets::USERINFO_PERCENT_ENCODE);
  return true;
}

bool url::set_port(const std::string_view input) {
  if (cannot_have_credentials_or_port()) {
    return false;
  }
  std::string trimmed(input);
  helpers::remove_ascii_tab_or_newline(trimmed);
  if (trimmed.empty()) {
    port = std::nullopt;
    return true;
  }
  // Input should not start with control characters.
  if (ada::unicode::is_c0_control_or_space(trimmed.front())) {
    return false;
  }
  // Input should contain at least one ascii digit.
  if (input.find_first_of("0123456789") == std::string_view::npos) {
    return false;
  }

  // Revert changes if parse_port fails.
  std::optional<uint16_t> previous_port = port;
  parse_port(trimmed);
  if (is_valid) {
    return true;
  }
  port = previous_port;
  is_valid = true;
  return false;
}

void url::set_hash(const std::string_view input) {
  if (input.empty()) {
    hash = std::nullopt;
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '#' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);
  hash = unicode::percent_encode(new_value,
                                 ada::character_sets::FRAGMENT_PERCENT_ENCODE);
  return;
}

void url::set_search(const std::string_view input) {
  if (input.empty()) {
    query = std::nullopt;
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '?' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);

  auto query_percent_encode_set =
      is_special() ? ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE
                   : ada::character_sets::QUERY_PERCENT_ENCODE;

  query = ada::unicode::percent_encode(std::string_view(new_value),
                                       query_percent_encode_set);
}

bool url::set_pathname(const std::string_view input) {
  if (has_opaque_path) {
    return false;
  }
  path = "";
  parse_path(input);
  return true;
}

bool url::set_protocol(const std::string_view input) {
  std::string view(input);
  helpers::remove_ascii_tab_or_newline(view);
  if (view.empty()) {
    return true;
  }

  // Schemes should start with alpha values.
  if (!checkers::is_alpha(view[0])) {
    return false;
  }

  view.append(":");

  std::string::iterator pointer =
      std::find_if_not(view.begin(), view.end(), unicode::is_alnum_plus);

  if (pointer != view.end() && *pointer == ':') {
    return parse_scheme<true>(
        std::string_view(view.data(), pointer - view.begin()));
  }
  return false;
}

bool url::set_href(const std::string_view input) {
  ada::result<ada::url> out = ada::parse<ada::url>(input);

  if (out) {
    username = out->username;
    password = out->password;
    host = out->host;
    port = out->port;
    path = out->path;
    query = out->query;
    hash = out->hash;
    type = out->type;
    non_special_scheme = out->non_special_scheme;
    has_opaque_path = out->has_opaque_path;
  }

  return out.has_value();
}

}  // namespace ada
