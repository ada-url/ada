#include "ada.h"

#include <string>

namespace ada {

  bool url::set_username(const std::string_view input) {
    if (cannot_have_credentials_or_port()) { return false; }
    username = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
    return true;
  }

  bool url::set_password(const std::string_view input) {
    if (cannot_have_credentials_or_port()) { return false; }
    password = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
    return true;
  }

  bool url::set_port(const std::string_view input) {
    if (cannot_have_credentials_or_port()) { return false; }
    return parse_port(input,false);
  }

  void url::set_hash(const std::string_view input) {
    if (input.empty()) {
      fragment = std::nullopt;
      // TODO: Potentially strip trailing spaces from an opaque path with this.
      return;
    }

    std::string new_value;
    new_value = input[0] == '#' ? input.substr(1) : input;
    helpers::remove_ascii_tab_or_newline(new_value);
    fragment = unicode::percent_encode(new_value, ada::character_sets::FRAGMENT_PERCENT_ENCODE);
    return;
  }

  void url::set_search(const std::string_view input) {
    if (input.empty()) {
      query = std::nullopt;
      // Empty this’s query object’s list.
      // @todo Implement this if/when we have URLSearchParams.
      // Potentially strip trailing spaces from an opaque path with this.
      return;
    }

    std::string new_value;
    new_value = input[0] == '?' ? input.substr(1) : input;
    helpers::remove_ascii_tab_or_newline(new_value);

    auto query_percent_encode_set = is_special() ?
      ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE :
      ada::character_sets::QUERY_PERCENT_ENCODE;

    query = ada::unicode::percent_encode(std::string_view(new_value), query_percent_encode_set);

    // Set this’s query object’s list to the result of parsing input.
    // @todo Implement this if/when we have URLSearchParams.
    return ;
  }

  bool url::set_pathname(const std::string_view input) {
    if (has_opaque_path) { return false; }
    path = "";
    return parse_path(input);
  }

  bool url::set_host(const std::string_view input) {
    if (has_opaque_path) { return false; }

    std::string_view::iterator _host_end = std::find(input.begin(), input.end(), '#');
    std::string _host(input.data(), std::distance(input.begin(), _host_end));
    helpers::remove_ascii_tab_or_newline(_host);
    std::string_view new_host(_host);

    // If url's scheme is "file", then set state to file host state, instead of host state.
    if (get_scheme_type() != ada::scheme::type::FILE) {
      std::string_view host_view(_host.data(), _host.length());
      bool inside_brackets{false};
      size_t location = helpers::get_host_delimiter_location(*this, host_view, inside_brackets);
      std::string_view::iterator pointer = (location != std::string_view::npos) ? new_host.begin() + location : new_host.end();

      // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
      // Note: we cannot access *pointer safely if (pointer == pointer_end).
      if ((pointer != new_host.end()) && (*pointer == ':') && !inside_brackets) {
        // TODO: The next 2 lines is the only difference between set_host and set_hostname. Let's simplify it.
        std::string_view buffer(&*(pointer + 1));
        if (!buffer.empty()) { set_port(buffer); }
      }
      // If url is special and host_view is the empty string, validation error, return failure.
      // Otherwise, if state override is given, host_view is the empty string,
      // and either url includes credentials or url’s port is non-null, return.
      else if (host_view.empty() && (is_special() || includes_credentials() || port.has_value())) {
        return false;
      }

      // Let host be the result of host parsing host_view with url is not special.
      if (host_view.empty()) {
        host = "";
        return true;
      }

      return parse_host(host_view);
    }

    size_t location = new_host.find_first_of("/\\?");
    if (location != std::string_view::npos) { new_host.remove_suffix(new_host.length() - location); }

    if (new_host.empty()) {
      // Set url’s host to the empty string.
      host = "";
    }
    else {
      // @todo This is required because to_ascii mutate input and does not revert if input fails.
      auto existing_host = std::move(host);

      // Let host be the result of host parsing buffer with url is not special.
      if (!parse_host(new_host)) {
        host = existing_host;
        return false;
      }

      // If host is "localhost", then set host to the empty string.
      if (host.has_value() && host.value() == "localhost") {
        host = "";
      }
    }
    return true;
  }

  bool url::set_hostname(const std::string_view input) {
    if (has_opaque_path) { return false; }

    std::string_view::iterator input_pointer_end = std::find(input.begin(), input.end(), '#');
    std::string _host(input.data(), std::distance(input.begin(), input_pointer_end));
    helpers::remove_ascii_tab_or_newline(_host);
    std::string_view new_host(_host);

    // If url's scheme is "file", then set state to file host state, instead of host state.
    if (get_scheme_type() != ada::scheme::type::FILE) {
      std::string_view host_view(_host.data(), _host.length());
      bool inside_brackets{false};
      size_t location = helpers::get_host_delimiter_location(*this, host_view, inside_brackets);
      std::string_view::iterator pointer = (location != std::string_view::npos) ? new_host.begin() + location : new_host.end();

      // Otherwise, if c is U+003A (:) and insideBrackets is false, then:
      // Note: we cannot access *pointer safely if (pointer == pointer_end).
      if ((pointer != new_host.end()) && (*pointer == ':') && !inside_brackets) {
        // If buffer is the empty string, validation error, return failure.
        return false;
      }
      // If url is special and host_view is the empty string, validation error, return failure.
      else if (host_view.empty() && is_special()) {
        return false;
      }
      // Otherwise, if state override is given, host_view is the empty string,
      // and either url includes credentials or url’s port is non-null, return.
      else if (host_view.empty() && (includes_credentials() || port.has_value())) {
        return true;
      }

      // Let host be the result of host parsing host_view with url is not special.
      if (host_view.empty()) {
        host = "";
        return true;
      }

      return parse_host(host_view);
    }

    size_t location = new_host.find_first_of("/\\?");
    if (location != std::string_view::npos) { new_host.remove_suffix(new_host.length() - location); }

    if (new_host.empty()) {
      // Set url’s host to the empty string.
      host = "";
    }
    else {
      // @todo This is required because to_ascii mutate input and does not revert if input fails.
      auto existing_host = std::move(host);

      // Let host be the result of host parsing buffer with url is not special.
      if (!parse_host(new_host)) {
        host = existing_host;
        return false;
      }

      // If host is "localhost", then set host to the empty string.
      if (host.has_value() && host.value() == "localhost") {
        host = "";
      }
    }
    return true;
  }

  bool url::set_protocol(const std::string_view input) {
    std::string view(input);
    helpers::remove_ascii_tab_or_newline(view);
    if (view.empty()) { return true; }

    // Schemes should start with alpha values.
    if (!checkers::is_alpha(view[0])) { return false; }

    view.append(":");

    std::string::iterator pointer = std::find_if_not(view.begin(), view.end(), unicode::is_alnum_plus);

    if (pointer != view.end() && *pointer == ':') {
      return parse_scheme<true>(std::string_view(view.data(), pointer - view.begin()));
    }
    return false;
  }

} // namespace ada
