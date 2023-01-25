#include "ada.h"

#include <string>

namespace ada {

  void url::set_username(const std::string_view input) {
    if (cannot_have_credentials_or_port()) return;
    username = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
  }

  void url::set_password(const std::string_view input) {
    if (cannot_have_credentials_or_port()) return;
    password = ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE);
  }

  void url::set_port(const std::string_view input) {
    if (cannot_have_credentials_or_port()) { return; }
    parse_port(input);
  }

  void url::set_hash(const std::string_view input) {
    if (input.empty()) {
      fragment = std::nullopt;
      // TODO: Potentially strip trailing spaces from an opaque path with this.
      return;
    }

    // Let input be the given value with a single leading U+0023 (#) removed, if any.
    std::string new_value;
    new_value = input[0] == '#' ? input.substr(1) : input;
    helpers::remove_ascii_tab_or_newline(new_value);

    // Set this’s URL’s fragment to the empty string.
    // Basic URL parse input with this’s URL as url and fragment state as state override.
    fragment = unicode::percent_encode(new_value, ada::character_sets::FRAGMENT_PERCENT_ENCODE);
  }

  void url::set_search(const std::string_view input) {
    // If the given value is the empty string:
    if (input.empty()) {
      // Set url’s query to null.
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

    // Percent-encode after encoding, with encoding, buffer, and queryPercentEncodeSet,
    // and append the result to url’s query.
    query = ada::unicode::percent_encode(std::string_view(new_value), query_percent_encode_set);

    // Set this’s query object’s list to the result of parsing input.
    // @todo Implement this if/when we have URLSearchParams.
  }

  void url::set_pathname(const std::string_view input) {
    if (has_opaque_path) { return; }
    path = "";
    parse_path(input);
  }

  void url::set_host(const std::string_view input) {
    // If this’s URL has an opaque path, then return.
    if (has_opaque_path) { return; }

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
        // If buffer is the empty string, validation error, return failure.
        return;
      }
      // If url is special and host_view is the empty string, validation error, return failure.
      // Otherwise, if state override is given, host_view is the empty string,
      // and either url includes credentials or url’s port is non-null, return.
      else if (host_view.empty() && (is_special() || includes_credentials() || port.has_value())) {
        return;
      }

      // Let host be the result of host parsing host_view with url is not special.
      if (host_view.empty()) {
        host = "";
        return;
      }

      parse_host(host_view);
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
        return;
      }

      // If host is "localhost", then set host to the empty string.
      if (host.has_value() && host.value() == "localhost") {
        host = "";
      }
    }
  }

} // namespace ada
