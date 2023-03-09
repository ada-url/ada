#include "ada.h"
#include "ada/helpers.h"
#include <optional>

namespace ada {

void url_base::set_hash(const std::string_view input) {
  if (input.empty()) {
    clear_base_hash();
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '#' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);
  update_base_hash(unicode::percent_encode(new_value, ada::character_sets::FRAGMENT_PERCENT_ENCODE));
}

bool url_base::set_pathname(const std::string_view input) {
  if (has_opaque_path) { return false; }
  update_base_pathname("");
  return parse_path(input);
}

bool url_base::set_username(const std::string_view input) {
  if (cannot_have_credentials_or_port()) { return false; }
  update_base_username(ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE));
  return true;
}

bool url_base::set_password(const std::string_view input) {
  if (cannot_have_credentials_or_port()) { return false; }
  update_base_password(ada::unicode::percent_encode(input, character_sets::USERINFO_PERCENT_ENCODE));
  return true;
}

void url_base::set_search(const std::string_view input) {
  if (input.empty()) {
    update_base_search(std::nullopt);
    helpers::strip_trailing_spaces_from_opaque_path(*this);
    return;
  }

  std::string new_value;
  new_value = input[0] == '?' ? input.substr(1) : input;
  helpers::remove_ascii_tab_or_newline(new_value);

  auto query_percent_encode_set = is_special() ?
    ada::character_sets::SPECIAL_QUERY_PERCENT_ENCODE :
    ada::character_sets::QUERY_PERCENT_ENCODE;

  update_base_search(ada::unicode::percent_encode(std::string_view(new_value), query_percent_encode_set));
}

bool url_base::set_port(const std::string_view input) {
  if (cannot_have_credentials_or_port()) { return false; }
  std::string trimmed(input);
  helpers::remove_ascii_tab_or_newline(trimmed);
  if (trimmed.empty()) { update_base_port(std::nullopt); return true; }
  // Input should not start with control characters.
  if (ada::unicode::is_c0_control_or_space(trimmed.front())) { return false; }
  // Input should contain at least one ascii digit.
  if (input.find_first_of("0123456789") == std::string_view::npos) { return false; }

  // Revert changes if parse_port fails.
  std::optional<uint16_t> previous_port = retrieve_base_port();
  parse_port(trimmed);
  if (is_valid) { return true; }
  update_base_port(previous_port);
  is_valid = true;
  return false;
}

bool url_base::set_protocol(const std::string_view input) {
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

ada_really_inline bool url_base::parse_path(std::string_view input) {
  ada_log("parse_path ", input);
  std::string tmp_buffer;
  std::string_view internal_input;
  if(unicode::has_tabs_or_newline(input)) {
    tmp_buffer = input;
    // Optimization opportunity: Instead of copying and then pruning, we could just directly
    // build the string from user_input.
    helpers::remove_ascii_tab_or_newline(tmp_buffer);
    internal_input = tmp_buffer;
  } else {
    internal_input = input;
  }

  std::string path = retrieve_base_pathname();

  // If url is special, then:
  if (is_special()) {
    if(internal_input.empty()) {
      update_base_pathname("/");
    } else if((internal_input[0] == '/') || (internal_input[0] == '\\')){
      if (helpers::parse_prepared_path(internal_input.substr(1), type, path)) {
        update_base_pathname(path);
        return true;
      }
      return false;
    } else {
      if (helpers::parse_prepared_path(internal_input, type, path)) {
        update_base_pathname(path);
        return true;
      }
      return false;
    }
  } else if (!internal_input.empty()) {
    if(internal_input[0] == '/') {
      if (helpers::parse_prepared_path(internal_input.substr(1), type, path)) {
        update_base_pathname(path);
        return true;
      }
      return false;
    } else {
      if (helpers::parse_prepared_path(internal_input, type, path)) {
        update_base_pathname(path);
        return true;
      }
      return false;
    }
  } else if (!base_hostname_has_value()) {
    update_base_pathname("/");
  }
  return true;
}

template <bool has_state_override>
ada_really_inline bool url_base::parse_scheme(const std::string_view input) {
  auto parsed_type = ada::scheme::get_scheme_type(input);
  bool is_input_special = (parsed_type != ada::scheme::NOT_SPECIAL);
  /**
   * In the common case, we will immediately recognize a special scheme (e.g., http, https),
   * in which case, we can go really fast.
   **/
  if(is_input_special) { // fast path!!!
    if (has_state_override) {
      // If url’s scheme is not a special scheme and buffer is a special scheme, then return.
      if (is_special() != is_input_special) { return true; }

      // If url includes credentials or has a non-null port, and buffer is "file", then return.
      if ((includes_credentials() || base_port_has_value()) && parsed_type == ada::scheme::type::FILE) { return true; }

      // If url’s scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE && base_hostname_has_value() && get_hostname().empty()) { return true; }
    }

    type = parsed_type;

    if (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url’s port is url’s scheme’s default port, then set url’s port to null.
        if (base_port_has_value() && retrieve_base_port().value() == urls_scheme_port) {
          update_base_port(std::nullopt);
        }
      }
    }
  } else { // slow path
    std::string _buffer = std::string(input);
    // Next function is only valid if the input is ASCII and returns false
    // otherwise, but it seems that we always have ascii content so we do not need
    // to check the return value.
    unicode::to_lower_ascii(_buffer.data(), _buffer.size());

    if (has_state_override) {
      // If url’s scheme is a special scheme and buffer is not a special scheme, then return.
      // If url’s scheme is not a special scheme and buffer is a special scheme, then return.
      if (is_special() != ada::scheme::is_special(_buffer)) { return true; }

      // If url includes credentials or has a non-null port, and buffer is "file", then return.
      if ((includes_credentials() || base_port_has_value()) && _buffer == "file") { return true; }

      // If url’s scheme is "file" and its host is an empty host, then return.
      // An empty host is the empty string.
      if (type == ada::scheme::type::FILE && base_hostname_has_value() && get_hostname().empty()) { return true; }
    }

    set_scheme(std::move(_buffer));

    if (has_state_override) {
      // This is uncommon.
      uint16_t urls_scheme_port = get_special_port();

      if (urls_scheme_port) {
        // If url’s port is url’s scheme’s default port, then set url’s port to null.
        if (base_port_has_value() && retrieve_base_port().value() == urls_scheme_port) {
          update_base_port(std::nullopt);
        }
      }
    }
  }

  return true;
}

} // namespace ada
