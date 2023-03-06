#include "ada.h"
#include "ada/helpers.h"

namespace ada {

void url_base::set_hash(const std::string_view input) {
  if (input.empty()) {
    update_base_hash(std::nullopt);
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

  // If url is special, then:
  if (is_special()) {
    if(internal_input.empty()) {
      update_base_pathname("/");
    } else if((internal_input[0] == '/') ||(internal_input[0] == '\\')){
      return helpers::parse_prepared_path(internal_input.substr(1), type, path);
    } else {
      return helpers::parse_prepared_path(internal_input, type, path);
    }
  } else if (!internal_input.empty()) {
    if(internal_input[0] == '/') {
      return helpers::parse_prepared_path(internal_input.substr(1), type, path);
    } else {
      return helpers::parse_prepared_path(internal_input, type, path);
    }
  } else {
    if(!base_hostname_has_value()) {
      update_base_pathname("/");
    }
  }
  return true;
}

} // namespace ada
