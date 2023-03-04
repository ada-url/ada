#include "ada.h"

namespace ada {

  bool url_base::set_hash(const std::string_view input) {
    if (input.empty()) {
      update_base_fragment(std::nullopt);
      fragment = std::nullopt;
      helpers::strip_trailing_spaces_from_opaque_path(*this);
      return;
    }

    std::string new_value;
    new_value = input[0] == '#' ? input.substr(1) : input;
    helpers::remove_ascii_tab_or_newline(new_value);
    update_base_fragment(unicode::percent_encode(new_value, ada::character_sets::FRAGMENT_PERCENT_ENCODE));
  }

}
