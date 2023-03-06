#include "ada.h"
#include "ada/helpers.h"

namespace ada {

bool url_base::set_hash(const std::string_view input) {
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

[[nodiscard]] ada_really_inline bool url_base::is_special() const noexcept {
  return type != ada::scheme::NOT_SPECIAL;
}

[[nodiscard]] inline uint16_t url_base::get_special_port() const {
  return ada::scheme::get_special_port(type);
}

[[nodiscard]] ada_really_inline uint16_t url_base::scheme_default_port() const noexcept {
  return scheme::get_special_port(type);
}

} // namespace ada
