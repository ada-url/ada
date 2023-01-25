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

} // namespace ada
