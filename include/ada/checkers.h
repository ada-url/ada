#ifndef ADA_CHECKERS_H
#define ADA_CHECKERS_H

#include "common_defs.h"

#include <string_view>

namespace ada::checkers {

  bool ends_in_a_number(std::string_view input) noexcept;
  bool is_windows_drive_letter(std::string_view input) noexcept;
  bool is_normalized_windows_drive_letter(std::string_view input) noexcept;
  ada_really_inline constexpr bool is_ipv4_number_valid(const std::string_view input) noexcept;

} // namespace ada::checkers

#endif //ADA_CHECKERS_H
