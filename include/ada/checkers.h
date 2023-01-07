#ifndef ADA_CHECKERS_H
#define ADA_CHECKERS_H

#include "common_defs.h"

#include <string_view>

namespace ada::checkers {

  inline bool ends_in_a_number(std::string_view input) noexcept;
  constexpr char to_lower(char x);
  constexpr bool is_alpha(char x);
  inline bool is_windows_drive_letter(std::string_view input) noexcept;
  inline bool is_normalized_windows_drive_letter(std::string_view input) noexcept;
  ada_really_inline constexpr bool is_ipv4_number_valid(std::string_view::iterator iterator_start, std::string_view::iterator iterator_end) noexcept;

} // namespace ada::checkers

#endif //ADA_CHECKERS_H
