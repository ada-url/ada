#ifndef ADA_CHECKERS_H
#define ADA_CHECKERS_H

#include "common_defs.h"

#include <string_view>

namespace ada::checkers {

  ada_really_inline bool ends_in_a_number(std::string_view input);
  ada_really_inline bool is_windows_drive_letter(std::string_view input);
  ada_really_inline bool is_normalized_windows_drive_letter(std::string_view input);

} // namespace ada::checkers

#endif //ADA_CHECKERS_H
